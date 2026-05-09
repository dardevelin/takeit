# Originally from magic-wormhole (MIT, (c) 2015 Brian Warner).
# Lifted into takeit; see NOTICE for the full list.
from collections import deque, defaultdict
from attr import attrs, attrib
from attr.validators import instance_of
from zope.interface import implementer
from twisted.internet.defer import inlineCallbacks
from twisted.internet.interfaces import (
    ITransport,
    IProducer,
    IConsumer,
    IAddress,
    IListeningPort,
    IHalfCloseableProtocol,
    IStreamClientEndpoint,
    IStreamServerEndpoint,
)
from twisted.internet.error import ConnectionDone
from twisted.python import log
from automat import MethodicalMachine
from .._interfaces import ISubChannel, IDilationManager
from ..util import provides

# HYP-455: caps on inbound subchannel buffers. A Noise-authenticated peer
# can otherwise send unbounded OPENs / DATA before the local factory is
# connected. Per-name OPEN cap is generous (legitimate use is 0..few);
# per-channel byte cap mirrors HYP-440's outbound 16 MiB.
MAX_PENDING_OPENS_PER_SUBPROTOCOL = 64
MAX_PENDING_REMOTE_DATA_BYTES = 16 << 20

# each subchannel frame (the data passed into transport.write(data)) gets a
# 9-byte header prefix (type, subchannel id, and sequence number), then gets
# encrypted (adding a 16-byte authentication tag). The result is transmitted
# with a 4-byte length prefix (which only covers the padded message, not the
# length prefix itself), so the padded message must be less than 2**32 bytes
# long.
MAX_FRAME_LENGTH = 2**32 - 1 - 9 - 16


# created in the (OPEN) state, by either:
#  * receipt of an OPEN message
#  * or local client_endpoint.connect()
# then transitions are:
# (OPEN) rx DATA: deliver .dataReceived(), -> (OPEN)
# (OPEN) rx CLOSE: deliver .connectionLost(), send CLOSE, -> (CLOSED)
# (OPEN) local .write(): send DATA, -> (OPEN)
# (OPEN) local .loseConnection(): send CLOSE, -> (CLOSING)
# (CLOSING) local .write(): error
# (CLOSING) local .loseConnection(): error
# (CLOSING) rx DATA: deliver .dataReceived(), -> (CLOSING)
# (CLOSING) rx CLOSE: deliver .connectionLost(), -> (CLOSED)
# object is deleted upon transition to (CLOSED)


class AlreadyClosedError(Exception):
    pass


class NormalCloseUsedOnHalfCloseable(Exception):
    pass


class HalfCloseUsedOnNonHalfCloseable(Exception):
    pass


class UnexpectedSubprotocol(Exception):
    """
    The peer sends an OPEN for a subprotocol name application code
    indicates will never exist
    """


class PendingOpenCapExceeded(Exception):
    """
    HYP-455: peer sent more OPENs for an expected-but-unregistered
    subprotocol than the per-name cap allows. The peer is non-conforming
    or hostile; Inbound closes the subchannel.
    """


@implementer(IAddress)
class _WormholeAddress:
    pass


@implementer(IAddress)
@attrs
class SubchannelAddress:
    """
    All subchannels have a named sub-protocol (as sent by our peer in
    the OPEN call).

    Although each subchannel does have an 'id', this is a concept
    private to this implementation, and not exposed here on purpose.
    """

    subprotocol = attrib(validator=instance_of(str))


@attrs(eq=False)
@implementer(ITransport)
@implementer(IProducer)
@implementer(IConsumer)
@implementer(ISubChannel)
class SubChannel:
    _scid = attrib(validator=instance_of(int))
    _manager = attrib(validator=provides(IDilationManager))
    _host_addr = attrib(validator=instance_of(_WormholeAddress))
    _peer_addr = attrib(validator=instance_of(SubchannelAddress))

    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)  # pragma: no cover

    def __attrs_post_init__(self):
        # self._mailbox = None
        # self._pending_outbound = {}
        # self._processed = set()
        self._protocol = None
        self._pending_remote_data = []
        # HYP-455: track total queued bytes so we can cap before the
        # local protocol attaches. The cap mirrors HYP-440's outbound
        # 16 MiB. Going over forces a close-and-drop rather than
        # silently consuming memory on a non-conforming peer's behalf.
        self._pending_remote_data_bytes = 0
        self._pending_remote_close = False

    @m.state(initial=True)
    def unconnected(self):
        pass  # pragma: no cover

    # once we get the IProtocol, it's either a IHalfCloseableProtocol, or it
    # can only be fully closed
    @m.state()
    def open_half(self):
        pass  # pragma: no cover

    @m.state()
    def read_closed():
        pass  # pragma: no cover

    @m.state()
    def write_closed():
        pass  # pragma: no cover

    @m.state()
    def open_full(self):
        pass  # pragma: no cover

    @m.state()
    def closing():
        pass  # pragma: no cover

    @m.state()
    def closed():
        pass  # pragma: no cover

    @m.input()
    def connect_protocol_half(self):
        pass

    @m.input()
    def connect_protocol_full(self):
        pass

    @m.input()
    def remote_data(self, data):
        pass

    @m.input()
    def remote_close(self):
        pass

    @m.input()
    def local_data(self, data):
        pass

    @m.input()
    def local_close(self):
        pass

    @m.output()
    def queue_remote_data(self, data):
        # HYP-455: cap pre-attach data buffering. The post-attach path
        # delivers bytes synchronously to the local protocol (no queue),
        # so this only fires while the local factory hasn't connected
        # yet. Going over cap closes the channel and stops accepting
        # further data — preferable to OOM under a hostile peer.
        if self._pending_remote_data_bytes + len(data) > MAX_PENDING_REMOTE_DATA_BYTES:
            log.msg(
                f"HYP-455: subchannel {self._scid} pre-attach data exceeded "
                f"{MAX_PENDING_REMOTE_DATA_BYTES} bytes; closing"
            )
            self._manager.send_close(self._scid)
            self._pending_remote_data = []
            self._pending_remote_data_bytes = 0
            return
        self._pending_remote_data.append(data)
        self._pending_remote_data_bytes += len(data)

    @m.output()
    def queue_remote_close(self):
        self._pending_remote_close = True

    @m.output()
    def send_data(self, data):
        self._manager.send_data(self._scid, data)

    @m.output()
    def send_close(self):
        self._manager.send_close(self._scid)

    @m.output()
    def signal_dataReceived(self, data):
        assert self._protocol
        self._protocol.dataReceived(data)

    @m.output()
    def signal_readConnectionLost(self):
        IHalfCloseableProtocol(self._protocol).readConnectionLost()

    @m.output()
    def signal_writeConnectionLost(self):
        IHalfCloseableProtocol(self._protocol).writeConnectionLost()

    @m.output()
    def signal_connectionLost(self):
        assert self._protocol
        self._protocol.connectionLost(ConnectionDone())

    @m.output()
    def close_subchannel(self):
        self._manager.subchannel_closed(self._scid, self)
        # we're deleted momentarily

    @m.output()
    def error_closed_write(self, data):
        raise AlreadyClosedError("write not allowed on closed subchannel")

    @m.output()
    def error_closed_close(self):
        raise AlreadyClosedError("loseConnection not allowed on closed subchannel")

    # stuff that arrives before we have a protocol connected
    unconnected.upon(remote_data, enter=unconnected, outputs=[queue_remote_data])
    unconnected.upon(remote_close, enter=unconnected, outputs=[queue_remote_close])

    # IHalfCloseableProtocol flow
    unconnected.upon(connect_protocol_half, enter=open_half, outputs=[])
    open_half.upon(remote_data, enter=open_half, outputs=[signal_dataReceived])
    open_half.upon(local_data, enter=open_half, outputs=[send_data])
    # remote closes first
    open_half.upon(remote_close, enter=read_closed, outputs=[signal_readConnectionLost])
    read_closed.upon(local_data, enter=read_closed, outputs=[send_data])
    read_closed.upon(
        local_close,
        enter=closed,
        outputs=[
            send_close,
            close_subchannel,
            # TODO: eventual-signal this?
            signal_writeConnectionLost,
        ],
    )
    # local closes first
    open_half.upon(
        local_close,
        enter=write_closed,
        outputs=[signal_writeConnectionLost, send_close],
    )
    write_closed.upon(local_data, enter=write_closed, outputs=[error_closed_write])
    write_closed.upon(remote_data, enter=write_closed, outputs=[signal_dataReceived])
    write_closed.upon(
        remote_close,
        enter=closed,
        outputs=[
            close_subchannel,
            signal_readConnectionLost,
        ],
    )
    # error cases
    write_closed.upon(local_close, enter=write_closed, outputs=[error_closed_close])

    # fully-closeable-only flow
    unconnected.upon(connect_protocol_full, enter=open_full, outputs=[])
    open_full.upon(remote_data, enter=open_full, outputs=[signal_dataReceived])
    open_full.upon(local_data, enter=open_full, outputs=[send_data])
    open_full.upon(
        remote_close,
        enter=closed,
        outputs=[send_close, close_subchannel, signal_connectionLost],
    )
    open_full.upon(local_close, enter=closing, outputs=[send_close])
    closing.upon(remote_data, enter=closing, outputs=[signal_dataReceived])
    closing.upon(
        remote_close, enter=closed, outputs=[close_subchannel, signal_connectionLost]
    )
    # error cases
    # we won't ever see an OPEN, since L4 will log+ignore those for us
    closing.upon(local_data, enter=closing, outputs=[error_closed_write])
    closing.upon(local_close, enter=closing, outputs=[error_closed_close])
    # the CLOSED state shouldn't ever see messages, since we'll be deleted
    # (but a local user should be able to call "close" without having
    # to know what state we're in)
    closed.upon(local_close, enter=closed, outputs=[])

    # our endpoints use these

    def _set_protocol(self, protocol):
        assert not self._protocol
        self._protocol = protocol
        if IHalfCloseableProtocol.providedBy(protocol):
            self.connect_protocol_half()
        else:
            # move from UNCONNECTED to OPEN
            self.connect_protocol_full()

    def _deliver_queued_data(self):
        for data in self._pending_remote_data:
            self.remote_data(data)
        del self._pending_remote_data
        if self._pending_remote_close:
            self.remote_close()
            del self._pending_remote_close

    # ITransport
    def write(self, data):
        assert isinstance(data, bytes)
        assert len(data) <= MAX_FRAME_LENGTH
        self.local_data(data)

    def writeSequence(self, iovec):
        self.write(b"".join(iovec))

    def loseWriteConnection(self):
        if not IHalfCloseableProtocol.providedBy(self._protocol):
            # this is a clear error
            raise HalfCloseUsedOnNonHalfCloseable()
        self.local_close()

    def loseConnection(self):
        # TODO: what happens if an IHalfCloseableProtocol calls normal
        # loseConnection()? I think we need to close the read side too.
        if IHalfCloseableProtocol.providedBy(self._protocol):
            # I don't know is correct, so avoid this for now
            raise NormalCloseUsedOnHalfCloseable()
        self.local_close()

    def getHost(self):
        # we define "host addr" as the overall takeit
        return self._host_addr

    def getPeer(self):
        # and "peer addr" as the subchannel within that takeit
        return self._peer_addr

    # IProducer: throttle inbound data (takeit "up" to local app's Protocol)
    def stopProducing(self):
        self._manager.subchannel_stopProducing(self)

    def pauseProducing(self):
        self._manager.subchannel_pauseProducing(self)

    def resumeProducing(self):
        self._manager.subchannel_resumeProducing(self)

    # IConsumer: allow the takeit to throttle outbound data (app->takeit)
    def registerProducer(self, producer, streaming):
        self._manager.subchannel_registerProducer(self, producer, streaming)

    def unregisterProducer(self):
        self._manager.subchannel_unregisterProducer(self)


@implementer(IStreamClientEndpoint)
@attrs
class SubchannelConnectorEndpoint:
    _subprotocol = attrib(validator=instance_of(str))
    _manager = attrib(validator=provides(IDilationManager))
    _host_addr = attrib(validator=instance_of(_WormholeAddress))
    _eventual_queue = attrib(repr=False)

    def __attrs_post_init__(self):
        self._connection_deferreds = deque()
        if not self._subprotocol:
            raise ValueError("subprotocol must be a non-empty str")

    @inlineCallbacks
    def connect(self, protocolFactory):
        # return Deferred that fires with IProtocol or Failure(ConnectError)
        yield self._manager._main_channel.when_fired()
        scid = self._manager.allocate_subchannel_id()
        self._manager.send_open(scid, self._subprotocol)
        peer_addr = SubchannelAddress(self._subprotocol)
        # ? f.doStart()
        # ? f.startedConnecting(CONNECTOR) # ??
        sc = SubChannel(scid, self._manager, self._host_addr, peer_addr)
        self._manager.subchannel_local_open(scid, sc)
        p = protocolFactory.buildProtocol(peer_addr)
        sc._set_protocol(p)
        p.makeConnection(sc)  # set p.transport = sc and call connectionMade()
        return p


class IllegalSubprotocolError(Exception):
    """
    A peer tried to open a subprotocol that has no listener.
    """


@implementer(IStreamServerEndpoint)
@attrs
class SubchannelListenerEndpoint:
    """
    This endpoint is used by application code to attach a factory to a
    given subprotocol. Instances are gotten via DilatedWormhole.listener_for()

    On listen(), we register for incoming OPENs on for this
    subprotocol name.
    """

    subprotocol_name = attrib()
    _manager = attrib()

    # this can, in fact, be async
    @inlineCallbacks
    def listen(self, factory):
        yield self._manager._main_channel.when_fired()
        self._manager._register_subprotocol_factory(self.subprotocol_name, factory)
        return SubchannelListeningPort(self._manager._host_addr)


class SubchannelDemultiplex:
    """
    Helper for Inbound to await factories for particular subprotocols,
    and deliver pending and future OPEN messages to them.

    `expected_subprotocols` is a (frozen)set of subprotocol-name strings
    a caller is willing to accept. An OPEN whose name is not in the set
    raises UnexpectedSubprotocol. Pass `frozenset()` to register the
    "reject all unknown subprotocols" posture explicitly. None is no
    longer accepted (HYP-442) — callers must commit to an allowlist.
    """

    def __init__(self, expected_subprotocols):
        if not isinstance(expected_subprotocols, (set, frozenset)):
            raise TypeError(
                "expected_subprotocols must be a set or frozenset; got {!r}".format(
                    type(expected_subprotocols).__name__
                )
            )
        self._factories = dict()  # name -> IProtocolFactory
        self._pending_opens = defaultdict(
            deque
        )  # name -> deque[tuple[transport, address]]
        self._expected = expected_subprotocols

    # from manager (actually Inbound)
    # t is Subchannel (transport) instance
    # peer_addr is a SubchannelAddress
    def _got_open(self, t, peer_addr):
        # t is "ITransport"
        name = peer_addr.subprotocol
        if name in self._factories:
            self._connect(self._factories[name], t, peer_addr)
        else:
            if name not in self._expected:
                raise UnexpectedSubprotocol()
            # HYP-455: cap per-name pending OPENs. Legitimate use queues
            # 0..few per subprotocol while waiting for the local
            # `register()` call; an authenticated-but-hostile peer can
            # otherwise spend memory by spamming OPENs for an
            # expected-but-never-registered subprotocol name.
            #
            # `.get(name, ())` rather than `[name]` to avoid inserting an
            # empty deque on the cap-exceeded path — that would slowly
            # leak entries into _pending_opens for hostile names.
            if (
                len(self._pending_opens.get(name, ()))
                >= MAX_PENDING_OPENS_PER_SUBPROTOCOL
            ):
                raise PendingOpenCapExceeded(name)
            self._pending_opens[name].append((t, peer_addr))

    def _connect(self, factory, t, peer_addr):
        p = factory.buildProtocol(peer_addr)
        t._set_protocol(p)
        p.makeConnection(t)
        t._deliver_queued_data()

    def register(self, subprotocol_name, factory):
        if subprotocol_name in self._factories:
            raise ValueError(f'Already listening for subprotocol "{subprotocol_name}"')
        self._factories[subprotocol_name] = factory

        # deliver any pending OPENs that have accumulated for this
        # subprotocol
        try:
            pending = self._pending_opens.pop(subprotocol_name)
        except KeyError:
            pending = deque()

        while pending:
            (t, peer_addr) = pending.popleft()
            self._connect(factory, t, peer_addr)


@implementer(IListeningPort)
@attrs
class SubchannelListeningPort:
    _host_addr = attrib(validator=provides(IAddress))

    def startListening(self):
        pass

    def stopListening(self):
        # TODO
        pass

    def getHost(self):
        return self._host_addr
