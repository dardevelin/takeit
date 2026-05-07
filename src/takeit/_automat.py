"""Tiny helpers for Automat state machines."""


def first(outputs):
    """Return the first output produced by an Automat ``@m.input`` call.

    ``MethodicalMachine`` returns a list of all output return values when
    a transition fires. Most takeit transitions have exactly one
    value-returning output and want it unwrapped; this helper is the
    standard ``collector=`` for those cases.
    """
    return list(outputs)[0]
