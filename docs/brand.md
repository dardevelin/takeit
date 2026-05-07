# TakeIt — Brand Foundations
*Mascot: Yobi*

---

## 1. The one-liner

**TakeIt** is peer-to-peer file transfer over Nostr, with resume.
**Yobi** is the small courier who carries the file.

Everything in the brand serves one of those two sentences. If a piece of design or copy doesn't make the product feel more peer-to-peer, more reliable, or more *Yobi*, cut it.

---

## 2. Personality

Yobi is **small, determined, single-minded.** Not cute-for-cute's-sake. Not a corporate mascot smiling at a camera. The energy is closer to a courier who has memorized the route and will get there even if it's raining.

Three traits, in order of priority:

1. **Capable.** Yobi *finishes things*. Resume isn't a feature, it's the personality. Pause Yobi, close the laptop, come back tomorrow — Yobi is still holding the parcel.
2. **Unfussy.** No flourish. Yobi doesn't celebrate the handshake, doesn't narrate the transfer, doesn't congratulate you for sending a file. Delivers, then waits.
3. **Warm without being soft.** The rosy cheeks are the only concession to cuteness. Everything else is geometry and intent.

What Yobi is *not*: a sidekick, a helper, a guide, a tutorial character. Yobi doesn't have a personality arc and doesn't grow. Yobi is a tool that happens to have a face, the way a stapler has a name.

---

## 3. Color system

### Primary
- **Violet** `#5B3FD9` — body, primary CTAs, brand surface.
  Chosen for Nostr lineage (purple is the de-facto color of the protocol's ecosystem) without aping any specific client.
- **Deep violet** `#3D27A8` — tape, hover states, pressed states, secondary structural elements.

### Accent
- **Coral** `#FF8A6B` — cheeks, success sparkles, *one* accent at a time. Never used for primary actions. This is the warmth note — when in doubt, leave it out.

### Ink
- **Ink** `#1A1726` — outlines, body text, dark surfaces. Not pure black. The slight violet undertone keeps the system unified.

### Neutrals
- **Cream** `#F4F1EC` — primary background. Not white. The warmth matters.
- **Smoke** `#9B95A8` — disabled states, captions on dark.
- **Mist** `#6B6478` — captions on cream, secondary text.

### Semantic (used sparingly)
- **Signal green** `#3FB67A` — successful delivery, only at the moment of confirmation.
- **Caution amber** `#E8A83C` — paused/waiting states, never alarming.
- **Stop red** `#D9483F` — only for failed/aborted transfers. Never for warnings.

### Color rules
- **Two colors max** in any single composition (excluding ink and cream, which are structural). Violet + coral, or violet + green. Never violet + coral + green together.
- **Coral is rare.** If every screen has coral, none of them do.
- **No gradients.** Anywhere. Flat fills only. The brand competes with a market full of glassmorphic transfer apps — flatness is differentiation.
- **No transparency tricks** on Yobi himself. Yobi is opaque. Always.

---

## 4. Typography

### Display & UI
**Inter** (or system equivalent — SF Pro on Apple, Segoe on Windows). 
Two weights only: **400 Regular** and **500 Medium**. Never 600+, never 300.

### Monospace (for transfer details, hashes, relay addresses)
**JetBrains Mono** or **IBM Plex Mono**.

### Hierarchy
- **Display**: 38–48px, weight 500, letter-spacing -0.02em. App splash, marketing.
- **H1**: 24px, weight 500.
- **H2**: 18px, weight 500.
- **Body**: 16px, weight 400, line-height 1.5.
- **Caption**: 13px, weight 400.
- **Eyebrow** (the small uppercase label above sections): 12px, weight 500, letter-spacing 0.04em, uppercase.

### Sentence case everywhere.
No Title Case, no ALL CAPS except eyebrow labels. Even buttons: "Send file" not "Send File".

---

## 5. Voice & copy

Read this section out loud. If it doesn't sound like a slightly tired courier with a clipboard, rewrite it.

### Rules

1. **Short sentences.** If a sentence has a comma, ask whether it needs one.
2. **Verbs over nouns.** "Yobi sent it" not "Transfer complete." "Picking up where you stopped" not "Resume in progress."
3. **Yobi is the subject of action sentences.** The product does things. The user is just the one who asked.
4. **No exclamation marks.** Yobi does not get excited. The work was the point.
5. **No emojis in product copy.** (Marketing site can break this rule once.)
6. **Numbers stay numerals.** "3 files" not "three files."
7. **No cleverness in error states.** When something is wrong, be plain. "Lost the connection. Yobi will retry." Not "Oops! Yobi tripped!"

### Vocabulary

| Use | Don't use |
|---|---|
| Send / Receive | Upload / Download |
| Carry, hold | Store, cache |
| Drop | Cancel |
| Pick up | Resume |
| The other side | The peer / The recipient |
| Relay | Server |
| Find each other | Connect |

### Examples

**Splash**: *"Yobi carries files between people."*

**Empty state, no transfers yet**: *"Drop a file. Yobi will find the other side."*

**Transferring**: *"Yobi has 47% of it."*

**Paused / will resume**: *"Yobi is holding it. Reopen TakeIt to keep going."*

**Done**: *"Delivered."* (one word, no celebration)

**Error**: *"Lost the other side. Yobi will try again when you're both online."*

**Onboarding**: *"You'll need a Nostr key. TakeIt uses the relay network to find your friend — no central server, no account, no upload."*

---

## 6. Iconography & illustration

- All product icons: **Tabler outline**, 1.5px stroke, never filled.
- All illustrations featuring Yobi: **2px outline** on the body, flat fills.
- Background scenes: schematic, not literal. Yobi standing on a horizon line, not in a landscape.
- No drop shadows on Yobi. A soft elliptical ground shadow at 12% opacity is the *only* shadow allowed.

---

## 7. Sound (for later)

When you get to sound design: a single soft *thunk* on delivery (the parcel landing). No fanfare. No swoosh on send. Silence when paused. The absence of sound is part of the personality.
