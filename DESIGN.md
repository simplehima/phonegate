---
name: PhoneGate
description: The front-desk visitor log. Every unlock is a carbonless slip you stamp APPROVED or DENIED.
colors:
  canary: "#f4c430"
  canary-live: "#f6cc45"
  canary-live-line: "#c99a12"
  canary-paper: "#fbe7a0"
  canary-line: "#d9b94f"
  ink-blue: "#1f3a93"
  ink-blue-strong: "#172d75"
  on-ink: "#fcfcfa"
  stamp-green: "#0e7c4a"
  stamp-red: "#c4271f"
  stamp-red-strong: "#a11f18"
  pink-copy: "#fadbe3"
  pink-line: "#e5a9bb"
  pink-ink: "#8a1c3c"
  warn-line: "#b7862b"
  warn-ink: "#8a5a00"
  graphite-label: "#4f5666"
  graphite-muted: "#5b6272"
  record-paper: "#fcfcfa"
  paper-line: "#d3d9e3"
  desk: "#e3e7ee"
  rail: "#d6dce6"
  text: "#1b2130"
  night-desk: "#0d1220"
  night-rail: "#111829"
  night-paper: "#172035"
  night-paper-line: "#2b3753"
  night-canary-live: "#4a3b0c"
  night-canary-paper: "#2c2815"
  night-ink-blue: "#b3c4ff"
  night-stamp-green: "#62d09a"
  night-stamp-red: "#ff8b80"
  night-pink-copy: "#351c29"
  night-pink-ink: "#f5b3c6"
  night-warn-line: "#9c7a2c"
  night-warn-ink: "#e3b54a"
  night-label: "#a4adbf"
  night-text: "#e4e8f0"
typography:
  headline:
    fontFamily: "Archivo, Segoe UI Variable Display, Segoe UI, sans-serif"
    fontSize: "1.75rem"
    fontWeight: 750
    lineHeight: 1.2
    letterSpacing: "-0.015em"
    fontVariation: "'wdth' 108"
  title:
    fontFamily: "Archivo, Segoe UI Variable Display, Segoe UI, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 700
    lineHeight: 1.2
  body:
    fontFamily: "Segoe UI Variable Text, Segoe UI, system-ui, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "Archivo, Segoe UI Variable Display, Segoe UI, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 650
    letterSpacing: "0.08em"
  stamp:
    fontFamily: "Archivo, Segoe UI Variable Display, Segoe UI, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 800
    lineHeight: 1
    letterSpacing: "0.06em"
    fontVariation: "'wdth' 115"
  numeral:
    fontFamily: "JetBrains Mono, Cascadia Mono, Consolas, monospace"
    fontSize: "1.25rem"
    fontWeight: 600
    fontFeature: "'tnum' 1"
  numeral-display:
    fontFamily: "JetBrains Mono, Cascadia Mono, Consolas, monospace"
    fontSize: "4.25rem"
    fontWeight: 700
    lineHeight: 1
    letterSpacing: "0.06em"
    fontFeature: "'tnum' 1"
rounded:
  paper-android: "2px"
  stamp: "3px"
  slip: "4px"
  control: "6px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "24px"
  slip-x: "28px"
components:
  button-primary:
    backgroundColor: "{colors.ink-blue}"
    textColor: "{colors.on-ink}"
    rounded: "{rounded.control}"
    padding: "0 18px"
    height: "44px"
  button-primary-hover:
    backgroundColor: "{colors.ink-blue-strong}"
  button-secondary:
    backgroundColor: "{colors.record-paper}"
    textColor: "{colors.ink-blue}"
    rounded: "{rounded.control}"
    padding: "0 18px"
    height: "44px"
  button-danger:
    backgroundColor: "{colors.record-paper}"
    textColor: "{colors.stamp-red-strong}"
    rounded: "{rounded.control}"
    padding: "0 18px"
    height: "44px"
  button-quiet:
    textColor: "{colors.ink-blue}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "44px"
  stamp-approved:
    textColor: "{colors.stamp-green}"
    typography: "{typography.stamp}"
    rounded: "{rounded.stamp}"
    padding: "5px 8px"
  stamp-denied:
    textColor: "{colors.stamp-red}"
    typography: "{typography.stamp}"
    rounded: "{rounded.stamp}"
    padding: "5px 8px"
  stamp-not-me:
    backgroundColor: "{colors.pink-copy}"
    textColor: "{colors.pink-ink}"
    typography: "{typography.stamp}"
    rounded: "{rounded.stamp}"
    padding: "5px 8px"
  slip-live:
    backgroundColor: "{colors.canary-live}"
    textColor: "{colors.text}"
    rounded: "{rounded.slip}"
    padding: "24px 28px"
  slip-desk-pass:
    backgroundColor: "{colors.canary-paper}"
    textColor: "{colors.text}"
    rounded: "{rounded.slip}"
    padding: "24px 28px"
  slip-record:
    backgroundColor: "{colors.record-paper}"
    textColor: "{colors.text}"
    rounded: "{rounded.slip}"
    padding: "24px 28px"
  slip-pink:
    backgroundColor: "{colors.pink-copy}"
    textColor: "{colors.text}"
    rounded: "{rounded.slip}"
    padding: "24px 28px"
  input:
    backgroundColor: "{colors.record-paper}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "8px 12px"
    height: "44px"
  badge-cell:
    backgroundColor: "{colors.record-paper}"
    textColor: "{colors.ink-blue}"
    typography: "{typography.numeral-display}"
    rounded: "{rounded.control}"
    width: "104px"
    height: "128px"
  decision-deny:
    textColor: "{colors.stamp-red-strong}"
    typography: "{typography.stamp}"
    rounded: "{rounded.slip}"
    height: "60px"
  decision-approve:
    backgroundColor: "{colors.ink-blue}"
    textColor: "{colors.on-ink}"
    typography: "{typography.stamp}"
    rounded: "{rounded.slip}"
    height: "60px"
  not-me-action:
    backgroundColor: "{colors.pink-copy}"
    textColor: "{colors.pink-ink}"
    rounded: "{rounded.slip}"
    height: "56px"
---

# Design System: PhoneGate

## Overview

**Creative North Star: "The Front Desk Visitor Log"**

Every unlock is a visitor at your front desk and you are the guard. A request arrives as a filled-in carbonless slip: canary for the live slip waiting on you, white for records, pink copy for anything suspicious. Values are written in ballpoint ink-blue, form labels are printed in small graphite caps, sections are separated by perforations, and outcomes are stamped as bordered uppercase marks. Setup reads as issuing a desk pass. History reads as the desk logbook, with carbon copies on both devices.

The system works as an instrument, not a showcase. It is dense where the owner reads (ruled label grids, tabular numbers) and it stays calm where the owner decides (one slip, two equal stamps). The approval moment happens many times a day, in seconds and often one-handed, so the live slip owns the viewport and nothing competes with it. It refuses the authenticator-app default of a white card, a shield glyph and a blue button.

The world spans two surfaces. The Windows companion is a Tauri web UI that carries the tokens as CSS custom properties. The Android app is native Material 3, themed into the same world through a fixed role mapping (see Colors). Dynamic color (Material You) is deliberately off on Android, because a wallpaper-derived palette could make a denial read as an approval.

**Key Characteristics:**
- One canary slip for a live request; white records for everything already decided.
- Ink-blue for every filled-in value, and graphite tracked caps for every form label.
- Perforated rules between slip sections; the request countdown is a perforation that tears away.
- Flat, bordered, unrotated outcome stamps that always carry an icon and a word.
- Every number (badge number, pairing code, recovery codes, times, counts) is set in tabular numerals.
- Night shift dark theme: a carbon-navy desk, a dimmed canary slip and pale ink.

## Colors

A desk of cool grey paper stock, with one saturated canary sheet, a ballpoint blue and two stamp inks.

### Primary
- **Live Canary Slip** (`canary-live`, Android `slip` = `canary`): the background of a request that is waiting on the owner, and nothing else. On the web this is the live pairing-code compare slip and the "type this number" turn-off slip. On Android it is the approval screen's visitor slip. Its edge (`canary-live-line`) darkens the border and the dashed rules on it.
- **Ballpoint Ink-Blue** (`ink-blue`): filled-in values, numbers, the Approve stamp fill, primary buttons, focus rings in light mode, the countdown fill and the current nav item. It hovers to `ink-blue-strong`.

### Secondary
- **Pale Desk-Pass Canary** (`canary-paper`, edge `canary-line`): the companion's status slip when protection is on (paired and enforcing), used as the desk pass for the PC. It is never a live request and never a warning.
- **Pink Carbon Copy** (`pink-copy`, edge `pink-line`, text `pink-ink`): "This wasn't me", NOT ME / WRONG NUMBER stamps, serious desk notices, error notices, suspicious logbook rows, the failed-pairing slip and the preview banner.

### Tertiary
- **Stamp Green** (`stamp-green`): APPROVED, PAIRED, KEY VERIFIED, PROTECTION ON, and relay reachable.
- **Stamp Red** (`stamp-red`, text weight `stamp-red-strong`): DENIED, NOT PAIRED, the Deny stamp's border, destructive buttons, invalid inputs and the last seconds of a countdown. On Android the Deny stamp uses `deniedOnSlip` (#A11E17) so it holds contrast on canary.
- **Amber Warning** (`warn-line`, `warn-ink`): warnings are white records with an amber rule and an amber icon, as in the warning notice and the acknowledgement box. Amber is never a fill.

### Neutral
- **Record Paper** (`record-paper`): white records, inputs, badge cells, dialogs and the QR sheet (the QR sheet is pure #ffffff in both themes).
- **Desk Grey** (`desk`) and **Rail Grey** (`rail`): the page ground and the companion's navigation rail. Android ground is #E4E7EC.
- **Paper Rule** (`paper-line`): hairline field rules, slip borders and logbook rules.
- **Graphite Label** (`graphite-label`, muted `graphite-muted`): form labels, help text, units and secondary lines. On the live slip, labels switch to `--canary-live-label` (#3F4553; Android `slipLabel` #3B3A36).
- **Desk Text** (`text`): body copy.

### Night shift
The dark theme is a night shift, not an inversion. The desk becomes carbon navy (`night-desk`), records become `night-paper`, and the live canary dims to a dark ochre sheet (`night-canary-live`; Android `slip` #3A3118 with a bright #B8922A edge). Ink turns pale (`night-ink-blue`), and stamps lift to `night-stamp-green` and `night-stamp-red`. Pink copy becomes a deep plum (`night-pink-copy`) with pale pink ink. Amber lifts to `night-warn-ink`. The focus ring swaps to canary (#f4c430) on navy. The companion honours `prefers-color-scheme` and a manual Auto / Light / Dark switch (`data-theme`). Android follows the system setting.

### Android Material 3 role mapping
`primary` = ink-blue (#1F3A93, night #B7C8FF). `secondaryContainer` = canary slip. `tertiary` = stamp green. `error` = stamp red. `errorContainer` / `onErrorContainer` = pink copy / pink ink (#F7C6CF / #6B1426). `background` and `surface` = desk ground. `surfaceContainerLowest` / `surfaceContainerLow` = record paper. `onSurfaceVariant` = graphite label. `outline` = rule. Colors that Material has no role for (slip edge, slip label, denied-on-slip, neutral stamp) live in `Desk.colors`.

### Named Rules
**The One Live Slip Rule.** Full-strength canary means "a request is waiting on you right now". Records, warnings and settled status never use it.

**The Amber-Is-A-Rule Rule.** Warnings are white records with an amber border and icon. Canary and amber are never confused: a warning is never yellow paper.

**The Fixed Ink Rule.** State colors are fixed and never derived (no dynamic color). Green approves, red denies and pink means someone else. Each is always paired with an icon and a word.

## Typography

**Display Font:** Archivo, variable in weight and width (with Segoe UI Variable Display, Segoe UI)
**Body Font:** Segoe UI Variable Text on Windows (with Segoe UI, system-ui); Roboto (the Material default) on Android
**Label/Mono Font:** JetBrains Mono (with Cascadia Mono, Consolas), used for every number

**Character:** Archivo is the printed form: headings, labels and stamps in a slightly widened, heavy cut. The workhorse system sans is the handwriting space between. JetBrains Mono gives every code and number the fixed columns of a ledger.

### Hierarchy
- **Headline** (Archivo 750, 1.75rem, width 108%, -0.015em): page titles. On Android, `headlineMedium` Archivo Bold carries the PC name on the slip.
- **Title** (Archivo 700, 1.125–1.5rem): slip titles, section heads, the compare question (1.5rem 750).
- **Body** (system sans 400, 1rem / 1.5): prose, capped at 60–65ch.
- **Label** (Archivo 650, 0.75rem, 0.08em, uppercase, graphite): form field labels (`dt`), logbook column heads. On Android, `labelSmall` Medium with 1.1sp tracking, uppercased by `FormLabel`.
- **Stamp** (Archivo 800, width 115%, 0.06em, uppercase): outcome stamps, 0.75rem inline and 1.875rem for large stamps. On Android the stamp is 20sp ExtraBold with 1.6sp tracking, and it steps down to 11sp at large font scales rather than clipping.
- **Numeral** (JetBrains Mono, tabular): field numbers at 1.25rem 600 in ink. Recovery codes are 1.0625rem 600. Times, counts and step marks are also mono.
- **Numeral display** (JetBrains Mono 700): the 6-digit pairing code (4.25rem, 3.25rem when narrow) and the badge cells (5.5rem on web; `badge` 44sp and `code` 40sp on Android).

### Named Rules
**The Ledger Numerals Rule.** Every number is tabular (`font-variant-numeric: tabular-nums`), and every code, badge number or time is also set in JetBrains Mono.

**The Printed Label Rule.** Tracked uppercase graphite caps are reserved for form field labels that sit directly above or beside their value, as on a printed form. They are never used as a heading ornament above a title.

## Layout

The companion is a two-column shell: a 15rem navigation rail on rail grey, and a scrolling main column (padding 2rem 2.5rem, page max 72rem). Pages pair a primary slip with a secondary column (status 1.35fr : 1fr, turn-off 1.1fr : 1fr, settings 2 × 1fr), gap 1.5–1.75rem. Below 1080px these collapse to one column. Below 760px the rail becomes a wrapping top bar, fields stack label-over-value, and the code grid goes to one column.

Every PC, status and history entry uses one ruled label grid: a fixed label column (10rem on web, 8rem in settings, 96dp on Android) and a value column, with a hairline or dashed rule under each row. Slips pad 24px by 28px on web and 20dp by 16dp on Android, with an internal gap of 16px.

The Android approval slip is capped at 560dp and keeps its decision group (badge number, stamps, "This wasn't me") pinned above the keyboard while context fields scroll with a fade edge. From 125% font scale the whole slip scrolls as one sheet. Touch targets are at least 44px on web and 48dp on Android. The decision stamps are 60dp and the not-me action is 56dp.

## Elevation & Depth

The system is paper on a desk: mostly flat, with a soft ambient lift only on sheets. On the web, slips and the QR sheet carry `--shadow`. Records inside slips, notices and desk notes are flat, bordered paper. Dialogs lift higher over a navy scrim. On Android only the live visitor slip lifts (2dp shadow elevation), and record sheets are flat with an outline-variant border. Stamps and buttons never cast shadows.

### Shadow Vocabulary
- **Sheet** (`box-shadow: 0 1px 2px rgb(31 42 70 / 0.08), 0 6px 18px rgb(31 42 70 / 0.08)`; night `0 1px 2px rgb(0 0 0 / 0.3), 0 8px 24px rgb(0 0 0 / 0.28)`): every slip and the QR sheet.
- **Dialog** (`box-shadow: 0 20px 60px rgb(10 16 32 / 0.35)`): modal dialogs only.

### Named Rules
**The Flat Stamp Rule.** Stamps are ink on paper: a 2px (Android 2–3dp) current-color border, with no shadow, no rotation and no distress texture.

## Shapes

Paper is almost square and controls are gently eased. On web, slips and notices use 4px, controls and inputs 6px, and stamps 3px (4px large). On Android, paper is 2dp and controls and stamps are 4dp across every Material shape step. Borders do the structural work: hairline 1px paper rules, 1.5px control borders, 2px stamp and badge-cell borders, and 2.5dp decision-stamp borders on Android.

Perforations separate slip sections. On the web, a perforation is a row of punched holes, drawn as 2px dots in the desk color every 12px across the slip's full bleed. The countdown track is a dotted line with an ink fill that shrinks. On Android, perforations are dashed lines (10/7 for rules, 6dp/5dp for the countdown), and the torn part of the countdown stays as a faint dashed trace. The history logbook adds a faint red margin line.

## Components

### Buttons
Buttons are plain and firm, like a desk clerk's controls.
- **Shape:** gently eased (6px), min height 44px, 18px side padding, weight 600.
- **Primary:** ink-blue fill with paper text; hover goes to ink-blue-strong.
- **Secondary:** paper fill, ink text and a 1.5px ink border; hover tints 8% ink.
- **Danger:** paper fill, red-strong text and a red border; hover tints 9% red.
- **Quiet:** transparent with ink text, for "Check again" and "Stop waiting".
- **States:** a 3px focus outline (ink in light, canary in night) with a 2px offset. Active nudges down 1px. Disabled drops to 55% opacity. Busy uses `aria-busy` at 75%.

### Decision stamps (signature)
Deny and Approve sit side by side at equal width by construction, because deny is never harder than approve. On Android, **Deny** is a transparent stamp with a 2.5dp red-on-slip border and a close icon, and needs no number or biometric. **Approve** is an ink-blue filled stamp with a check icon, enabled only once 2 digits are typed. Disabled, it shows a 16% ink wash with muted text. Both use the stamp type, 60dp tall and 4dp corners. **This wasn't me** sits beneath as a full-width pink-copy action (56dp) with a warning icon. The companion's pairing compare uses the same grammar: two equal grid cells, 52px tall.

### Outcome stamps
Flat, bordered uppercase marks with an icon and a word: 2px current-color border, Archivo 800 at width 115%, 3px corners. Variants: ok (green), bad (red), alert (pink ink on pink copy), ink and muted (neutral). The large stamp (1.875rem) states a slip's result, such as PROTECTION ON, PAIRED or NOT PAIRED.

### Slips / Containers
- **Corner Style:** 4px web, 2dp Android.
- **Background:** live canary for a request waiting on the owner; pale canary for the protected-status desk pass; record paper for records; pink copy for failed or suspicious sheets.
- **Shadow Strategy:** the sheet shadow (see Elevation & Depth).
- **Border:** 1px in the slip's own line color; the slip head carries a matching bottom rule.
- **Internal Padding:** 24px × 28px, 16px gap.

### Badge number
Two tall cells for the 2-digit number. On web they are paper cells 104 × 128px with a 2px ink border and 5.5rem ink mono digits. On Android they are 64 × 72dp record cells with a 2dp slip-edge border, and the active cell's border becomes 3dp ink. The real field is transparent so the IME, focus and TalkBack behavior stay native.

### Inputs / Fields
- **Style:** paper fill, 1.5px graphite border, 6px corners, min 44px, max 34rem, ink caret. Codes use mono with 0.04em tracking and uppercase.
- **Focus:** the border and outline switch to the focus color. Hover darkens the border to text.
- **Error / Disabled:** `aria-invalid` gives a red border with red-strong 600 error text. Disabled mixes paper-line into the fill.

### Notices and desk notes
White records with an icon column. Error notices and serious notes are pink copy with a red-strong icon. Warnings keep white paper with an amber rule and an amber icon. Info uses an ink icon and ok uses a green icon. A notice has a title in weight 650 and a body capped at 65ch.

### Navigation
The companion rail uses 44px items with a graphite icon and 500 text. Hover mixes paper at 55%. The current page gets a paper background, ink text in 650 and a 1px inset paper-line ring. The theme switch is a three-choice segmented control (Auto / Light / Dark) in the same style. Below 760px the rail wraps into a top bar.

### Logbook
The history table sits on a record slip with a faint red margin line. Column heads use the label style over a 2px rule, and rows sit on 1px rules. The first column holds times in mono. Suspicious rows tint 75% pink copy, and each outcome cell holds an inline stamp with an optional note.

## Do's and Don'ts

### Do:
- **Do** reserve full-strength canary (`canary-live`, Android `canary`) for a request that is waiting on the owner right now.
- **Do** keep Deny and Approve at equal width and equal height, side by side, with "This wasn't me" full-width beneath in pink copy.
- **Do** set every number in tabular numerals, and every code, badge number and time in JetBrains Mono.
- **Do** write filled-in values in ink-blue and form labels in graphite tracked caps directly beside or above their value.
- **Do** pair every state color with an icon and a word (stamps, notices, reachability).
- **Do** separate slip sections with a perforation: punched dots on web, dashed lines on Android.
- **Do** design night shift as its own palette: a carbon-navy desk, dimmed canary, pale ink and a canary focus ring.

### Don't:
- **Don't** use canary for warnings. Warnings are white records with an amber rule (`warn-line`) and amber icon (`warn-ink`).
- **Don't** rotate, distress or shadow stamps; they are flat bordered marks.
- **Don't** enable Material You dynamic color, or derive state colors from anything else.
- **Don't** put tracked-caps kickers or eyebrow labels above headings; caps are for form field labels only.
- **Don't** make Deny smaller, quieter or further from reach than Approve.
- **Don't** fall back to the authenticator-app default of a white card, a shield hero glyph and a lone blue button.
