---
name: terces
description: A self-hosted secret scanner whose report and site show real scan output on quiet paper panels.
colors:
  accent: "#2f5d50"
  accent-ink: "#ffffff"
  accent-soft: "#e4eeea"
  bg: "#f7f7f5"
  panel: "#ffffff"
  ink: "#1d1d1b"
  muted: "#62625d"
  line: "#e2e2dc"
  line-strong: "#cfcfc7"
  code-bg: "#f0f0ec"
  add-bg: "#e9f2ee"
  hit-bg: "#fbe3d6"
  hit-ink: "#1d1d1b"
  critical: "#a4161a"
  high: "#c2410c"
  medium: "#b08900"
  low: "#5c7080"
  accent-dark: "#7fb7a4"
  accent-ink-dark: "#10201b"
  accent-soft-dark: "#21302b"
  bg-dark: "#141413"
  panel-dark: "#1d1d1b"
  ink-dark: "#ecece6"
  muted-dark: "#a3a39b"
  line-dark: "#33332f"
  line-strong-dark: "#474741"
  code-bg-dark: "#262623"
  add-bg-dark: "#1f2c27"
  hit-bg-dark: "#4a2a1a"
  hit-ink-dark: "#ffd9c2"
  critical-dark: "#ff6b6b"
  high-dark: "#ff922b"
  medium-dark: "#ffd43b"
  low-dark: "#a5b4c3"
typography:
  display:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica Neue, sans-serif"
    fontSize: "clamp(2.3rem, 4.6vw, 3.75rem)"
    fontWeight: 700
    lineHeight: 1.04
    letterSpacing: "-0.032em"
  headline:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica Neue, sans-serif"
    fontSize: "clamp(1.75rem, 3vw, 2.5rem)"
    fontWeight: 700
    lineHeight: 1.1
    letterSpacing: "-0.025em"
  title:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica Neue, sans-serif"
    fontSize: "clamp(1.35rem, 2.2vw, 1.75rem)"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "-0.02em"
  body:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica Neue, sans-serif"
    fontSize: "16px"
    fontWeight: 400
    lineHeight: 1.6
  label:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica Neue, sans-serif"
    fontSize: "12px"
    fontWeight: 600
    lineHeight: 1.4
    letterSpacing: "0.04em"
  mono:
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, Liberation Mono, monospace"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.6
  wordmark:
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, Liberation Mono, monospace"
    fontSize: "19px"
    fontWeight: 650
    lineHeight: 1
    letterSpacing: "-0.02em"
rounded:
  xs: "3px"
  sm: "4px"
  md: "8px"
  lg: "10px"
  pill: "999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "14px"
  lg: "18px"
  xl: "32px"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.accent-ink}"
    rounded: "9px"
    padding: "13px 18px"
  button-secondary:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink}"
    rounded: "9px"
    padding: "13px 18px"
  button-small:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink}"
    rounded: "9px"
    padding: "9px 13px"
  panel:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink}"
    rounded: "{rounded.lg}"
  command-box:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink}"
    typography: "{typography.mono}"
    rounded: "{rounded.lg}"
    padding: "6px 6px 6px 16px"
  code-chip:
    backgroundColor: "{colors.code-bg}"
    textColor: "{colors.ink}"
    typography: "{typography.mono}"
    rounded: "{rounded.sm}"
    padding: "0.1em 0.35em"
  severity-pill-critical:
    backgroundColor: "{colors.critical}"
    textColor: "{colors.accent-ink}"
    rounded: "{rounded.pill}"
    padding: "1px 10px"
  severity-pill-high:
    backgroundColor: "{colors.high}"
    textColor: "{colors.accent-ink}"
    rounded: "{rounded.pill}"
    padding: "1px 10px"
  severity-pill-medium:
    backgroundColor: "{colors.medium}"
    textColor: "{colors.ink}"
    rounded: "{rounded.pill}"
    padding: "1px 10px"
  severity-pill-low:
    backgroundColor: "{colors.low}"
    textColor: "{colors.accent-ink}"
    rounded: "{rounded.pill}"
    padding: "1px 10px"
  tab:
    backgroundColor: "{colors.code-bg}"
    textColor: "{colors.muted}"
    rounded: "7px"
    padding: "10px 14px"
  tab-selected:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink}"
    rounded: "7px"
    padding: "10px 14px"
  nav-link:
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "8px 12px"
  nav-link-hover:
    backgroundColor: "{colors.code-bg}"
    textColor: "{colors.ink}"
  filter-chip:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink}"
    rounded: "{rounded.pill}"
    padding: "7px 12px"
  search-input:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "8px 12px"
---

# Design System: terces

## Overview

**Creative North Star: "The Evidence Sheet"**

terces shows proof, and the visual system exists to carry that proof. Every surface is a quiet paper ground with white panels on it. The panels hold real scan output: commands, diffs, stored rows, tables and terminal text. The system uses one deep green accent and four severity hues. Everything else is warm gray.

The system has two homes. The first home is the HTML report that the binary writes, in `internal/render/report.html`. The second home is the GitHub Pages site in `site/`. The site inherits the tokens of the report and adds the marketing and teaching parts. Both homes follow light and dark mode from the same custom property names. Both homes make no external requests and load no font files.

The density is that of a working tool. Text is small and exact, panels are tight, and decoration is close to zero. Depth comes from a hairline border and one soft shadow, not from color fills or large lifts.

**Key Characteristics:**

- A warm paper ground with white hairline panels and `10px` corners.
- Monospace for every artifact. System sans for prose.
- One green accent for action and current state. Four severity hues for severity only.
- Dark mode swaps values on the same tokens.
- Real output, never a full secret. A preview or a redaction chip stands in for the secret.

## Colors

The palette is warm neutral gray with one deep green accent and a fixed four-step severity scale.

### Primary

- **Ledger Green** `accent`: Marks the primary button, links, the focus ring, text selection, the current step in the rail, the regex window and the winning value in a benchmark table. In dark mode, `accent-dark` replaces it.
- **Accent Ink** `accent-ink`: Text and strokes on a Ledger Green fill. In dark mode, `accent-ink-dark` is a near-black green.
- **Pale Ledger** `accent-soft`: The fill of the regex window in the engine diagram. Use it for a highlighted region inside a panel.

### Secondary

- **Severity Critical** `critical`: Critical pills and counts. The site also uses it for the failed check icon and the `Required · Failed` state.
- **Severity High** `high`: High pills and counts, and the underline of a keyword hit.
- **Severity Medium** `medium`: Medium pills and counts. The pill carries `ink` text on this fill.
- **Severity Low** `low`: Low pills and counts.

### Tertiary

- **Added Line** `add-bg`: The background of an added line in a diff panel. Site only.
- **Keyword Hit** `hit-bg` with `hit-ink`: The `mark` fill for a keyword such as `ghp_`. Site only.

### Neutral

- **Paper** `bg`: The page ground. Hop labels also sit on it.
- **Sheet** `panel`: Every panel, table wrapper, button at rest and selected tab.
- **Ink** `ink`: Body text and headings. The report names this token `--text`.
- **Graphite** `muted`: Secondary text, captions, table headers, line numbers and the shell prompt.
- **Hairline** `line`: Every panel border and row divider.
- **Strong Hairline** `line-strong`: Secondary button borders, the scrollbar thumb and the top of the hop line. Site only.
- **Code Wash** `code-bg`: Inline code chips, nav hover, the tab strip and the terminal caption bar.

### Named Rules

**The One Accent Rule.** Ledger Green is the only hue that means "act here" or "you are here". Do not add a second brand hue.

**The Severity Is Data Rule.** The four severity hues appear only where they encode severity or a failed state. Do not use them for decoration or emphasis.

**The Same Tokens Rule.** Dark mode changes the values of the same custom properties inside `prefers-color-scheme: dark`. Components do not carry their own dark styles. The one exception is pill text, which turns to `bg-dark` on the bright dark-mode severity fills.

## Typography

**Display Font:** the system sans stack `system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", sans-serif`
**Body Font:** the same system sans stack
**Label and Mono Font:** `ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace`

**Character:** The sans carries prose and the mono carries evidence. The contrast between the two faces tells the reader what is real output and what is explanation.

### Hierarchy

- **Display** `700`, `clamp(2.3rem, 4.6vw, 3.75rem)`, line height `1.04`: The hero headline only. It has tight tracking and a measure of `15ch`, which grows to `18ch` below `960px`. Site only.
- **Headline** `700`, `clamp(1.75rem, 3vw, 2.5rem)`, line height `1.1`: Section titles on the site. The report uses a fixed `26px` title and `18px` section headings.
- **Title** `700`, `clamp(1.35rem, 2.2vw, 1.75rem)`, line height `1.2`: Journey step headings. Smaller list headings use `1.05rem`.
- **Body** `400`, `16px`, line height `1.6`: Site prose, at a measure of `52ch` to `68ch`. The lead paragraph is `1.125rem` in Graphite. The report body is `15px` with line height `1.5`.
- **Label** `600`, `12px`, letter spacing `0.04em`, uppercase: Table column headers in both homes and stat card labels in the report.
- **Mono** `13px` to `14px`, line height `1.6`: Commands, paths, rule IDs, fingerprints, previews, terminal output and diff lines.
- **Wordmark** mono `650`, `19px`, letter spacing `-0.02em`: The lowercase `terces` mark. The footer uses it at `15px`.

### Named Rules

**The Artifact In Mono Rule.** Set every command, path, rule ID, fingerprint, preview and output line in the mono stack. Set every sentence of explanation in the sans stack.

**The Tabular Numbers Rule.** Tables and counts use `font-variant-numeric: tabular-nums`, so the columns of numbers align.

## Layout

The site uses one centered column of `min(1180px, 100% - 32px)`. The report uses `max-width: 1280px` with `16px` side padding.

The site hero is a two-column grid of `1.05fr` and `1fr`. The journey is a grid of a `250px` sticky rail and a fluid column. Section heads are a two-column grid of title and intro, aligned at the bottom. Section padding uses `clamp(56px, 9vh, 104px)` and a `line` top border between sections. The gap between journey steps is `clamp(72px, 12vh, 128px)`.

The report lays out stat cards with `repeat(auto-fit, minmax(150px, 1fr))` and breakdown panels with `minmax(300px, 1fr)`, both with a `12px` gap.

The spacing rhythm is small. Gaps of `8px`, `14px` and `18px` repeat inside and between panels. Panel heads and table cells use `9px` to `10px` vertical padding and `12px` to `14px` horizontal padding.

Breakpoints are `960px` and `720px`. At `960px`, every two-column grid becomes one column, and a sticky step bar replaces the rail. At `720px`, the header keeps only the GitHub link, and two-up tables stack. Terminal output keeps its columns and scrolls sideways with a fade mask at the right edge.

## Elevation & Depth

The system is flat with one soft shadow. A panel separates from the ground through the white Sheet fill and a `1px` Hairline border. The shadow adds a small lift and does not carry meaning. The rail and the tab strip reuse the same shadow to mark the current item.

### Shadow Vocabulary

- **Panel lift** `box-shadow: 0 1px 2px rgba(29, 29, 27, 0.05), 0 6px 16px -10px rgba(29, 29, 27, 0.16)`: Panels, command boxes, terminal figures, tab sets, the current rail step and the selected tab. In dark mode, the same two layers use black at `0.4` and `0.6`.
- **Report lift** `box-shadow: 0 1px 2px rgba(0, 0, 0, 0.06)`: Report cards and the table wrapper. The report sets it to `none` in dark mode.

### Named Rules

**The Hairline First Rule.** A panel always has its `1px` Hairline border. The shadow is optional and stays soft. Do not use a shadow without the border.

## Shapes

Corners are gently rounded and consistent. Panels, command boxes, tab sets, table wrappers, screenshots and report cards use `10px`. Buttons use `9px`. Nav links, the copy button, the skip link and the report search field use `8px`. Tabs use `7px`. Inline code chips and the redaction chip use `4px`. The keyword `mark` uses `3px`.

Pills use `999px`. They hold severity, hop labels and the report filter chips. Quick-start step numbers are `30px` circles in Ledger Green.

Line icons are inline SVG with a `1.8px` to `2px` round stroke in `currentColor`. The logo is a rounded square with three text lines. The favicon draws the same shape and follows dark mode.

## Components

### Buttons

Buttons are solid and plain. They lift through border color, not through shadow.

- **Shape:** gently rounded `9px` corners, `1px` border, `600` sans at `15px`.
- **Primary:** Ledger Green fill and border with Accent Ink text. On hover, the fill mixes `86%` accent with `ink`.
- **Secondary:** Sheet fill, Strong Hairline border, Ink text. On hover, the border turns Ink.
- **Small:** `9px 13px` padding at `14px`. It carries a `16px` line icon.
- **Active:** the button moves down `1px`.
- **Focus:** a `2px` Ledger Green outline with a `3px` offset. This ring applies to every focusable element.
- **Copy button:** a `36px` square icon button inside a command box. It is Graphite at rest and turns Ledger Green for `1600ms` after a copy.

### Chips

- **Severity pill:** `600` sans at `12px`, `999px` corners, `1px 10px` padding, a severity fill and light text. Medium carries `ink` text. In dark mode, all pills carry `bg-dark` text.
- **Code chip:** Code Wash fill, `4px` corners, mono at `0.875em`. An inline chip stays on one line.
- **Redaction chip:** Code Wash fill, Graphite italic sans at `12px`. It replaces the secret part of a token with a count such as `36 characters`. Site only.
- **Filter chip:** a `999px` Sheet button with a Hairline border at `13px`. An off filter has `aria-pressed="false"` and `0.45` opacity. Report only.

### Cards / Containers

- **Corner Style:** `10px`.
- **Background:** Sheet on Paper.
- **Shadow Strategy:** Panel lift. Refer to Elevation & Depth.
- **Border:** `1px` Hairline. A panel head has a Hairline bottom border.
- **Internal Padding:** `10px 14px` for heads and rows. `14px 16px` for terminal output and report cards.

### Inputs / Fields

- **Search field:** Sheet fill, `1px` Hairline border, `8px` corners, `8px 12px` padding, inherited sans. Report only.
- **Focus:** the global Ledger Green ring.

### Navigation

- **Header:** a sticky `64px` bar on Paper at `88%` opacity with a blur and a Hairline bottom border. Links are Ink at `15px` with `8px 12px` padding. On hover, a Code Wash fill appears. The GitHub link always shows a Hairline border. Site only.
- **Step rail:** a numbered list with mono step numbers in Graphite. The current step gets a Sheet fill, Panel lift and a Ledger Green number. A `2px` Ledger Green bar grows down the rail as the reader scrolls. Site only.
- **Tabs:** a Code Wash strip with transparent `600` tabs in Graphite. The selected tab gets a Sheet fill, Ink text and Panel lift. Site only.

### Command Box

A Sheet panel that holds one shell command in mono after a Graphite `$` prompt, with a copy button at the right. The copy action removes the prompt. Long commands wrap only at spaces. Site only.

### Terminal Figure

A Sheet panel whose caption is a Code Wash bar with the command in mono. The body is real CLI output at `13px` with line height `1.6`. Below `720px`, the output keeps its columns, scrolls sideways and fades at the right edge. Site only.

### Data Table

Column headers use the Label style in Graphite. Rows have a Hairline bottom border and `9px` to `10px` vertical padding. The last row has no border. In the report, headers are sticky, and a click sorts the column. On the site, the winning value in the last column is `700` Ledger Green.

### Fingerprint Demo

The hero shows a diff panel, a hop line and a stored-row panel. The diff panel marks the added line with Added Line and the keyword with Keyword Hit plus a `2px` Severity High underline. The stored row is a two-column definition list with mono keys. While a new fingerprint computes, the value blurs `3px` at `0.55` opacity over `380ms`. The fake token settles over `520ms`. With `prefers-reduced-motion: reduce`, both changes are instant. Site only.

### Motion

All transitions use the ease `cubic-bezier(0.16, 1, 0.3, 1)`. Hover color changes take `160ms`. Rail and card moves take `200ms`. The rail bar takes `300ms`. Motion only confirms state. It never hides content.

## Do's and Don'ts

### Do:

- **Do** put every artifact on a Sheet panel with a `1px` Hairline border and `10px` corners.
- **Do** use the mono stack for every command, path, rule ID, preview, fingerprint and output line.
- **Do** show real output from the binary, made from synthetic fake tokens, and label it as synthetic.
- **Do** show a secret as a preview such as `ghp_… (40)` or as a redaction chip.
- **Do** add every new color as a custom property with a light value and a dark value.
- **Do** keep text on every fill at `4.5:1` contrast or more.
- **Do** respect `prefers-reduced-motion: reduce` for every scripted animation and for smooth scroll.

### Don't:

- **Don't** render a full token-shaped string in markup, a screenshot or an example.
- **Don't** use a severity hue for decoration, a heading or a link.
- **Don't** add a second accent hue.
- **Don't** load external fonts, images or scripts. Both homes run under a strict Content Security Policy.
- **Don't** use a large or dark drop shadow. The Panel lift is the only site shadow.
- **Don't** fill a panel with a tint to make it stand out. Use the border, the shadow and the content.
