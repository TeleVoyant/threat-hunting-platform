# APT Threat Hunting Platform — Design System

> **Premium cyber operations center (SOC), intelligence-grade, low-noise interface.**
> Built around the magnifying-glass + target + shield mark.

This design system codifies the visual language, tone, and component vocabulary for the **APT Threat Hunting Platform** — an enterprise APT detection product that uses **XGBoost-driven models to surface credential-based lateral movement and DNS exfiltration**. The audience is SOC analysts and threat hunters working long, focused sessions; everything in this system is tuned for **signal density, rapid visual scanning, and operational clarity**.

---

## Source materials

This system was built from materials provided by the brand owner:

- 📄 `uploads/APT_Threat_Hunting_Platform_Brand_Style_Guide.pdf` — 4-page designer handoff brief covering positioning, logo system, color tokens, typography, themes, components, and do/don'ts.
- 🖼️ `uploads/APT THP various logos (banners, sidebar,etc).png` — 19-cell logo sheet with primary/horizontal/stacked marks, favicon set (16→512), sidebar/active variants, light/dark theme icons, loading/login lockups, social profile pics, OG banner, email signature, watermark pattern, and a UI-element icon row (Search, Hunt, Protect, Analytics, Alerts, Settings, Secure, Monitoring, Warning, Critical, Processing).

The original logo sheet is preserved at `uploads/logo-sheet.png`; cropped individual marks live in `assets/`.

> **No codebase or Figma file** was provided. The UI kit in `ui_kits/web/` is therefore an **inferred recreation** based on the brief's stated principles (dark SOC dashboard, card layouts, severity badges, dense tables, line-chart + timeline + lateral-movement-graph emphasis). Treat it as a starting point and flag anything that diverges from the production product.

---

## Brand positioning (verbatim from brief)

- **Personality:** intelligent, precise, defensive, analytical, trustworthy, proactive.
- **Core promise:** surface APT activity, accelerate analyst investigations, support early detection.
- **Design tone:** premium cyber operations center (SOC), intelligence-grade, low-noise interface.
- **Logo meaning:** Hunt (magnifier) · Precision (reticle) · Protection (shield) · Digital telemetry (pixels).

---

## Content fundamentals

The product talks to **threat hunters and SOC analysts**, not consumers. Copy is **clipped, factual, technical, and noun-heavy**. Every word earns its place — analysts under load have no patience for marketing voice or filler.

### Voice and tone

- **Stance:** observational and analytical. The product *surfaces* and *suggests*; the analyst decides. We don't shout "Threat detected!!" — we say "Lateral movement signature matched · confidence 0.94."
- **Perspective:** mostly object-focused (the host, the user account, the DNS query). Second-person ("you") is reserved for explicit user actions ("You triaged 14 hunts this week"). First-person plural ("we") is avoided entirely.
- **Density over warmth:** a tooltip says "RDP from 10.0.4.21 → DC01 · off-hours · new geo", not "We noticed something interesting about your network."
- **Time-stamped where useful:** "Detected 14m ago", "First seen 2026-04-21 03:14:08 UTC". Always 24-hour, always UTC by default with a local-time toggle.

### Casing

- **Sentence case** for UI labels, buttons, menu items, page titles: *"Start hunt"*, *"Mark as benign"*, *"Active detections"*. Title Case is reserved for proper nouns and named entities ("MITRE ATT&CK", "Active Directory", "DNS Exfiltration Model").
- **UPPERCASE with letter-spacing** only for **eyebrows / section labels / table column headers** at micro size (`--fs-micro`, `--tk-micro`).
- **Severity badges** are uppercase: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

### Numbers, IDs, and technical strings

- Numbers are **tabular** (`font-variant-numeric: tabular-nums`) and use the mono stack for IDs, hashes, IPs, IOCs.
- IPs, FQDNs, hashes, user SIDs render in monospace and are click-to-copy.
- Confidence is a 0.00–1.00 decimal, never a percent: `0.94`, not `94%`. (Percents are reserved for trend deltas.)

### Empty / loading / error language

- **Empty:** "No detections in the last 24h." — flat statement, no exclamation, no illustration.
- **Loading:** "Scanning…" / "Replaying telemetry…" with the pulsing-shield reticle.
- **Error:** "Could not reach detector node 03. Retry?" — name the resource, offer one action.

### Emoji & decorative punctuation

- **No emoji.** Anywhere. This is non-negotiable for the product surface.
- No em-dash flourishes in UI copy (they're fine in docs/README).
- The brand uses the **target reticle (⊙ visual)** and **pixel-fragment motif** as the only "decorative" graphic device.

### Example copy (good)

- KPI label: `ACTIVE HUNTS` · value `247` · trend `+12 ↑`
- Detection title: `Credential reuse · svc_backup → 7 hosts in 4m`
- Detection subtitle: `RDP · off-hours · model v2.1 · confidence 0.91`
- Button: `Open in investigation`
- Toast: `Hunt saved. Running against last 7d of telemetry.`

### Example copy (avoid)

- ❌ "Uh oh! Something suspicious happened 👀"
- ❌ "We've found some really interesting activity for you!"
- ❌ "Click here to learn more about our amazing platform"

---

## Visual foundations

### Color

- **Primary Navy `#072147`** — navigation, headings, dark UI scaffolding. The system's *gravity*.
- **Threat Teal `#12B5B0`** — the **only** primary accent. Used for active detections, primary CTAs, graph highlights, focus rings, hover glows, the active sidebar item, and the brand mark. Never used for body text or large fills.
- **Dark Surface `#081B34`** — default operational dashboard background; **never use pure black**. The brief explicitly forbids it ("avoid pure black, soft contrast").
- **Light Surface `#F7FAFC`** — light-mode background. Light mode exists but dark is the default analyst mode.
- **Status palette:** `#2ECC71` success · `#F39C12` warning · `#E74C3C` critical · `#3498DB` info. Each has a low-opacity background variant (`*-bg`) for filled badges and row highlights.
- **Severity ramp** for findings: low (green) → medium (amber) → high (orange) → critical (red).
- **Chart palette** is muted and analyst-friendly: teal, periwinkle, amber, lavender, coral, mint, mustard — see `--chart-1`…`--chart-7`. Distinguishable but not vibrating.

### Type

- **Roboto** (variable, weight + width axes) for everything — display, headings, body, UI. The brand owner shipped `fonts/Roboto-VariableFont_wdth_wght.ttf`; this is the canonical face. The matching family is also loaded from Google Fonts CDN so inlined preview artifacts render without sub-resource fetches.
- **IBM Plex Mono** for IPs, hashes, IDs, KPI metric values, log lines.
- **Semibold (600)** for metric labels and section titles. Bold (700) only for the very top of the hierarchy.
- **Wide letter-spacing on micro/eyebrow labels** (`--tk-micro: 0.06em` uppercase) is the primary "premium SOC" signal.
- **Tabular numerals everywhere a number lives** — KPIs, tables, timestamps. Critical for column alignment.

> ⚠️ **Font note:** The brief's recommended list was Inter / IBM Plex Sans / Manrope, but the brand owner subsequently shipped **Roboto Variable** (`fonts/Roboto-VariableFont_wdth_wght.ttf`) — that is now the canonical face. No brand mono was supplied; IBM Plex Mono from Google Fonts is the substitute. If you have a licensed mono face, drop it into `fonts/` and update the `@font-face` block at the top of `colors_and_type.css`.

### Spacing & rhythm

- **4-px base grid** (`--sp-1` = 4px … `--sp-10` = 72px). Card padding is typically 16 or 20px; section gaps 24–32px.
- **Density bias:** rows are 36–40px (not 48–56px) — analysts need to see 20+ detections per screen.

### Radius

- **6 px** on buttons and inputs (per brief: "rounded 6–8 px").
- **8 px** on cards.
- **12 px** on large panels / modals.
- **999 px (pill)** for severity badges, status chips, filter tokens.

### Backgrounds & imagery

- **No photography.** No stock people. No marketing illustration.
- The **OG / social banner** is the only place a "scene" exists: dark navy with subtle circuit-board pixel pattern and the wordmark.
- **Watermark / pattern:** a faint pixel-fragment pattern derived from the logo's digital-telemetry pixels. Used at very low opacity (5–8%) on login splash and auth screens. **Never on dashboards** — it would compete with data.
- Dashboard backgrounds are **flat dark navy** (`--bg-1`) with cards floating one elevation up (`--bg-2`).
- **Gradients are forbidden as decoration.** The only sanctioned gradient use is **chart area-fills** (teal → transparent under a line, critical → transparent under an anomaly spike).

### Shadows & elevation

- **Dark mode** uses a layered approach: a 1-px **inset top highlight** (`rgba(255,255,255,0.04–0.06)`) plus a soft drop. This gives cards a faintly "lit from above" feel without looking glossy. See `--shadow-1/2/3`.
- **Glow shadows** (`--shadow-glow-teal`, `--shadow-glow-critical`) are reserved for **focus rings, active detection cards, and the critical-alert pulse** — never decorative.
- Light mode uses traditional soft navy-tinted shadows (`--shadow-light-1/2`).

### Borders

- Dashboards use **1 px borders** in `--border-1` (subtle) or `--border-2` (stronger, for outer card edges).
- Borders carry hierarchy in dark mode where shadows are subdued.
- **No double borders** (border + outline). Pick one.
- **Focus ring** is a 2-px outer ring in `--apt-teal` with 2-px offset against the background — see `:focus-visible` in components.

### Cards

- Background `--bg-2`, 1-px `--border-1`, `--shadow-1`, radius `--r-3` (8 px), padding `--sp-5` (20 px).
- **Hover:** background shifts to `--bg-3`, shadow → `--shadow-2`, transition `var(--dur-base) var(--ease-out)`.
- **Selected / drilled-in:** 1-px `--apt-teal` border + faint teal glow.
- **Critical-state card:** thin left-edge `--critical` rule (3-px) + matching glow. No full red fills — analysts get blind to them.

### Hover & press states

- **Hover (buttons / links):** brightness up — teal goes to `--apt-teal-bright`, navy buttons lighten one step.
- **Press:** color darkens (`--apt-teal-dim`) **and** the element shifts down 1 px (`transform: translateY(1px)`) — no scale-shrink (too playful).
- **Icon-only buttons:** background fades in at 8% opacity on hover; 14% on press.
- **Rows in tables:** hover gets a `--bg-3` wash; selected row gets a `--bg-4` wash with a 2-px teal left-edge marker.

### Motion

- **Durations are short.** `--dur-fast` (120 ms) for hovers, `--dur-base` (180 ms) for state changes, `--dur-slow` (320 ms) for panel opens. **Never** longer than 400 ms.
- **Easing:** `--ease-out` for entrances, `--ease-in-out` for back-and-forth state toggles.
- **No bounces. No springs. No rotation flourishes.** The brief is explicit: "Don't clutter dashboards with unnecessary motion."
- The **one sanctioned motion** is the **pulsing shield reticle** used for loading states and the live-detector heartbeat indicator — a 2-step opacity pulse, 1.6 s loop.
- Anomaly spikes in charts may briefly flash on first render but settle to static within 600 ms.

### Transparency & blur

- **Backdrop blur (16–24 px)** is reserved for modals, popovers, and the command palette — over a 70% navy scrim.
- **Never** blur-over-data. The dashboard surface itself is always sharp.
- **Opacity below 60%** is reserved for disabled state and the watermark pattern.

### Layout

- **Persistent left sidebar** (`--sidebar-w: 232px`, collapsed `64px`). Active item gets a teal left-edge bar + teal icon + tinted background.
- **Top bar** (`--topbar-h: 56px`) holds global search (⌘K), tenant switcher, alert bell with count, and the analyst avatar.
- **Content max width:** 1440 px centered, but most dashboard views are full-bleed within the content area.
- **Investigation pane** slides in from the right as an overlay panel (640 px wide) — never a full route change, so the analyst keeps context.

### Iconography motif rules

- All product icons use **2-px stroke, rounded line-caps, no fills** (matches the magnifier outline in the logo). The pixel-fragment ornament from the logo is **never** repurposed as a generic icon — it's part of the brand mark only.
- Status icons (the 5 colored badge icons in the brand sheet — Secure, Monitoring, Warning, Critical, Processing) use **filled-shape** treatment, color-coded.

---

## Iconography

The brand sheet ships a small set of bespoke product icons in the bottom row:

> **Outline (UI / button icons):** Search · Hunt · Protect · Analytics · Alerts · Settings
> **Filled (status icons, color-coded):** Secure (green check-shield) · Monitoring (target reticle) · Warning (amber triangle) · Critical (red octagon) · Processing (gear/circle)

These are preserved as a single strip at `assets/ui-icons-row.png` — useful as a reference but **not usable as individual icons** in code (no SVG was provided).

**Implementation choice:** the UI kit uses **[Lucide](https://lucide.dev) via CDN** as the working icon set. Lucide matches the brief's required aesthetic almost exactly — **2-px stroke, rounded line-caps, outline-style, no fills** — and is the closest open-source match to the bespoke icons shown in the brand sheet. Mappings used:

| Brand icon  | Lucide equivalent     | Where it's used                      |
|-------------|-----------------------|--------------------------------------|
| Search      | `search`              | Top-bar search, command palette      |
| Hunt        | `crosshair` / `target`| "Hunts" nav, hunt-start CTA          |
| Protect     | `shield`              | Policy, coverage, protection views   |
| Analytics   | `bar-chart-3`         | Analytics nav, charts                |
| Alerts      | `bell`                | Notifications, alert center          |
| Settings    | `settings`            | Settings nav, panel cog              |
| Secure      | `shield-check` (filled)| Healthy host / cleared finding      |
| Monitoring  | `radar`               | Live detector heartbeat              |
| Warning     | `triangle-alert`      | Medium severity                      |
| Critical    | `octagon-alert`       | Critical severity                    |
| Processing  | `loader-circle`       | In-flight tasks (animate-spin)       |

> ⚠️ **Substitution flag:** Lucide is a stand-in. If the brand owns dedicated SVGs for the 11 bespoke icons shown in the brand sheet, drop them into `assets/icons/` and swap the `<i data-lucide>` calls.

- **No emoji** anywhere in product UI (see Content Fundamentals).
- **No icon fonts** other than Lucide's optional one — we render Lucide via `<svg>` for crisp scaling.
- The **logo mark** (magnifier + reticle + shield) is **never** broken apart for icon use. The reticle alone is not an icon. The shield alone is not an icon. They only appear together as the brand mark.

---

## Index — what's in this folder

```
.
├── README.md                ← you are here
├── SKILL.md                 ← agent skill manifest (Claude Code compatible)
├── colors_and_type.css      ← all design tokens as CSS custom properties
├── assets/                  ← logos, icons, watermark, OG banner (all cropped from brand sheet)
│   ├── logo-primary-horizontal.png
│   ├── logo-horizontal.png
│   ├── logo-stacked.png
│   ├── icon-square.png · icon-circle.png · icon-filled.png · icon-outline.png
│   ├── icon-sidebar.png · icon-sidebar-active.png
│   ├── icon-light.png · icon-dark.png
│   ├── social-og-banner.png · social-profile-set.png
│   ├── watermark-pattern.png
│   ├── ui-icons-row.png     ← reference strip of the 11 bespoke product icons
│   └── logo-sheet-full.png  ← full original brand sheet
├── preview/                 ← cards for the Design System tab
│   └── *.html
├── ui_kits/
│   └── web/                 ← APT THP analyst dashboard (dark, default)
│       ├── README.md
│       ├── index.html       ← interactive click-thru
│       └── *.jsx            ← components
└── uploads/                 ← original source materials (preserved)
```

> **Note on the UI kit:** `ui_kits/web/index.html` is a **bundled** runtime artifact — all JSX modules and the stylesheet are inlined into a single file (the preview sandbox can't auth sub-resource requests). The modular `*.jsx` and `styles.css` files are the source-of-truth — re-bundle them into `index.html` after edits.

---

## Open questions / asks back to brand owner

1. **Production codebase or Figma?** No source was provided. The UI kit was inferred from the brief; please share a repo or Figma URL so we can pixel-match the real product.
2. **Font licensing?** Roboto Variable is shipped at `fonts/`. Confirm a licensed brand mono face (or accept IBM Plex Mono as the substitute).
3. **Bespoke icon SVGs?** The brand sheet shows 11 custom icons; only the rasterized strip was shipped. SVG sources would let us drop the Lucide substitution.
4. **Light theme priority?** Brief mentions light theme exists. Confirm whether it's a first-class mode or an export-only / printable view.
