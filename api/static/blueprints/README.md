# APT THP — Web UI Kit

Interactive recreation of the APT Threat Hunting Platform analyst dashboard, built from the brand brief. Dark-mode by default (the operational mode for analysts).

> ⚠️ **No codebase or Figma was provided** for the production product. This kit is an **inferred recreation** based on the brand brief's stated principles: dark SOC dashboard, card layouts, severity badges, dense analyst tables, line charts + anomaly spikes + timelines + lateral-movement graphs, and the magnifying-glass + shield + reticle motif. Treat as a starting point and flag anything that diverges from production.

## What's here

- `index.html` — interactive click-thru. Opens to the **Operations dashboard**. Sidebar swaps between Dashboard / Hunts / Lateral graph / DNS exfil. Clicking a detection opens the **Investigation panel** (right slide-in). The "Start hunt" button opens the **Hunt composer** modal. ⌘K / Ctrl+K opens the command palette.
- `App.jsx` — top-level layout + view router.
- `Sidebar.jsx` — left nav with active state, counts, alert badge.
- `Topbar.jsx` — global search, tenant switcher, alert bell, avatar.
- `KpiCard.jsx` — dashboard metric tile with trend delta.
- `SeverityBadge.jsx` · `StatusPill.jsx` — pill primitives.
- `DetectionTable.jsx` — dense analyst table, click-to-investigate.
- `DetectionCard.jsx` — surfaced finding card with confidence + tags.
- `MiniChart.jsx` — sparkline + area-fill line chart with anomaly spike.
- `LateralGraph.jsx` — host-to-host force-style lateral-movement graph (SVG).
- `InvestigationPanel.jsx` — right slide-in with timeline, IOC list, model card.
- `HuntComposer.jsx` — modal for composing a saved hunt query.
- `CommandPalette.jsx` — ⌘K palette.

## How to extend

All components consume tokens from `../../colors_and_type.css`. Add new screens as additional `<View>` cases in `App.jsx`.
