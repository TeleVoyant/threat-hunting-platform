# visualization/explanation_widget.py
"""
Self-contained HTML widget for alert explainability.

Two visual sections:

  1. Per-alert SHAP bars  — horizontal bar chart of the top-K features that
     drove THIS specific detection. Red bars = feature pushed toward attack
     (positive SHAP); blue bars = pushed away (negative). Bar length is
     proportional to |contribution|.

  2. Global feature importance — gray bars ranking the features the model
     uses most across ALL predictions (XGBoost gain). Provides context for
     interpreting the SHAP bars: "is this feature usually important?"

No JS dependency — pure HTML + inline CSS. Embeddable as iframe in a
React dashboard, viewable standalone, screenshot-friendly for Chapter 7.
"""

from html import escape
from typing import Optional


def _bar_html(label: str, value: float, max_abs: float, *, color_pos: str,
              color_neg: str, show_sign: bool = True) -> str:
    """Render one horizontal bar. Negative values render to the LEFT of zero."""
    pct = (abs(value) / max_abs * 50) if max_abs > 0 else 0  # max 50% of width
    # Sign-aware rendering: positive → right of midline, negative → left
    is_neg = value < 0
    color = color_neg if is_neg else color_pos
    # Pre-format the contribution label
    sign = "+" if value > 0 and show_sign else ("-" if value < 0 else "")
    fmt_val = f"{sign}{abs(value):.4f}" if show_sign else f"{value:.4f}"

    if is_neg:
        bar_style = (
            f"position:absolute;right:50%;width:{pct}%;height:18px;"
            f"background:{color};"
        )
    else:
        bar_style = (
            f"position:absolute;left:50%;width:{pct}%;height:18px;"
            f"background:{color};"
        )

    return f"""
    <div style="display:grid;grid-template-columns:340px 1fr 80px;
                gap:8px;align-items:center;padding:3px 0;">
      <div style="font-family:monospace;font-size:12px;color:#cbd5e1;
                  text-align:right;overflow:hidden;text-overflow:ellipsis;
                  white-space:nowrap;">{escape(label)}</div>
      <div style="position:relative;height:20px;background:#1f2937;
                  border-radius:3px;">
        <div style="position:absolute;left:50%;width:1px;height:100%;
                    background:#475569;"></div>
        <div style="{bar_style}"></div>
      </div>
      <div style="font-family:monospace;font-size:12px;color:{color};
                  text-align:left;">{fmt_val}</div>
    </div>"""


def _gray_bar_html(label: str, share: float, raw_score: float) -> str:
    """Single-direction gray bar for global importance (always positive)."""
    pct = share * 100
    return f"""
    <div style="display:grid;grid-template-columns:340px 1fr 100px;
                gap:8px;align-items:center;padding:3px 0;">
      <div style="font-family:monospace;font-size:12px;color:#cbd5e1;
                  text-align:right;overflow:hidden;text-overflow:ellipsis;
                  white-space:nowrap;">{escape(label)}</div>
      <div style="position:relative;height:20px;background:#1f2937;
                  border-radius:3px;">
        <div style="height:100%;width:{pct:.2f}%;background:#64748b;
                    border-radius:3px;"></div>
      </div>
      <div style="font-family:monospace;font-size:12px;color:#94a3b8;
                  text-align:left;">{share:.1%}</div>
    </div>"""


def render_explanation(
    *,
    alert_id: str,
    detector_name: str,
    confidence: float,
    severity: str,
    timestamp: str,
    source_entity: str,
    contributing_features: dict[str, float],
    global_importance: list[dict],
    mitre_techniques: Optional[list[str]] = None,
) -> str:
    """
    Build the standalone HTML page for one alert's explanation.

    contributing_features: signed SHAP from Detection.contributing_features.
    global_importance: list of {feature, score, normalized_share} from the
                      /models/{name}/importance endpoint (already top-K).
    """
    mitre_techniques = mitre_techniques or []

    # Per-alert SHAP bars
    if contributing_features:
        max_shap = max(abs(v) for v in contributing_features.values()) or 1.0
        # Sort by |contribution| descending so the strongest feature is on top
        sorted_shap = sorted(
            contributing_features.items(),
            key=lambda kv: abs(kv[1]),
            reverse=True,
        )
        shap_bars = "".join(
            _bar_html(name, val, max_shap,
                       color_pos="#dc2626", color_neg="#2563eb")
            for name, val in sorted_shap
        )
    else:
        shap_bars = ('<p style="color:#94a3b8;font-style:italic;">'
                      'No SHAP contributions available — model may have been '
                      'trained without feature names.</p>')

    # Global importance bars
    if global_importance:
        gimp_bars = "".join(
            _gray_bar_html(item["feature"], item["normalized_share"],
                           item["score"])
            for item in global_importance
        )
    else:
        gimp_bars = ('<p style="color:#94a3b8;font-style:italic;">'
                      'No global importance available.</p>')

    # Header tags
    severity_color = {
        "critical": "#dc2626",
        "high":     "#ea580c",
        "medium":   "#d97706",
        "low":      "#65a30d",
    }.get(severity.lower(), "#6b7280")

    mitre_chips = "".join(
        f'<span style="background:#334155;padding:2px 8px;border-radius:10px;'
        f'font-size:11px;font-family:monospace;color:#cbd5e1;'
        f'margin-right:4px;">{escape(t)}</span>'
        for t in mitre_techniques
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Alert Explanation — {escape(alert_id)}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',
                          Roboto, sans-serif;
             background: #0f172a; color: #e2e8f0; margin: 0; padding: 20px;
             font-size: 14px; }}
    h1 {{ font-size: 20px; margin: 0 0 4px 0; color: #f1f5f9; }}
    h2 {{ font-size: 14px; margin: 24px 0 8px 0; color: #94a3b8;
           text-transform: uppercase; letter-spacing: 0.5px;
           border-bottom: 1px solid #334155; padding-bottom: 4px; }}
    .meta {{ color: #94a3b8; font-size: 12px; margin-bottom: 16px; }}
    .meta strong {{ color: #cbd5e1; }}
    .severity-pill {{ display: inline-block; padding: 2px 10px;
                       border-radius: 10px; font-size: 11px;
                       font-weight: 600; text-transform: uppercase;
                       background: {severity_color}; color: white;
                       margin-right: 8px; }}
    .legend {{ font-size: 11px; color: #94a3b8;
                margin-bottom: 8px; display: flex; gap: 16px; }}
    .legend span {{ display: inline-block; width: 12px; height: 12px;
                     border-radius: 2px; margin-right: 4px;
                     vertical-align: middle; }}
    .panel {{ background: #1e293b; padding: 16px; border-radius: 6px;
               margin-bottom: 12px; }}
  </style>
</head>
<body>

  <h1>Alert Explanation</h1>
  <div class="meta">
    <span class="severity-pill">{escape(severity)}</span>
    <strong>{escape(detector_name)}</strong> &middot;
    confidence <strong>{confidence:.1%}</strong> &middot;
    {escape(timestamp)}
    <br>
    Source entity: <strong>{escape(source_entity)}</strong>
    <br>
    {mitre_chips}
  </div>

  <h2>Why did THIS alert fire? (per-detection SHAP)</h2>
  <div class="panel">
    <div class="legend">
      <div><span style="background:#dc2626;"></span>pushed TOWARD attack</div>
      <div><span style="background:#2563eb;"></span>pushed AWAY from attack</div>
    </div>
    {shap_bars}
  </div>

  <h2>Which features does the model rely on overall? (gain)</h2>
  <div class="panel">
    <div class="legend">
      <div>Higher bar = the model splits on this feature more often
            (averaged loss reduction).</div>
    </div>
    {gimp_bars}
  </div>

  <p style="color:#475569;font-size:11px;margin-top:24px;">
    APT Threat Hunting Platform — explainability widget for alert
    {escape(alert_id)}.
  </p>
</body>
</html>"""
