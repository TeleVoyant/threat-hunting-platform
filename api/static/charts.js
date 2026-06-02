// charts.js — Chart.js wrappers that read tokens from CSS vars and
// re-skin on theme change.
(function () {
  function token(name) {
    return getComputedStyle(document.documentElement)
      .getPropertyValue(name).trim();
  }

  function palette() {
    return {
      grid:   token('--border-1'),
      text:   token('--fg-2'),
      muted:  token('--fg-3'),
      bg:     token('--bg-2'),
      teal:   token('--apt-teal'),
      chart: [
        token('--chart-1'), token('--chart-2'), token('--chart-3'),
        token('--chart-4'), token('--chart-5'), token('--chart-6'),
        token('--chart-7'),
      ],
      severity: {
        critical: token('--sev-critical'),
        high:     token('--sev-high'),
        medium:   token('--sev-medium'),
        low:      token('--sev-low'),
      },
    };
  }

  function applyTheme(chart) {
    const p = palette();
    if (chart.options.scales) {
      Object.values(chart.options.scales).forEach(scale => {
        if (scale.grid)   scale.grid.color = p.grid;
        if (scale.ticks)  scale.ticks.color = p.text;
        if (scale.title)  scale.title.color = p.text;
      });
    }
    if (chart.options.plugins && chart.options.plugins.legend) {
      chart.options.plugins.legend.labels = chart.options.plugins.legend.labels || {};
      chart.options.plugins.legend.labels.color = p.text;
    }
    chart.update('none');
  }

  function commonOptions() {
    const p = palette();
    return {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: p.text, font: { family: 'inherit', size: 11 } },
        },
        tooltip: {
          backgroundColor: p.bg,
          borderColor: token('--border-2'),
          borderWidth: 1,
          titleColor: token('--fg-1'),
          bodyColor: p.text,
          padding: 10,
          cornerRadius: 6,
        },
      },
      scales: {
        x: {
          grid: { color: p.grid, drawBorder: false },
          ticks: { color: p.text, font: { family: 'inherit', size: 11 } },
        },
        y: {
          grid: { color: p.grid, drawBorder: false },
          ticks: { color: p.text, font: { family: 'inherit', size: 11 } },
          beginAtZero: true,
        },
      },
    };
  }

  function severityStackedBar(canvas, buckets) {
    const p = palette();
    const labels = buckets.map(b => b.ts);
    const ds = [
      { label: 'Critical', backgroundColor: p.severity.critical, data: buckets.map(b => b.critical || 0) },
      { label: 'High',     backgroundColor: p.severity.high,     data: buckets.map(b => b.high     || 0) },
      { label: 'Medium',   backgroundColor: p.severity.medium,   data: buckets.map(b => b.medium   || 0) },
      { label: 'Low',      backgroundColor: p.severity.low,      data: buckets.map(b => b.low      || 0) },
    ];
    const opts = commonOptions();
    opts.scales.x.stacked = true;
    opts.scales.y.stacked = true;
    return new Chart(canvas, {
      type: 'bar',
      data: { labels, datasets: ds },
      options: opts,
    });
  }

  function severityDonut(canvas, stats) {
    const p = palette();
    return new Chart(canvas, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
          data: [stats.critical || 0, stats.high || 0, stats.medium || 0, stats.low || 0],
          backgroundColor: [p.severity.critical, p.severity.high, p.severity.medium, p.severity.low],
          borderColor: token('--bg-2'),
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '64%',
        plugins: {
          legend: { position: 'right', labels: { color: p.text, font: { size: 11 } } },
          tooltip: commonOptions().plugins.tooltip,
        },
      },
    });
  }

  function lineChart(canvas, points, opts = {}) {
    const p = palette();
    const labels = points.map(pt => pt.ts);
    const series = (opts.series || [{ key: 'value', label: 'Value' }]).map((s, i) => ({
      label: s.label,
      data: points.map(pt => pt[s.key] || 0),
      borderColor: s.color || p.chart[i % p.chart.length],
      backgroundColor: (s.color || p.chart[i % p.chart.length]) + '33',
      fill: !!opts.fill,
      tension: 0.25,
      borderWidth: 2,
      pointRadius: 0,
      pointHoverRadius: 4,
    }));
    return new Chart(canvas, {
      type: 'line',
      data: { labels, datasets: series },
      options: commonOptions(),
    });
  }

  function horizontalBar(canvas, items, opts = {}) {
    const p = palette();
    const labels = items.map(it => it.label);
    const data = items.map(it => it.value);
    return new Chart(canvas, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: opts.label || '',
          data,
          backgroundColor: opts.color || p.teal,
          borderRadius: 4,
          borderSkipped: false,
        }],
      },
      options: {
        ...commonOptions(),
        indexAxis: 'y',
        plugins: { ...commonOptions().plugins, legend: { display: false } },
      },
    });
  }

  // ── Curve chart (ROC, PR, calibration) ──────────────────────────────────
  // points: [{x, y}, ...]   opts: { xLabel, yLabel, seriesLabel, color,
  //   fill: bool, referenceDiagonal: bool, areaLabel }
  function curveChart(canvas, points, opts = {}) {
    const p = palette();
    const color = opts.color || p.teal;
    const datasets = [{
      label: opts.seriesLabel || 'curve',
      data: points.map(pt => ({ x: pt.x, y: pt.y })),
      borderColor: color,
      backgroundColor: color + '33',
      fill: !!opts.fill,
      tension: 0.0,           // straight segments — curves are step-wise samples
      borderWidth: 2,
      pointRadius: 0,
      pointHoverRadius: 4,
    }];
    if (opts.referenceDiagonal) {
      datasets.push({
        label: 'no-skill / perfect calibration',
        data: [{ x: 0, y: 0 }, { x: 1, y: 1 }],
        borderColor: p.muted,
        borderDash: [4, 4],
        borderWidth: 1,
        pointRadius: 0,
        fill: false,
      });
    }
    const opts2 = commonOptions();
    // Curves use linear X (0..1), not categorical labels.
    opts2.scales.x = {
      type: 'linear', min: 0, max: 1,
      grid: { color: p.grid, drawBorder: false },
      ticks: { color: p.text, font: { family: 'inherit', size: 11 } },
      title: { display: !!opts.xLabel, text: opts.xLabel || '', color: p.text },
    };
    opts2.scales.y = {
      type: 'linear', min: 0, max: 1,
      grid: { color: p.grid, drawBorder: false },
      ticks: { color: p.text, font: { family: 'inherit', size: 11 } },
      title: { display: !!opts.yLabel, text: opts.yLabel || '', color: p.text },
    };
    return new Chart(canvas, {
      type: 'line',
      data: { datasets },
      options: opts2,
    });
  }

  // ── Score distribution histogram ────────────────────────────────────────
  // dist: { bin_midpoints: [...], positive_counts: [...], negative_counts: [...] }
  // Renders two overlaid bar series — positive (red) + negative (teal) — so
  // class separability is visible at a glance. Strong models show two tight
  // peaks at 0 and 1 with little overlap; weak models show overlapping blobs.
  function scoreHistogram(canvas, dist) {
    const p = palette();
    const labels = (dist.bin_midpoints || []).map(v => v.toFixed(2));
    const opts = commonOptions();
    opts.scales.x.title = { display: true, text: 'Model confidence', color: p.text };
    opts.scales.y.title = { display: true, text: 'Window count',     color: p.text };
    return new Chart(canvas, {
      type: 'bar',
      data: {
        labels,
        datasets: [
          {
            label: 'Negative (benign)',
            data: dist.negative_counts || [],
            backgroundColor: p.severity.low + 'cc',
            borderColor: p.severity.low,
            borderWidth: 1,
          },
          {
            label: 'Positive (attack)',
            data: dist.positive_counts || [],
            backgroundColor: p.severity.critical + 'cc',
            borderColor: p.severity.critical,
            borderWidth: 1,
          },
        ],
      },
      options: opts,
    });
  }

  // ── Sparkline (history trend tile) ──────────────────────────────────────
  // values: number[]  opts: { color, fill: bool }
  // Minimal: no axes, no legend, no points. Used in the History tab's
  // metric-trend column.
  function sparkline(canvas, values, opts = {}) {
    const p = palette();
    const color = opts.color || p.teal;
    return new Chart(canvas, {
      type: 'line',
      data: {
        labels: values.map((_, i) => i),
        datasets: [{
          data: values,
          borderColor: color,
          backgroundColor: color + '33',
          fill: opts.fill !== false,
          tension: 0.3,
          borderWidth: 1.5,
          pointRadius: 0,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        scales: { x: { display: false }, y: { display: false, beginAtZero: false } },
      },
    });
  }

  // Theme re-skin
  window.addEventListener('themechange', () => {
    if (!window._aptCharts) return;
    window._aptCharts.forEach(applyTheme);
  });
  new MutationObserver(() => {
    window.dispatchEvent(new Event('themechange'));
  }).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

  function register(chart) {
    window._aptCharts = window._aptCharts || [];
    window._aptCharts.push(chart);
    _attachResizeWatcher(chart);
    return chart;
  }

  // Bulletproof resize: don't trust Chart.js's internal responsive observer
  // (which silently latches onto whatever it sees at init time). Attach our
  // own ResizeObserver to the canvas's parent; every time the parent's box
  // changes, call chart.resize(). Survives grid-layout settle, sidebar
  // collapse animation, window resize, and DPR changes.
  function _attachResizeWatcher(chart) {
    const canvas = chart.canvas;
    if (!canvas || !canvas.parentElement) return;
    const parent = canvas.parentElement;
    let lastW = 0, lastH = 0;
    const tick = () => {
      const w = parent.clientWidth, h = parent.clientHeight;
      if (w === lastW && h === lastH) return;
      lastW = w; lastH = h;
      if (w > 0 && h > 0) {
        try { chart.resize(); } catch (_) {}
      }
    };
    // Kick once immediately so the chart picks up the actual size right after
    // layout flushes (defends against the 0×0 init trap).
    requestAnimationFrame(tick);
    const ro = new ResizeObserver(tick);
    ro.observe(parent);
    // Tear down with the chart so we don't leak observers on detector switch.
    const origDestroy = chart.destroy.bind(chart);
    chart.destroy = function () {
      try { ro.disconnect(); } catch (_) {}
      return origDestroy();
    };
  }

  window.AptCharts = {
    severityStackedBar: (canvas, buckets) => register(severityStackedBar(canvas, buckets)),
    severityDonut:      (canvas, stats)   => register(severityDonut(canvas, stats)),
    lineChart:          (canvas, points, opts) => register(lineChart(canvas, points, opts)),
    horizontalBar:      (canvas, items, opts)  => register(horizontalBar(canvas, items, opts)),
    curveChart:         (canvas, points, opts) => register(curveChart(canvas, points, opts)),
    scoreHistogram:     (canvas, dist)         => register(scoreHistogram(canvas, dist)),
    sparkline:          (canvas, values, opts) => register(sparkline(canvas, values, opts)),
    palette,
    token,
  };
})();
