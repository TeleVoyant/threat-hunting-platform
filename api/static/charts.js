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
    return chart;
  }

  window.AptCharts = {
    severityStackedBar: (canvas, buckets) => register(severityStackedBar(canvas, buckets)),
    severityDonut:      (canvas, stats)   => register(severityDonut(canvas, stats)),
    lineChart:          (canvas, points, opts) => register(lineChart(canvas, points, opts)),
    horizontalBar:      (canvas, items, opts)  => register(horizontalBar(canvas, items, opts)),
    palette,
    token,
  };
})();
