// WinPerf report dashboard. Talks only to this server's /api endpoints. Everything that came from
// the database (process names, explanations) is put on the page with textContent, never as HTML.
(() => {
  'use strict';

  const params = new URLSearchParams(location.search);
  const token = params.get('token');
  const headers = token ? { Authorization: 'Bearer ' + token } : {};
  const $ = (id) => document.getElementById(id);

  const MIN = 60e3;
  const HOUR = 60 * MIN;
  const RANGES = { '15m': 15 * MIN, '1h': HOUR, '6h': 6 * HOUR, '24h': 24 * HOUR, '7d': 168 * HOUR };
  const MAX_RANGE = 400 * 24 * HOUR;
  const POLL_MS = 10000;

  let rangeKey = '1h';
  try {
    const saved = localStorage.getItem('winperf.range');
    if (saved && (saved in RANGES || saved === 'custom')) rangeKey = saved;
  } catch (_) { /* storage may be blocked; the default is fine */ }
  let custom = null; // { from, to } in ms while the custom range is shown
  let groupKey = 'process';
  try {
    const saved = localStorage.getItem('winperf.group');
    if (saved === 'process' || saved === 'application') groupKey = saved;
  } catch (_) { /* optional */ }
  let intervalSecs = 5;
  if (rangeKey === 'custom') rangeKey = '1h';

  // ---- formatting ----------------------------------------------------------------------------

  const num = (v) => typeof v === 'number' && Number.isFinite(v);
  const pct = (v) => (num(v) ? v.toFixed(v < 10 ? 1 : 0) + ' %' : '–');
  function bytes(v) {
    if (!num(v)) return '–';
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    let i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return v.toFixed(v < 10 && i > 0 ? 1 : 0) + ' ' + units[i];
  }
  const rate = (v) => (num(v) ? bytes(v) + '/s' : '–');
  const when = (ms) => new Date(ms).toLocaleString();
  function ago(ms) {
    const s = Math.max(0, Math.round(ms / 1000));
    if (s < 90) return s + ' s';
    if (s < 5400) return Math.round(s / 60) + ' min';
    if (s < 172800) return Math.round(s / 3600) + ' h';
    return Math.round(s / 86400) + ' d';
  }

  // ---- DOM helpers ---------------------------------------------------------------------------

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  const SEVERITY = {
    informational: 'bg-slate-200 text-slate-700',
    warning: 'bg-amber-200 text-amber-900',
    high: 'bg-orange-300 text-orange-950',
    critical: 'bg-red-600 text-white',
  };

  // ---- API -----------------------------------------------------------------------------------

  async function api(path) {
    const response = await fetch(path, { headers, cache: 'no-store' });
    let body = null;
    try { body = await response.json(); } catch (_) { /* not JSON */ }
    if (!response.ok) throw new Error((body && body.error) || 'HTTP ' + response.status);
    return body;
  }

  // ---- charts --------------------------------------------------------------------------------

  const charts = {};
  function chart(id) {
    if (!charts[id]) charts[id] = echarts.init($(id));
    return charts[id];
  }
  window.addEventListener('resize', () => Object.values(charts).forEach((c) => c.resize()));

  // One [time, value] pair per point; a null where recording was interrupted so the line breaks.
  function seriesOf(points, key, bucket) {
    const out = [];
    let prev = null;
    for (const p of points) {
      if (prev !== null && p.ts_ms - prev > bucket * 2.5) out.push([prev + bucket, null]);
      out.push([p.ts_ms, num(p[key]) ? p[key] : null]);
      prev = p.ts_ms;
    }
    return out;
  }

  function draw(id, from, to, lines, format, max) {
    chart(id).setOption({
      animation: false,
      grid: { left: 8, right: 16, top: lines.length > 1 ? 28 : 12, bottom: 4, containLabel: true },
      legend: lines.length > 1 ? { top: 0 } : undefined,
      tooltip: { trigger: 'axis', valueFormatter: format },
      xAxis: { type: 'time', min: from, max: to, axisLabel: { hideOverlap: true } },
      yAxis: { type: 'value', min: 0, max, axisLabel: { formatter: format } },
      series: lines.map((l) => ({
        name: l.name,
        type: 'line',
        showSymbol: false,
        connectNulls: false,
        lineStyle: { width: 1.5 },
        areaStyle: { opacity: 0.12 },
        data: l.data,
      })),
    }, true);
  }

  function drawCharts(system, from, to) {
    const pts = system.points;
    const b = system.bucket_ms;
    draw('chart-cpu', from, to, [{ name: 'CPU', data: seriesOf(pts, 'cpu_percent', b) }], (v) => pct(v), 100);
    draw('chart-mem', from, to, [{ name: 'Memory', data: seriesOf(pts, 'memory_used_percent', b) }], (v) => pct(v), 100);
    draw('chart-disk', from, to, [
      { name: 'Read', data: seriesOf(pts, 'disk_read_bytes_per_sec', b) },
      { name: 'Write', data: seriesOf(pts, 'disk_write_bytes_per_sec', b) },
    ], rate);
    draw('chart-net', from, to, [
      { name: 'Received', data: seriesOf(pts, 'net_rx_bytes_per_sec', b) },
      { name: 'Sent', data: seriesOf(pts, 'net_tx_bytes_per_sec', b) },
    ], rate);
  }

  // ---- panels --------------------------------------------------------------------------------

  function showNotice(text) {
    const n = $('notice');
    n.textContent = text || '';
    n.classList.toggle('hidden', !text);
  }

  function showStatus(s) {
    const pill = $('recording');
    const age = s.latest_sample_ms ? ago(s.now_ms - s.latest_sample_ms) + ' ago' : 'no samples yet';
    pill.textContent = (s.recording ? 'Recording' : 'Not recording') + ' · last sample ' + age;
    pill.className = 'rounded-full px-3 py-1 text-xs font-medium ' +
      (s.recording ? 'bg-emerald-600 text-white' : 'bg-red-600 text-white');
    if (s.interval_secs) intervalSecs = s.interval_secs;
    $('now-anomalies').textContent = String(s.active_anomalies);
    $('anomaly-card').className = 'rounded-lg p-4 shadow ' + (s.active_anomalies > 0 ? 'bg-amber-100' : 'bg-white');
  }

  function showNow(current) {
    const sys = current.system;
    $('now-cpu').textContent = sys ? pct(sys.cpu_percent) : '–';
    $('now-mem').textContent = sys ? pct(sys.memory_used_percent) : '–';
    $('now-disk').textContent = sys ? pct(sys.disk_busy_percent) : '–';
    $('now-net').textContent = sys && (num(sys.net_rx_bytes_per_sec) || num(sys.net_tx_bytes_per_sec))
      ? '↓ ' + rate(sys.net_rx_bytes_per_sec) + '  ↑ ' + rate(sys.net_tx_bytes_per_sec)
      : '–';
    const body = $('top');
    body.replaceChildren();
    for (const p of current.processes) {
      const row = el('tr', 'border-t border-slate-100');
      const name = el('td', 'py-1 pr-3', p.name);
      name.title = (p.application ? p.application + ' · ' : '') + 'PID ' + p.pid;
      row.append(
        name,
        el('td', 'py-1 pr-3 text-right tabular-nums', pct(p.cpu_percent)),
        el('td', 'py-1 pr-3 text-right tabular-nums', bytes(p.working_set_bytes)),
        el('td', 'py-1 text-right tabular-nums',
          rate((p.io_read_bytes_per_sec || 0) + (p.io_write_bytes_per_sec || 0))),
      );
      body.append(row);
    }
    $('top-empty').classList.toggle('hidden', current.processes.length > 0);
  }

  function showAnomalies(list) {
    const ul = $('anomalies');
    ul.replaceChildren();
    for (const a of list.anomalies.slice(0, 20)) {
      const li = el('li', 'rounded border border-slate-200 p-2');
      const head = el('div', 'flex flex-wrap items-center gap-2');
      head.append(
        el('span', 'rounded px-2 py-0.5 text-xs font-semibold uppercase ' +
          (SEVERITY[a.severity] || SEVERITY.informational), a.severity),
        el('span', 'font-medium', a.kind === 'memory_growth' ? 'memory growth' : a.resource),
        el('span', '', a.process.name),
        el('span', 'text-xs text-slate-500',
          (a.state === 'active' ? 'active since ' : 'resolved · ') + when(a.detected_ts_ms)),
      );
      const more = el('details', 'mt-1 text-sm text-slate-700');
      more.append(el('summary', 'cursor-pointer text-slate-500', 'Why was this flagged?'), el('p', 'mt-1', a.explanation));
      li.append(head, more);
      ul.append(li);
    }
    $('anomalies-empty').classList.toggle('hidden', list.anomalies.length > 0);
  }

  // ---- rankings ------------------------------------------------------------------------------

  const METRICS = [
    { key: 'cpu', title: 'CPU', fmt: pct, hint: 'Share of the whole machine\'s CPU' },
    { key: 'memory', title: 'Memory', fmt: bytes, hint: 'Working set; memory shared between processes counts in each' },
    { key: 'disk_read', title: 'Disk read', fmt: rate, hint: 'All I/O the process reads (files, pipes, devices), not only the physical disk' },
    { key: 'disk_write', title: 'Disk write', fmt: rate, hint: 'All I/O the process writes, not only the physical disk' },
    { key: 'net_rx', title: 'Network received', fmt: rate, hint: 'Per-process network traffic (needs the monitor to run as administrator)' },
    { key: 'net_tx', title: 'Network sent', fmt: rate, hint: 'Per-process network traffic (needs the monitor to run as administrator)' },
  ];
  let rankingsRun = 0;
  let rankingsAt = 0;

  function rankingCard(metric, data) {
    const card = el('div', 'rounded-lg bg-white p-4 shadow');
    const title = el('h3', 'mb-2 font-medium', metric.title);
    title.title = metric.hint;
    card.append(title);
    if (!data) {
      card.append(el('p', 'text-sm text-slate-500', 'Could not load.'));
      return card;
    }
    if (!data.available) {
      card.append(el('p', 'text-sm text-slate-500', 'Not measured in this range. ' + (data.note || '')));
      return card;
    }
    if (data.rows.length === 0) {
      card.append(el('p', 'text-sm text-slate-500', 'Nothing recorded in this range.'));
      return card;
    }
    const table = el('table', 'w-full text-left text-sm');
    const head = el('tr', 'text-slate-500');
    head.append(el('th', 'py-1 pr-2', groupKey === 'process' ? 'Process' : 'Application'),
      el('th', 'py-1 pr-2 text-right', 'Now'), el('th', 'py-1 pr-2 text-right', 'Average'), el('th', 'py-1 text-right', 'Peak'));
    const thead = el('thead');
    thead.append(head);
    const tbody = el('tbody');
    for (const r of data.rows) {
      const row = el('tr', 'border-t border-slate-100');
      const name = el('td', 'max-w-40 truncate py-1 pr-2', r.name);
      name.title = r.application && r.application !== r.name ? r.name + ' · ' + r.application : r.name;
      row.append(name,
        el('td', 'py-1 pr-2 text-right tabular-nums', r.current === null ? 'not running' : metric.fmt(r.current)),
        el('td', 'py-1 pr-2 text-right tabular-nums', metric.fmt(r.average)),
        el('td', 'py-1 text-right tabular-nums', metric.fmt(r.peak)));
      tbody.append(row);
    }
    table.append(thead, tbody);
    const wrap = el('div', 'overflow-x-auto');
    wrap.append(table);
    card.append(wrap);
    return card;
  }

  async function loadRankings(from, to) {
    const run = ++rankingsRun;
    rankingsAt = Date.now();
    const base = '/api/rankings?group=' + groupKey + '&limit=8&from_ms=' + Math.floor(from) + '&to_ms=' + Math.ceil(to) + '&metric=';
    const results = await Promise.allSettled(METRICS.map((m) => api(base + m.key)));
    if (run !== rankingsRun) return; // a newer request replaced this one
    const box = $('rankings');
    box.replaceChildren();
    let sampled = 1;
    results.forEach((r, i) => {
      const data = r.status === 'fulfilled' ? r.value : null;
      if (data && data.sampled_every_ticks > sampled) sampled = data.sampled_every_ticks;
      box.append(rankingCard(METRICS[i], data));
    });
    $('rankings-note').textContent =
      'Average is over the whole range, counting the time something was not running as zero, so a short burst ranks below steady work. ' +
      'Processes with several copies running are added together. ' +
      (sampled > 1
        ? 'This range is long, so it is read from about every ' + sampled + 'th sample (roughly every ' +
          ago(sampled * intervalSecs * 1000) + '); peaks are the highest of those moments.'
        : '');
  }

  const GON = 'group rounded px-3 py-1 text-sm bg-slate-800 text-white';
  const GOFF = 'group rounded px-3 py-1 text-sm bg-slate-200 text-slate-700 hover:bg-slate-300';
  function markGroup() {
    document.querySelectorAll('button.group').forEach((b) => {
      b.className = b.dataset.group === groupKey ? GON : GOFF;
      b.setAttribute('aria-pressed', String(b.dataset.group === groupKey));
    });
  }
  $('groups').addEventListener('click', (event) => {
    const key = event.target.dataset && event.target.dataset.group;
    if (!key || key === groupKey) return;
    groupKey = key;
    try { localStorage.setItem('winperf.group', key); } catch (_) { /* optional */ }
    markGroup();
    const { from, to } = window_();
    loadRankings(from, to);
  });

  // ---- loading -------------------------------------------------------------------------------

  function window_() {
    if (custom) return custom;
    const to = Date.now();
    return { from: to - RANGES[rangeKey], to };
  }

  let busy = false;
  async function refresh(force) {
    if (busy) return;
    busy = true;
    const { from, to } = window_();
    if (force || Date.now() - rankingsAt > 30000) loadRankings(from, to);
    try {
      const results = await Promise.allSettled([
        api('/api/status'),
        api('/api/current?limit=10'),
        api('/api/system?from_ms=' + Math.floor(from) + '&to_ms=' + Math.ceil(to) + '&points=600'),
        api('/api/anomalies?hours=24&limit=50'),
      ]);
      const [status, current, system, anomalies] = results;
      const failed = results.find((r) => r.status === 'rejected');
      showNotice(failed ? failed.reason.message : '');
      if (status.status === 'fulfilled') showStatus(status.value);
      if (current.status === 'fulfilled') showNow(current.value);
      if (system.status === 'fulfilled') drawCharts(system.value, from, to);
      if (anomalies.status === 'fulfilled') showAnomalies(anomalies.value);
      $('updated').textContent = 'Updated ' + new Date().toLocaleTimeString();
    } finally {
      busy = false;
    }
  }

  // ---- range selector ------------------------------------------------------------------------

  const ON = 'range rounded px-3 py-1 text-sm bg-sky-500 text-white';
  const OFF = 'range rounded px-3 py-1 text-sm bg-slate-700 text-slate-200 hover:bg-slate-600';
  function markRange() {
    const shown = custom ? 'custom' : rangeKey;
    document.querySelectorAll('button.range').forEach((b) => {
      b.className = b.dataset.range === shown ? ON : OFF;
      b.setAttribute('aria-pressed', String(b.dataset.range === shown));
    });
    $('custom').classList.toggle('hidden', shown !== 'custom');
    $('custom').classList.toggle('flex', shown === 'custom');
  }

  function localInput(ms) {
    const d = new Date(ms - new Date(ms).getTimezoneOffset() * MIN);
    return d.toISOString().slice(0, 16);
  }

  $('ranges').addEventListener('click', (event) => {
    const key = event.target.dataset && event.target.dataset.range;
    if (!key) return;
    if (key === 'custom') {
      const to = Date.now();
      $('from').value = localInput(custom ? custom.from : to - 24 * HOUR);
      $('to').value = localInput(custom ? custom.to : to);
      custom = custom || { from: to - 24 * HOUR, to };
    } else {
      custom = null;
      rangeKey = key;
      try { localStorage.setItem('winperf.range', key); } catch (_) { /* optional */ }
    }
    markRange();
    refresh(true);
  });

  $('custom').addEventListener('submit', (event) => {
    event.preventDefault();
    const from = Date.parse($('from').value);
    const to = Date.parse($('to').value);
    const error = $('custom-error');
    if (!Number.isFinite(from) || !Number.isFinite(to)) { error.textContent = 'Choose both times.'; return; }
    if (from >= to) { error.textContent = 'The start must be before the end.'; return; }
    if (to - from > MAX_RANGE) { error.textContent = 'At most 400 days.'; return; }
    error.textContent = '';
    custom = { from, to };
    markRange();
    refresh(true);
  });

  // ---- polling -------------------------------------------------------------------------------

  setInterval(() => { if (!document.hidden && !custom) refresh(); }, POLL_MS);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });

  markRange();
  markGroup();
  refresh(true);
})();
