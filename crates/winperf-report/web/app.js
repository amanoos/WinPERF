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

  // A line may carry `band`: the stored baseline row { median, p95 } of the same metric. It is
  // drawn as two dashed lines with the stretch between them shaded; the numbers are the stored
  // ones, unchanged.
  // `band.p95` may be left out for a single reference level (an event's baseline). `span` is
  // [from, to] in ms: the stretch of time to shade (when an event was active).
  function bandMarks(band, format, labelled, span) {
    // The two labels sit on opposite sides of their lines, so they stay readable when the typical
    // level and the 95th percentile are close together.
    const label = (position) => labelled
      ? { show: true, position, fontSize: 11, formatter: (p) => p.name + ' ' + format(p.value) }
      : { show: false };
    const out = {};
    const areas = [];
    if (band) {
      const two = band.p95 !== undefined;
      const lines = [{ name: two ? 'typical' : 'baseline', yAxis: band.median, label: label('insideEndBottom') }];
      if (two) {
        lines.push({ name: 'p95', yAxis: band.p95, label: label('insideEndTop') });
        areas.push([{ yAxis: band.median }, { yAxis: band.p95 }]);
      }
      out.markLine = { silent: true, symbol: 'none', lineStyle: { type: 'dashed', width: 1 }, data: lines };
    }
    if (span) areas.push([{ xAxis: span[0], itemStyle: { color: '#f59e0b', opacity: 0.18 } }, { xAxis: span[1] }]);
    if (areas.length) out.markArea = { silent: true, itemStyle: { opacity: 0.08 }, data: areas };
    return out;
  }

  function draw(id, from, to, lines, format, max) {
    // With a baseline the axis must also reach the baseline's upper line.
    if (max === undefined && lines.some((l) => l.band)) {
      let top = 0;
      for (const l of lines) {
        for (const [, v] of l.data) if (num(v) && v > top) top = v;
        if (l.band) top = Math.max(top, l.band.median, l.band.p95 || 0);
      }
      if (top > 0) max = top * 1.1;
    }
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
        // Few points (a short-lived program): show them, or a single point would be invisible.
        showSymbol: l.data.filter(([, v]) => v !== null).length < 60,
        symbolSize: 5,
        connectNulls: false,
        lineStyle: { width: 1.5 },
        areaStyle: { opacity: 0.12 },
        data: l.data,
        ...bandMarks(l.band, format, lines.length === 1, l.span),
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

  function anomalyItem(a) {
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
    const open = el('a', 'text-sky-700 hover:underline', 'Investigate');
    open.href = '#/anomalies/' + a.id;
    const links = el('p', 'mt-1');
    links.append(open);
    more.append(el('summary', 'cursor-pointer text-slate-500', 'Why was this flagged?'), el('p', 'mt-1', a.explanation), links);
    li.append(head, more);
    return li;
  }

  function showAnomalies(list) {
    const ul = $('anomalies');
    ul.replaceChildren();
    for (const a of list.anomalies.slice(0, 20)) ul.append(anomalyItem(a));
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
      const name = el('td', 'max-w-40 truncate py-1 pr-2');
      name.title = r.application && r.application !== r.name ? r.name + ' · ' + r.application : r.name;
      if (r.subject) {
        const link = el('a', 'text-sky-700 hover:underline', r.name);
        link.href = '#/subject/' + r.subject.scope + '/' + r.subject.id;
        name.append(link);
      } else {
        name.textContent = r.name;
      }
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
    let res = 0;
    results.forEach((r, i) => {
      const data = r.status === 'fulfilled' ? r.value : null;
      if (data && data.sampled_every_ticks > sampled) sampled = data.sampled_every_ticks;
      if (data && data.resolution_ms) res = data.resolution_ms;
      box.append(rankingCard(METRICS[i], data));
    });
    $('rankings-note').textContent =
      'Average is over the whole range, counting the time something was not running as zero, so a short burst ranks below steady work. ' +
      'Processes with several copies running are added together. ' +
      (res ? 'This range reaches back past the raw samples, so it is read from ' + ago(res) +
          ' averages (older history is kept as averages); peaks are the highest average of one such period. ' : '') +
      (sampled > 1
        ? 'This range is long, so it is read from about every ' + sampled + 'th ' + (res ? 'period' : 'sample') + ' (roughly every ' +
          ago(sampled * (res || intervalSecs * 1000)) + '); peaks are the highest of those moments.'
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
    updateExports();
    const { from, to } = window_();
    loadRankings(from, to);
  });

  // ---- detail page ---------------------------------------------------------------------------

  let view = 'dashboard';
  let detailKey = null; // 'application/12' or 'executable/3'
  let detailRun = 0;
  let detailWindow = null; // the baseline window (hours) the person picked, if any
  let detailData = null;

  function showDetailError(text) {
    const n = $('detail-error');
    n.textContent = text || '';
    n.classList.toggle('hidden', !text);
  }

  const SIGNATURE = {
    valid: 'signed',
    not_signed: 'not signed',
    invalid: 'signature invalid',
    unreadable: 'signature could not be read',
  };
  const signature = (status, signer) =>
    (SIGNATURE[status] || status) + (signer && status === 'valid' ? ' by ' + signer : '');

  function metaRow(label, value) {
    if (value === null || value === undefined || value === '') return [];
    const dt = el('dt', 'text-slate-500', label);
    const dd = el('dd', 'break-words');
    if (value instanceof Node) dd.append(value); else dd.textContent = String(value);
    return [dt, dd];
  }

  function subjectLink(scope, id, text) {
    const a = el('a', 'text-sky-700 hover:underline', text);
    a.href = '#/subject/' + scope + '/' + id;
    return a;
  }

  function showMeta(d) {
    $('d-name').textContent = d.name;
    document.title = d.name + ' \u00b7 WinPerf report';
    $('d-kind').textContent =
      (d.scope === 'application' ? 'Installed application' : 'Program file') + ' \u00b7 ' + d.classification.replace(/_/g, ' ');
    const dl = $('d-meta');
    dl.replaceChildren();
    const rows = [
      metaRow('Publisher', d.publisher),
      metaRow('Version', d.version),
      metaRow('Description', d.description),
      metaRow(d.scope === 'application' ? 'Installed in' : 'File', d.location),
      metaRow('Signature', d.signature ? signature(d.signature.status, d.signature.signer) : null),
      metaRow('Installed on', d.install_date),
      metaRow('Part of', d.application ? subjectLink('application', d.application.id, d.application.name) : null),
      metaRow('First seen by a scan', d.first_seen),
      metaRow('Last seen by a scan', d.last_seen),
    ];
    for (const pair of rows) dl.append(...pair);
  }

  function showExecutables(d) {
    const body = $('d-exes');
    body.replaceChildren();
    for (const e of d.executables) {
      const row = el('tr', 'border-t border-slate-100');
      const name = el('td', 'py-1 pr-3');
      name.append(d.scope === 'application' ? subjectLink('executable', e.id, e.file_name) : document.createTextNode(e.file_name));
      const path = el('td', 'break-all py-1 text-slate-600', e.file_path);
      row.append(name, el('td', 'py-1 pr-3', signature(e.signature_status, e.signer)),
        el('td', 'py-1 pr-3 text-right tabular-nums', String(e.running)),
        el('td', 'py-1 pr-3 text-right tabular-nums', String(e.instances)), path);
      body.append(row);
    }
    $('d-exes-empty').classList.toggle('hidden', d.executables.length > 0);
  }

  function showRuns(d) {
    const body = $('d-runs');
    body.replaceChildren();
    for (const r of d.runs) {
      const row = el('tr', 'border-t border-slate-100');
      const name = el('td', 'py-1 pr-3', r.name);
      if (r.exe_path) name.title = r.exe_path;
      row.append(name, el('td', 'py-1 pr-3 text-right tabular-nums', String(r.pid)),
        el('td', 'py-1 pr-3', r.first_seen), el('td', 'py-1 pr-3', r.last_seen),
        el('td', 'py-1 pr-3', r.ended || 'not marked as ended'), el('td', 'py-1', r.user || ''));
      body.append(row);
    }
    $('d-runs-empty').classList.toggle('hidden', d.runs.length > 0);
  }

  // The stored baseline rows of one window, by metric.
  function baselinesOf(d, windowHours) {
    const out = {};
    for (const b of d.baselines) if (b.window_hours === windowHours) out[b.metric] = b;
    return out;
  }

  function drawDetailCharts(d, from, to, windowHours) {
    const pts = d.series;
    const k = d.bucket_ms;
    const bl = baselinesOf(d, windowHours);
    draw('d-chart-cpu', from, to, [{ name: 'CPU', data: seriesOf(pts, 'cpu_percent', k), band: bl.cpu }], pct);
    draw('d-chart-mem', from, to, [{ name: 'Memory', data: seriesOf(pts, 'working_set_bytes', k), band: bl.memory }], bytes);
    draw('d-chart-disk', from, to, [
      { name: 'Read', data: seriesOf(pts, 'disk_read_bytes_per_sec', k), band: bl.disk_read },
      { name: 'Write', data: seriesOf(pts, 'disk_write_bytes_per_sec', k), band: bl.disk_write },
    ], rate);
    draw('d-chart-net', from, to, [
      { name: 'Received', data: seriesOf(pts, 'net_rx_bytes_per_sec', k), band: bl.net_rx },
      { name: 'Sent', data: seriesOf(pts, 'net_tx_bytes_per_sec', k), band: bl.net_tx },
    ], rate);
    const any = d.baselines.find((b) => b.window_hours === windowHours);
    $('d-baseline-note').textContent = any
      ? 'Dashed lines are the stored baseline for the last ' + windowHours + ' h: the typical level (median) and the 95th percentile, ' +
        'with the stretch between them shaded. It was computed ' + when(any.computed_at_ms) + ' from ' + any.observations +
        ' samples. Values are totals over all running copies, averaged within each point; gaps mean it was not running or not recorded.'
      : 'No baseline has been stored for this yet; it needs the monitor to have recorded it for a while.';
    if (d.resolution_ms) {
      $('d-baseline-note').textContent += ' This range reaches back past the raw samples, so the history shows ' +
        ago(d.resolution_ms) + ' averages.';
    }
    if (d.sampled_every_ticks > 1) {
      $('d-baseline-note').textContent += ' This range is long, so the history is read from about every ' + d.sampled_every_ticks +
        'th ' + (d.resolution_ms ? 'period' : 'sample') + ' (roughly every ' +
        ago(d.sampled_every_ticks * (d.resolution_ms || intervalSecs * 1000)) + '); a program that ran for less than that can be missing.';
    }
  }

  function renderDetail(d, from, to) {
    detailData = d;
    showMeta(d);
    showExecutables(d);
    showRuns(d);
    const list = $('d-anomalies');
    list.replaceChildren();
    for (const a of d.anomalies) list.append(anomalyItem(a));
    $('d-anomalies-empty').classList.toggle('hidden', d.anomalies.length > 0);

    const windows = [...new Set(d.baselines.map((b) => b.window_hours))].sort((a, b) => a - b);
    if (!windows.includes(detailWindow)) detailWindow = windows.length ? windows[windows.length - 1] : null;
    const select = $('d-window');
    select.replaceChildren();
    for (const w of windows) {
      const o = el('option', '', w + ' h');
      o.value = String(w);
      select.append(o);
    }
    select.value = String(detailWindow);
    select.disabled = windows.length === 0;
    drawDetailCharts(d, from, to, detailWindow);
  }

  $('d-window').addEventListener('change', (event) => {
    detailWindow = Number(event.target.value);
    if (detailData) {
      const { from, to } = window_();
      drawDetailCharts(detailData, from, to, detailWindow);
    }
  });

  async function loadDetail() {
    if (!detailKey) return;
    const run = ++detailRun;
    const { from, to } = window_();
    try {
      const [d, status] = await Promise.all([
        api('/api/subjects/' + detailKey + '?points=300&from_ms=' + Math.floor(from) + '&to_ms=' + Math.ceil(to)),
        api('/api/status').catch(() => null), // only for the recording pill in the header
      ]);
      if (run !== detailRun || view !== 'detail') return;
      showDetailError('');
      if (status) showStatus(status);
      renderDetail(d, from, to);
      $('updated').textContent = 'Updated ' + new Date().toLocaleTimeString();
    } catch (e) {
      if (run === detailRun) {
        showDetailError(e.message);
        if (!detailData) $('d-name').textContent = 'Not available';
      }
    }
  }

  // ---- anomalies: list and investigation -----------------------------------------------------

  let anomalyId = null;
  let anomalyData = null;
  let anomalyRun = 0;
  let listRun = 0;
  let listData = [];
  const filters = { state: 'all', severity: 'all', resource: 'all', text: '' };

  function showAnomalyError(text) {
    const n = $('anomaly-error');
    n.textContent = text || '';
    n.classList.toggle('hidden', !text);
  }

  const RESOURCE_LABEL = { cpu: 'CPU', memory: 'Memory', disk: 'Disk', network: 'Network' };
  const kindLabel = (a) => (a.kind === 'memory_growth' ? 'memory growth' : RESOURCE_LABEL[a.resource] || a.resource);
  // The unit of an event's numbers follows its resource.
  const valueFormat = (a) => (a.kind === 'memory_growth' ? (v) => (num(v) ? bytes(v) + '/h' : '–')
    : a.resource === 'cpu' ? pct : a.resource === 'memory' ? bytes : rate);

  function duration(ms) {
    const s = Math.round(ms / 1000);
    if (s < 90) return s + ' s';
    if (s < 5400) return Math.round(s / 60) + ' min';
    return (s / 3600).toFixed(1) + ' h';
  }

  function ratio(a) {
    return a.baseline > 0 ? (a.current / a.baseline).toFixed(a.current / a.baseline < 10 ? 1 : 0) + '× baseline' : 'no usable baseline';
  }

  function matches(a) {
    if (filters.state === 'active' && a.state !== 'active') return false;
    if (filters.severity !== 'all' && a.severity !== filters.severity) return false;
    if (filters.resource !== 'all' && a.resource !== filters.resource) return false;
    const t = filters.text.trim().toLowerCase();
    if (t && !((a.process.name || '') + ' ' + (a.process.application || '')).toLowerCase().includes(t)) return false;
    return true;
  }

  function showAnomalyList() {
    const body = $('al-rows');
    body.replaceChildren();
    const shown = listData.filter(matches);
    for (const a of shown) {
      const row = el('tr', 'border-t border-slate-100 hover:bg-slate-50');
      const sev = el('td', 'py-1 pr-3');
      sev.append(el('span', 'rounded px-2 py-0.5 text-xs font-semibold uppercase ' + (SEVERITY[a.severity] || SEVERITY.informational), a.severity));
      const who = el('td', 'py-1 pr-3');
      const link = el('a', 'text-sky-700 hover:underline', a.process.name);
      link.href = '#/anomalies/' + a.id;
      who.append(link);
      if (a.process.application) who.append(el('span', 'ml-2 text-xs text-slate-500', a.process.application));
      const f = valueFormat(a);
      row.append(sev, el('td', 'py-1 pr-3', kindLabel(a)), who,
        el('td', 'py-1 pr-3 text-right tabular-nums', f(a.current)),
        el('td', 'py-1 pr-3 text-right tabular-nums', f(a.baseline)),
        el('td', 'py-1 pr-3 text-right tabular-nums', ratio(a)),
        el('td', 'py-1 pr-3', when(a.detected_ts_ms)),
        el('td', 'py-1 pr-3 text-right tabular-nums', duration(a.duration_ms)),
        el('td', 'py-1', a.state === 'active' ? 'active' : 'resolved'));
      body.append(row);
    }
    $('al-count').textContent = shown.length + ' of ' + listData.length + ' events in this range';
    $('al-empty').classList.toggle('hidden', shown.length > 0);
  }

  async function loadAnomalyList() {
    const run = ++listRun;
    const { from, to } = window_();
    const hours = Math.max(1, Math.ceil((Date.now() - from) / HOUR));
    try {
      const [res, status] = await Promise.all([
        api('/api/anomalies?limit=1000&hours=' + hours),
        api('/api/status').catch(() => null),
      ]);
      if (run !== listRun || view !== 'anomalies') return;
      $('al-error').classList.add('hidden');
      if (status) showStatus(status);
      listData = res.anomalies.filter((a) => a.detected_ts_ms <= to);
      showAnomalyList();
      $('updated').textContent = 'Updated ' + new Date().toLocaleTimeString();
    } catch (e) {
      if (run !== listRun) return;
      $('al-error').textContent = e.message;
      $('al-error').classList.remove('hidden');
    }
  }

  function bindFilter(id, key) {
    $(id).addEventListener('input', (event) => {
      filters[key] = event.target.value;
      showAnomalyList();
    });
  }
  bindFilter('f-state', 'state');
  bindFilter('f-severity', 'severity');
  bindFilter('f-resource', 'resource');
  bindFilter('f-text', 'text');

  function fact(label, value) {
    return [el('dt', 'text-slate-500', label), el('dd', 'font-medium', value)];
  }

  function showAnomaly(a) {
    anomalyData = a;
    const f = valueFormat(a);
    document.title = a.process.name + ' · anomaly · WinPerf report';
    $('a-title').textContent = a.process.name;
    $('a-state').textContent = (a.state === 'active' ? 'Active since ' : 'Resolved · started ') + when(a.detected_ts_ms) +
      (a.resolved_ts_ms ? ', ended ' + when(a.resolved_ts_ms) : '');
    const sev = $('a-severity');
    sev.className = 'inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase ' + (SEVERITY[a.severity] || SEVERITY.informational);
    sev.textContent = a.severity;
    const facts = $('a-facts');
    facts.replaceChildren();
    const rows = [
      fact('Process', a.process.name + ' (PID ' + a.process.pid + ')'),
      a.process.application ? fact('Application', a.process.application) : [],
      fact(kindLabel(a) + (a.kind === 'memory_growth' ? ' rate' : ' consumption'), f(a.current)),
      fact('Established baseline', f(a.baseline)),
      fact('Deviation', ratio(a) + ' (' + (a.deviation_percent >= 0 ? '+' : '') + Math.round(a.deviation_percent) + ' %)'),
      fact('Duration', duration(a.duration_ms)),
      fact('Baseline confidence', a.baseline_confidence + ' (last ' + a.baseline_window_hours + ' h)'),
      fact('System CPU at the time', pct(a.system.cpu_percent)),
      fact('System memory at the time', pct(a.system.memory_percent)),
      fact('System disk busy at the time', pct(a.system.disk_percent)),
      fact('System pressure / this process’s share', pct(a.impact.pressure_percent) + ' / ' + pct(a.impact.share_percent)),
    ];
    for (const pair of rows) facts.append(...pair);
    $('a-assessment').textContent = a.explanation;
    const link = $('a-subject');
    link.classList.toggle('hidden', !a.subject);
    if (a.subject) link.href = '#/subject/' + a.subject.scope + '/' + a.subject.id;
    drawAnomalyCharts(a);
  }

  function drawAnomalyCharts(a) {
    const c = a.context;
    const f = valueFormat(a);
    const span = [a.detected_ts_ms, a.resolved_ts_ms || a.last_update_ts_ms];
    const proc = c.process;
    $('a-chart-note').textContent = proc === null
      ? 'The process’s own samples are not linked to this event, so only the system is shown.'
      : (c.cut ? 'Long event: the charts show its first 3 hours. ' : '') +
        'The shaded stretch is when the event was active; the dashed line is the baseline it was judged against.';
    $('a-chart-proc-box').classList.toggle('hidden', proc === null);
    if (proc !== null) {
      const band = { median: a.baseline };
      const lines = a.resource === 'disk'
        ? [{ name: 'Read', data: seriesOf(proc, 'io_read_bytes_per_sec', c.bucket_ms), band, span },
          { name: 'Write', data: seriesOf(proc, 'io_write_bytes_per_sec', c.bucket_ms), span }]
        : a.resource === 'network'
          ? [{ name: 'Network', data: seriesOf(proc, 'net_bytes_per_sec', c.bucket_ms), band, span }]
          : a.resource === 'memory' || a.kind === 'memory_growth'
            ? [{ name: 'Working set', data: seriesOf(proc, 'working_set_bytes', c.bucket_ms), band: a.kind === 'memory_growth' ? undefined : band, span }]
            : [{ name: 'CPU', data: seriesOf(proc, 'cpu_percent', c.bucket_ms), band, span }];
      $('a-chart-proc-title').textContent = a.process.name + ' — ' + kindLabel(a);
      draw('a-chart-proc', c.from_ms, c.to_ms, lines, a.kind === 'memory_growth' ? bytes : f);
    }
    draw('a-chart-cpu', c.from_ms, c.to_ms, [{ name: 'System CPU', data: seriesOf(c.system, 'cpu_percent', c.bucket_ms), span }], pct, 100);
    draw('a-chart-mem', c.from_ms, c.to_ms, [{ name: 'System memory', data: seriesOf(c.system, 'memory_used_percent', c.bucket_ms), span }], pct, 100);
    draw('a-chart-disk', c.from_ms, c.to_ms, [{ name: 'Disk busy', data: seriesOf(c.system, 'disk_busy_percent', c.bucket_ms), span }], pct, 100);
  }

  async function loadAnomaly() {
    if (!anomalyId) return;
    const run = ++anomalyRun;
    try {
      const [a, status] = await Promise.all([api('/api/anomalies/' + anomalyId), api('/api/status').catch(() => null)]);
      if (run !== anomalyRun || view !== 'anomaly') return;
      showAnomalyError('');
      if (status) showStatus(status);
      showAnomaly(a);
      $('updated').textContent = 'Updated ' + new Date().toLocaleTimeString();
    } catch (e) {
      if (run !== anomalyRun) return;
      showAnomalyError(e.message);
      if (!anomalyData) $('a-title').textContent = 'Not available';
    }
  }

  // ---- views ---------------------------------------------------------------------------------

  function route() {
    const m = /^#\/subject\/(application|executable)\/(\d+)$/.exec(location.hash);
    const list = location.hash === '#/anomalies';
    const one = /^#\/anomalies\/(\d+)$/.exec(location.hash);
    const next = m ? 'detail' : list ? 'anomalies' : one ? 'anomaly' : 'dashboard';
    const changed = next !== view || (m && detailKey !== m[1] + '/' + m[2]) || (one && anomalyId !== one[1]);
    view = next;
    for (const [name, id] of [['dashboard', 'view-dashboard'], ['detail', 'view-detail'],
      ['anomalies', 'view-anomalies'], ['anomaly', 'view-anomaly']]) {
      $(id).classList.toggle('hidden', view !== name);
    }
    if (!changed) return;
    if (view === 'anomalies') {
      document.title = 'Anomalies · WinPerf report';
      window.scrollTo(0, 0);
      loadAnomalyList();
    } else if (view === 'anomaly') {
      anomalyId = one[1];
      anomalyData = null;
      $('a-title').textContent = 'Loading…';
      for (const id of ['a-facts', 'a-assessment']) $(id).replaceChildren();
      $('a-assessment').textContent = '';
      showAnomalyError('');
      window.scrollTo(0, 0);
      loadAnomaly();
    } else if (view === 'detail') {
      detailKey = m[1] + '/' + m[2];
      detailData = null;
      for (const id of ['d-meta', 'd-exes', 'd-runs', 'd-anomalies']) $(id).replaceChildren(); // the last page's
      $('d-kind').textContent = '';
      $('d-name').textContent = 'Loading\u2026';
      showDetailError('');
      window.scrollTo(0, 0);
      loadDetail();
    } else {
      document.title = 'WinPerf report';
      detailKey = null;
      refresh(true);
    }
    // Charts were laid out while their page was hidden; let them measure themselves again.
    Object.values(charts).forEach((c) => c.resize());
  }
  window.addEventListener('hashchange', route);

  // ---- downloads -----------------------------------------------------------------------------

  // The links carry the selected range, the grouping and the token, so a click downloads what is
  // on screen. They are plain links: the browser streams the file to disk.
  function updateExports() {
    const { from, to } = window_();
    const metric = $('export-metric').value;
    document.querySelectorAll('#exports a').forEach((a) => {
      const q = new URLSearchParams({ format: a.dataset.format, from_ms: String(Math.floor(from)), to_ms: String(Math.ceil(to)) });
      if (a.dataset.export === 'rankings') { q.set('metric', metric); q.set('group', groupKey); }
      if (token) q.set('token', token);
      a.href = '/api/export/' + a.dataset.export + '?' + q.toString();
    });
  }
  $('export-metric').addEventListener('change', updateExports);

  // ---- loading -------------------------------------------------------------------------------

  function window_() {
    if (custom) return custom;
    const to = Date.now();
    return { from: to - RANGES[rangeKey], to };
  }

  let chartRes = 0;
  let busy = false;
  async function refresh(force) {
    if (busy) return;
    busy = true;
    const { from, to } = window_();
    if (force || Date.now() - rankingsAt > 30000) loadRankings(from, to);
    updateExports();
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
      if (system.status === 'fulfilled') {
        drawCharts(system.value, from, to);
        chartRes = system.value.resolution_ms || 0;
      }
      if (anomalies.status === 'fulfilled') showAnomalies(anomalies.value);
      $('updated').textContent = 'Updated ' + new Date().toLocaleTimeString() +
        (chartRes ? ' · the charts show ' + ago(chartRes) + ' averages (older than the raw samples)' : '');
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
    reload(true);
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
    reload(true);
  });

  // ---- polling -------------------------------------------------------------------------------

  function reload(force) {
    if (view === 'detail') return loadDetail();
    if (view === 'anomalies') return loadAnomalyList();
    if (view === 'anomaly') return loadAnomaly();
    return refresh(force);
  }

  setInterval(() => { if (!document.hidden && !custom) reload(); }, POLL_MS);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) reload(); });

  markRange();
  markGroup();
  route();
  if (view === 'dashboard') refresh(true);
})();
