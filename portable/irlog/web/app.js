/* 应急响应日志分析平台 — 交互控制台逻辑（原生 JS，零依赖，离线可用） */
'use strict';

const SEV = { 1: '紧急', 2: '高危', 3: '中危', 4: '低危' };

const state = {
  files: [],
  selected: new Set(),
  rules: [],
  version: '',
  ioc: { items: [], files: [] },
  current: null,      // 当前分析结果（或从报告中心载入的历史结果）
  task: null,
  polling: false,
  runs: [],
};

/* ---------- 工具 ---------- */
const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function fmtSize(n) {
  if (n == null) return '-';
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
  return (n / 1073741824).toFixed(2) + ' GB';
}
function fmtNum(n) { return (n == null ? '-' : n).toLocaleString(); }

let toastTimer = null;
function toast(msg, type) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = type || 'info';
  t.style.display = 'block';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.style.display = 'none'; }, 3200);
}

async function api(path, opts) {
  const r = await fetch(path, opts);
  const text = await r.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) { /* 非 JSON */ }
  if (!r.ok) throw new Error((data && data.error) || text || ('HTTP ' + r.status));
  return data;
}

function switchTab(name) {
  $$('.tab').forEach((b) => b.classList.toggle('active', b.dataset.tab === name));
  $$('.panel').forEach((p) => p.classList.toggle('active', p.id === 'tab-' + name));
  if (name === 'reports') refreshRuns();
  if (name === 'audit') refreshAudit();
  if (name === 'ioc') refreshIOC();
  if (name === 'timeline') renderTimeline();
  if (name === 'alerts') renderAlerts();
}

/* ---------- 证据管理 ---------- */
async function refreshFiles() {
  try {
    const files = await api('/api/files');
    state.files = files;
    state.selected = new Set(files.map((f) => f.name)); // 默认全选
    renderFiles();
    renderChips();
  } catch (e) { toast('获取证据列表失败: ' + e.message, 'err'); }
}

function renderFiles() {
  const tb = $('#fileTable tbody');
  if (!state.files.length) {
    tb.innerHTML = '<tr><td colspan="6" class="empty"><span class="big">📂</span>暂无证据文件，拖拽上传或点击上方选择</td></tr>';
  } else {
    tb.innerHTML = state.files.map((f) => `
      <tr>
        <td><input type="checkbox" class="fileChk" data-name="${esc(f.name)}" ${state.selected.has(f.name) ? 'checked' : ''}></td>
        <td class="mono">${esc(f.name)}</td>
        <td class="nowrap">${fmtSize(f.size)}</td>
        <td><span class="badge type">${esc(f.log_type || 'generic')}</span></td>
        <td class="mono" title="${esc(f.sha256)}">${esc((f.sha256 || '').slice(0, 20))}…</td>
        <td><button class="small danger" data-del="${esc(f.name)}" title="删除该证据文件（不可恢复，记入审计）">🗑 删除</button></td>
      </tr>`).join('');
  }
  $('#selCount').textContent = `已选 ${state.selected.size} / ${state.files.length} 个文件`;
}

function selectAll(on) {
  state.selected = on ? new Set(state.files.map((f) => f.name)) : new Set();
  renderFiles();
  renderChips();
}

function renderChips() {
  const box = $('#selChips');
  $('#chipCount').textContent = state.selected.size;
  if (!state.selected.size) {
    box.innerHTML = '<span class="hint">尚未选择文件，请前往「证据管理」勾选。</span>';
    return;
  }
  box.innerHTML = [...state.selected].map((n) =>
    `<span class="chip">${esc(n)}<button data-deselect="${esc(n)}" title="移除">✕</button></span>`).join('');
}

/* 事件委托：文件名含引号/特殊字符时，比内联 onclick 更安全 */
document.addEventListener('click', (e) => {
  const del = e.target.closest('[data-del]');
  if (del) { deleteFile(del.dataset.del); return; }
  const des = e.target.closest('[data-deselect]');
  if (des) deselect(des.dataset.deselect);
});

async function deleteFile(name) {
  if (!confirm(`确定删除证据文件「${name}」？\n\n删除后不可恢复，该操作会记入审计日志。`)) return;
  try {
    const r = await api('/api/files?name=' + encodeURIComponent(name), { method: 'DELETE' });
    state.files = state.files.filter((f) => f.name !== r.deleted);
    state.selected.delete(r.deleted);
    renderFiles();
    renderChips();
    toast('已删除 ' + r.deleted, 'ok');
  } catch (e) { toast('删除失败: ' + e.message, 'err'); }
}

function deselect(name) {
  state.selected.delete(name);
  renderFiles();
  renderChips();
}

function gotoAnalyze() {
  if (!state.selected.size) { toast('请先勾选至少一个证据文件', 'err'); return; }
  switchTab('analyze');
}

function friendlyErr(e) {
  const m = String(e && e.message || e);
  if (/failed to fetch|networkerror|load failed/i.test(m)) {
    return '无法连接服务（请确认 http://' + location.host + ' 可访问、服务已启动）';
  }
  return m;
}

/* 与服务端 _safe_filename 保持一致，用于核实文件是否已落盘 */
function sanitizeName(name) {
  return String(name || '').split(/[\\/]/).pop()
    .replace(/[^A-Za-z0-9._\-\u4e00-\u9fff]/g, '_').slice(0, 120) || 'upload.bin';
}

/* XHR 上传：可观测进度，错误信息更完整 */
function uploadOne(file, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/upload');
    xhr.timeout = 300000;
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total);
    };
    xhr.onload = () => {
      let d = null;
      try { d = JSON.parse(xhr.responseText); } catch (e) { /* 非 JSON */ }
      if (xhr.status >= 200 && xhr.status < 300) resolve(d || {});
      else reject(new Error((d && d.error) || ('HTTP ' + xhr.status)));
    };
    xhr.onerror = () => reject(new Error('网络错误/响应中断'));
    xhr.ontimeout = () => reject(new Error('上传超时(300s)'));
    const fd = new FormData();
    fd.append('file', file);
    xhr.send(fd);
  });
}

/* 网络层失败时核实服务端是否已收到（大文件经代理上传时响应可能被掐断，但文件已落盘） */
async function fileLanded(file) {
  try {
    const files = await api('/api/files');
    const want = sanitizeName(file.name);
    return files.some((f) => f.name === want || f.size === file.size);
  } catch (e) { return false; }
}

async function uploadFiles(list) {
  if (!list || !list.length) return;
  const status = $('#uploadStatus');
  let ok = 0;
  for (const f of list) {
    let done = false;
    for (let attempt = 1; attempt <= 2 && !done; attempt++) {
      try {
        if (status) status.textContent = `正在上传 ${f.name}（${fmtSize(f.size)}）…`;
        await uploadOne(f, (p) => {
          if (status) status.textContent = `正在上传 ${f.name} ${Math.round(p * 100)}%`;
        });
        done = true;
      } catch (e) {
        if (await fileLanded(f)) { done = true; break; }  // 已落盘，视为成功
        if (attempt === 2) {
          toast('上传失败 ' + f.name + '：' + friendlyErr(e) +
                '。如反复失败，请在浏览器直接打开本页地址上传（部分预览代理不支持大文件 POST）', 'err');
        }
      }
    }
    if (done) ok++;
  }
  if (status) status.textContent = '';
  if (ok) toast(`已上传 ${ok} 个文件`, 'ok');
  await refreshFiles();
}

/* ---------- 分析中心 ---------- */
async function startAnalysis() {
  const files = [...state.selected];
  if (!files.length) { toast('请先在「证据管理」中勾选证据文件', 'err'); switchTab('evidence'); return; }
  const overrides = [];
  $$('[data-cfg]').forEach((inp) => {
    const v = (inp.value || '').trim();
    if (!v) return;
    const k = inp.dataset.cfg;
    overrides.push(inp.dataset.unit === 'mb' ? `${k}=${Math.round(parseFloat(v) * 1048576)}` : `${k}=${v}`);
  });
  const body = {
    files,
    operator: ($('#operator').value || '').trim() || 'IR-Analyst',
    rules: $('#rulesSelect').value,
    overrides,
  };
  $('#runBtn').disabled = true;
  $('#progWrap').style.display = 'block';
  $('#progBar').style.width = '0%';
  $('#progMsg').textContent = '正在启动分析…';
  try {
    const r = await api('/api/analyze', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    state.task = r.task_id;
    pollTask();
  } catch (e) {
    toast('启动失败: ' + e.message, 'err');
    $('#runBtn').disabled = false;
    $('#progWrap').style.display = 'none';
  }
}

async function pollTask() {
  if (!state.task || state.polling) return;
  state.polling = true;
  try {
    const t = await api('/api/task/' + state.task);
    $('#progBar').style.width = Math.round((t.progress || 0) * 100) + '%';
    $('#progMsg').textContent = t.message || '';
    if (t.status === 'done') {
      state.task = null;
      state.current = t.result;
      $('#runBtn').disabled = false;
      $('#progWrap').style.display = 'none';
      renderAll();
      refreshRuns();
      refreshIOC();
      toast(`分析完成：${fmtNum(t.result.stats.total_events)} 条事件，${t.result.stats.alert_count} 条告警`, 'ok');
    } else if (t.status === 'error') {
      state.task = null;
      $('#runBtn').disabled = false;
      $('#progMsg').textContent = '分析失败: ' + (t.error || '未知错误');
      toast('分析失败: ' + (t.error || '未知错误'), 'err');
    } else {
      setTimeout(pollTask, 800);
    }
  } catch (e) {
    state.task = null;
    $('#runBtn').disabled = false;
    toast('轮询失败: ' + e.message, 'err');
  } finally {
    state.polling = false;
  }
}

function renderSummary() {
  const d = state.current;
  const card = $('#summaryCard');
  if (!d) { card.style.display = 'none'; return; }
  card.style.display = 'block';
  const s = d.stats || {};
  const sev = d.severity_summary || {};
  $('#runIdLabel').textContent = '案件编号 ' + d.run_id + ' · ' + (d.started || '') + ' ~ ' + (d.finished || '');
  $('#statRow').innerHTML =
    `<div class="stat"><b>${fmtNum(s.total_events)}</b><span>事件总数</span></div>
     <div class="stat"><b>${fmtNum(s.total_files)}</b><span>证据文件</span></div>
     <div class="stat alert"><b>${fmtNum(s.alert_count)}</b><span>告警总数</span></div>
     <div class="stat"><b>${d.duration_sec}s</b><span>分析耗时</span></div>
     <div class="stat"><b style="color:var(--sev-critical)">${sev['紧急'] || 0}</b><span>紧急</span></div>
     <div class="stat"><b style="color:var(--sev-high)">${sev['高危'] || 0}</b><span>高危</span></div>
     <div class="stat"><b style="color:var(--sev-medium)">${sev['中危'] || 0}</b><span>中危</span></div>
     <div class="stat"><b style="color:var(--sev-low)">${sev['低危'] || 0}</b><span>低危</span></div>`;
  const files = (d.files || []).map((f) => `
    <tr><td class="mono">${esc((f.path || '').split(/[\\\/]/).pop())}</td>
        <td><span class="badge type">${esc(f.log_type || '-')}</span></td>
        <td>${fmtNum(f.events)}</td>
        <td class="hint">${esc(f.skipped_reason || '')}</td></tr>`).join('');
  const dlJson = $('#dlJson'), dlHtml = $('#dlHtml');
  dlJson.href = '/api/report/' + encodeURIComponent(d.run_id) + '?format=json';
  dlJson.setAttribute('download', d.run_id + '.json');
  dlHtml.href = '/api/report/' + encodeURIComponent(d.run_id) + '?format=html';
  dlHtml.setAttribute('download', d.run_id + '.html');
  const old = $('#fileSummaryTable');
  if (old) old.remove();
  const tbl = document.createElement('div');
  tbl.id = 'fileSummaryTable';
  tbl.innerHTML = `<h3>证据解析明细</h3>
    <table class="grid"><thead><tr><th>文件</th><th>识别类型</th><th>事件数</th><th>备注</th></tr></thead>
    <tbody>${files || '<tr><td colspan="4" class="hint">无</td></tr>'}</tbody></table>`;
  card.appendChild(tbl);
}

/* ---------- 告警看板 ---------- */
function filteredAlerts() {
  const sev = $('#sevFilter').value;
  const rule = $('#ruleFilter').value;
  const q = ($('#alertSearch').value || '').trim().toLowerCase();
  return (state.current?.alerts || []).filter((a) => {
    if (sev && String(a.severity) !== sev) return false;
    if (rule && a.rule_id !== rule) return false;
    if (q && !JSON.stringify(a).toLowerCase().includes(q)) return false;
    return true;
  });
}

function alertCard(a) {
  const ent = Object.entries(a.entities || {})
    .map(([k, v]) => `<b>${esc(k)}</b>: ${esc(Array.isArray(v) ? v.join(', ') : v)}`)
    .join(' &nbsp;·&nbsp; ');
  const evs = (a.evidence || []).map((e) =>
    `<div class="ev"><span class="src">[${esc(e.time || '?')}] ${esc((e.source || '').split(/[\\\/]/).pop())}</span>\n${esc(e.raw)}</div>`).join('');
  return `<details class="alert-card">
    <summary class="ac-head">
      <span class="badge sev${a.severity}">${esc(a.severity_label || SEV[a.severity] || a.severity)}</span>
      <span class="ac-title">${esc(a.title)}</span>
      <span class="ac-desc">${esc((a.description || '').slice(0, 110))}</span>
      <span class="ac-time">${esc(a.first_time || '')} ~ ${esc(a.last_time || '')} · ${a.count} 次</span>
    </summary>
    <div class="ac-body">
      <div class="kv">${ent || '<span class="hint">无实体信息</span>'}</div>
      <span class="tag-mitre">ATT&CK: ${esc(a.mitre)}</span>
      <div class="rec"><b>处置建议：</b>${esc(a.recommendation)}</div>
      <div style="margin-top:8px"><b>证据样本</b>（原始日志只读未改）：</div>
      ${evs || '<div class="hint">（无采样证据）</div>'}
    </div>
  </details>`;
}

function renderAlerts() {
  const box = $('#alertList');
  const pill = $('#alertPill');
  const total = (state.current?.alerts || []).length;
  pill.style.display = total ? 'inline-block' : 'none';
  pill.textContent = total;
  if (!state.current) {
    box.innerHTML = '<div class="empty"><span class="big">🚨</span>尚未运行分析。前往「分析中心」开始，或在「报告中心」载入历史结果。</div>';
    $('#alertCountLabel').textContent = '';
    return;
  }
  // 规则过滤器选项（按当前结果中出现的规则重建）
  const ruleSel = $('#ruleFilter');
  const cur = ruleSel.value;
  const ids = [...new Set((state.current.alerts || []).map((a) => a.rule_id))].sort();
  ruleSel.innerHTML = '<option value="">全部</option>' +
    ids.map((id) => `<option value="${esc(id)}">${esc(id)}</option>`).join('');
  ruleSel.value = ids.includes(cur) ? cur : '';

  const list = filteredAlerts();
  $('#alertCountLabel').textContent = `共 ${total} 条，筛选出 ${list.length} 条`;
  box.innerHTML = list.length
    ? list.map(alertCard).join('')
    : '<div class="empty"><span class="big">✅</span>没有符合筛选条件的告警</div>';
}

function exportFiltered() {
  const list = filteredAlerts();
  if (!list.length) { toast('没有可导出的告警', 'err'); return; }
  const blob = new Blob([JSON.stringify({ exported_at: new Date().toISOString(), alerts: list }, null, 2)],
    { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'irlog-alerts-' + (state.current?.run_id || 'export') + '.json';
  a.click();
  URL.revokeObjectURL(a.href);
  toast(`已导出 ${list.length} 条告警`, 'ok');
}

/* ---------- 时间线 ---------- */
function renderTimeline() {
  const box = $('#timelineChart');
  const d = state.current;
  const hist = (d && d.timeline && d.timeline.hour_histogram) || {};
  const entries = Object.entries(hist);
  if (!entries.length) {
    box.innerHTML = '<div class="empty"><span class="big">📈</span>暂无可绘制的时间线数据</div>';
    renderTypeBreakdown();
    return;
  }
  // 每小时告警标记
  const marks = {};
  ((d && d.alerts) || []).forEach((a) => {
    const h = (a.first_time || '').slice(0, 13);
    if (h) (marks[h] = marks[h] || []).push(a);
  });
  const W = 920, H = 300, mL = 60, mR = 14, mT = 34, mB = 42;
  const iw = W - mL - mR, ih = H - mT - mB, n = entries.length;
  const slot = iw / n;
  const bw = Math.max(2, slot - 2);
  const max = Math.max(1, ...entries.map((e) => e[1]));
  let s = `<svg class="timeline-chart" viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg" role="img">`;
  for (let i = 0; i <= 4; i++) {
    const v = Math.round((max * i) / 4), y = mT + ih - (ih * i) / 4;
    s += `<line x1="${mL}" y1="${y}" x2="${W - mR}" y2="${y}" stroke="#e8edf2"/>`;
    s += `<text x="${mL - 8}" y="${y + 4}" text-anchor="end" font-size="11" fill="#7f8c8d">${v}</text>`;
  }
  const step = Math.max(1, Math.ceil(n / 14));
  entries.forEach(([hh, c], i) => {
    const cx = mL + (i + 0.5) * slot;
    const h = Math.max(1.5, (ih * c) / max);
    s += `<rect x="${(cx - bw / 2).toFixed(1)}" y="${(mT + ih - h).toFixed(1)}" width="${bw.toFixed(1)}" height="${h.toFixed(1)}" rx="2" fill="#2874a6">`
       + `<title>${esc(hh)} 时 · ${c} 条事件</title></rect>`;
    const mk = marks[hh];
    if (mk) {
      s += `<circle cx="${cx.toFixed(1)}" cy="${mT - 14}" r="5.5" fill="#c0392b">`
         + `<title>该小时 ${mk.length} 条告警：${esc(mk.map((a) => a.title).join('；').slice(0, 140))}</title></circle>`;
    }
    if (i % step === 0) {
      s += `<text x="${cx.toFixed(1)}" y="${H - 12}" text-anchor="middle" font-size="10" fill="#7f8c8d">${esc(hh.slice(5))}</text>`;
    }
  });
  s += `<line x1="${mL}" y1="${mT + ih}" x2="${W - mR}" y2="${mT + ih}" stroke="#c9d4de"/>`;
  s += '</svg>';
  box.innerHTML = s;
  renderTypeBreakdown();
}

function renderTypeBreakdown() {
  const box = $('#typeBreakdown');
  const by = (state.current && state.current.timeline && state.current.timeline.by_log_type) || {};
  const entries = Object.entries(by).sort((a, b) => b[1] - a[1]);
  if (!entries.length) { box.innerHTML = '<div class="hint">无数据</div>'; return; }
  const max = Math.max(1, ...entries.map((e) => e[1]));
  box.innerHTML = entries.map(([t, c]) => `
    <div style="display:flex;align-items:center;gap:10px;margin:5px 0">
      <span class="mono" style="width:130px;text-align:right;color:#41556b">${esc(t)}</span>
      <div style="flex:1;background:#eef2f5;border-radius:4px;height:15px">
        <div style="height:100%;width:${((c * 100) / max).toFixed(1)}%;background:#2874a6;border-radius:4px"></div>
      </div>
      <span class="mono" style="width:70px">${fmtNum(c)}</span>
    </div>`).join('');
}

/* ---------- IOC 情报 ---------- */
async function refreshIOC() {
  try {
    const r = await api('/api/ioc');
    state.ioc = { items: r.items || [], files: r.files || [] };
    renderIOC();
  } catch (e) { toast('获取 IOC 失败: ' + e.message, 'err'); }
}

function renderIOC() {
  const items = state.ioc.items;
  $('#iocCountLabel').textContent = items.length;
  $('#iocCountLabel2').textContent = `当前 ${items.length} 条`;
  const pill = $('#iocPill');
  pill.style.display = items.length ? 'inline-block' : 'none';
  pill.textContent = items.length;
  const sel = $('#iocFileSelect');
  const keep = sel.value;
  sel.innerHTML = '<option value="">（无可用文件）</option>' +
    state.ioc.files.map((f) => `<option value="${esc(f)}">${esc(f)}</option>`).join('');
  sel.value = state.ioc.files.includes(keep) ? keep : '';
  $('#iocTable tbody').innerHTML = items.length
    ? items.map((it, i) => `<tr><td>${i + 1}</td><td class="mono">${esc(it.value)}</td>
        <td><span class="badge type">${esc(it.type)}</span></td><td class="hint">${esc(it.source)}</td></tr>`).join('')
    : '<tr><td colspan="4" class="hint">IOC 库为空。粘贴导入或从文件载入；分析时自动匹配 IP/域名/哈希/URL。</td></tr>';
}

async function importIOC() {
  const text = $('#iocText').value || '';
  if (!text.trim()) { toast('请先粘贴 IOC 内容', 'err'); return; }
  try {
    const r = await api('/api/ioc', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    });
    toast(`已导入 ${r.imported} 条，当前共 ${r.count} 条`, 'ok');
    $('#iocText').value = '';
    await refreshIOC();
  } catch (e) { toast('导入失败: ' + e.message, 'err'); }
}

async function clearIOC() {
  if (!confirm('确认清空当前 IOC 库？')) return;
  try {
    await fetch('/api/ioc', { method: 'DELETE' });
    toast('IOC 库已清空', 'ok');
    await refreshIOC();
  } catch (e) { toast('清空失败: ' + e.message, 'err'); }
}

async function loadIOCFile() {
  const f = $('#iocFileSelect').value;
  if (!f) { toast('请先选择 IOC 文件', 'err'); return; }
  try {
    const r = await api('/api/ioc', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'load_file', file: f }),
    });
    toast(`已从 ${f} 载入 ${r.loaded} 条`, 'ok');
    await refreshIOC();
  } catch (e) { toast('载入失败: ' + e.message, 'err'); }
}

/* ---------- 报告中心 ---------- */
async function refreshRuns() {
  try {
    const r = await api('/api/runs');
    state.runs = r.runs || [];
    const tb = $('#runsTable tbody');
    if (!state.runs.length) {
      tb.innerHTML = '<tr><td colspan="7" class="empty"><span class="big">📄</span>暂无历史报告</td></tr>';
      return;
    }
    tb.innerHTML = state.runs.map((run) => {
      const sev = run.severity_summary || {};
      const sevHtml = Object.entries(sev).map(([k, v]) =>
        `<span class="badge ${esc(k)}" style="margin-right:4px">${esc(k)} ${v}</span>`).join('');
      return `<tr>
        <td class="mono">${esc(run.run_id)}</td>
        <td class="nowrap">${esc(run.started || '')}</td>
        <td>${esc(run.duration_sec)}s</td>
        <td>${fmtNum(run.total_events)}</td>
        <td><b style="color:var(--sev-high)">${fmtNum(run.alert_count)}</b></td>
        <td>${sevHtml || '<span class="hint">无告警</span>'}</td>
        <td class="actions">
          <button class="small" onclick="previewReport('${esc(run.run_id)}')">预览</button>
          <a class="btn ghost small" href="/api/report/${encodeURIComponent(run.run_id)}?format=json" download>JSON</a>
          <a class="btn ghost small" href="/api/report/${encodeURIComponent(run.run_id)}?format=html" download>HTML</a>
          <button class="small ghost" onclick="loadRunToBoard('${esc(run.run_id)}')">载入看板</button>
        </td>
      </tr>`;
    }).join('');
  } catch (e) { toast('获取历史报告失败: ' + e.message, 'err'); }
}

function previewReport(runId) {
  openModal('报告预览 · ' + runId,
    `<iframe src="/api/report/${encodeURIComponent(runId)}?format=html" title="report preview"></iframe>`);
}

async function loadRunToBoard(runId) {
  try {
    const d = await api('/api/report/' + encodeURIComponent(runId) + '?format=json');
    state.current = d;
    renderAll();
    switchTab('alerts');
    toast(`已载入 ${runId} 到看板`, 'ok');
  } catch (e) { toast('载入失败: ' + e.message, 'err'); }
}

/* ---------- 审计日志 ---------- */
async function refreshAudit() {
  try {
    const r = await api('/api/audit?n=' + ($('#auditN').value || '500'));
    const rows = (r.entries || []).map((e) => `
      <tr><td class="mono nowrap">${esc(e.ts)}</td><td>${esc(e.actor)}</td>
          <td><span class="badge type">${esc(e.action)}</span></td>
          <td class="mono" style="word-break:break-all">${esc(JSON.stringify(e.detail || {}))}</td></tr>`).join('');
    $('#auditTable tbody').innerHTML = rows ||
      '<tr><td colspan="4" class="hint">暂无审计记录</td></tr>';
  } catch (e) { toast('获取审计日志失败: ' + e.message, 'err'); }
}

/* ---------- 模态框 ---------- */
function openModal(title, bodyHtml) {
  $('#modalTitle').textContent = title;
  $('#modalBody').innerHTML = bodyHtml;
  $('#modal').style.display = 'flex';
}
function closeModal() {
  $('#modal').style.display = 'none';
  $('#modalBody').innerHTML = '';
}

/* ---------- 汇总渲染 ---------- */
function renderAll() {
  renderChips();
  renderSummary();
  renderAlerts();
  renderTimeline();
  $('#iocCountLabel').textContent = state.ioc.items.length;
}

/* ---------- 初始化 ---------- */
function init() {
  // 标签页
  $$('.tab').forEach((b) => b.addEventListener('click', () => switchTab(b.dataset.tab)));
  // 证据复选框（事件委托）
  $('#fileTable tbody').addEventListener('change', (e) => {
    const cb = e.target;
    if (!cb.classList.contains('fileChk')) return;
    const name = cb.dataset.name;
    if (cb.checked) state.selected.add(name); else state.selected.delete(name);
    $('#selCount').textContent = `已选 ${state.selected.size} / ${state.files.length} 个文件`;
    renderChips();
  });
  // 拖拽上传
  const dz = $('#dropzone'), fi = $('#fileInput');
  dz.addEventListener('click', () => fi.click());
  fi.addEventListener('change', () => { uploadFiles(fi.files); fi.value = ''; });
  ['dragover', 'dragenter'].forEach((ev) => dz.addEventListener(ev, (e) => {
    e.preventDefault(); dz.classList.add('over');
  }));
  ['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, (e) => {
    e.preventDefault(); dz.classList.remove('over');
  }));
  dz.addEventListener('drop', (e) => {
    if (e.dataTransfer && e.dataTransfer.files.length) uploadFiles(e.dataTransfer.files);
  });
  // Esc 关闭模态框
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });
  // 分析人持久化
  const savedOp = localStorage.getItem('irlog-operator');
  if (savedOp) $('#operator').value = savedOp;
  $('#operator').addEventListener('change', (e) =>
    localStorage.setItem('irlog-operator', e.target.value));

  (async () => {
    try {
      const r = await api('/api/rules');
      state.rules = r.rules || [];
      state.version = r.version || '';
      $('#verLabel').textContent = 'v' + state.version;
      $('#connDot').classList.add('ok');
      $('#connText').textContent = '已连接';
      const sel = $('#rulesSelect');
      sel.innerHTML = '<option value="all">全部规则</option>' +
        state.rules.map((x) => `<option value="${esc(x.id)}">${esc(x.title)}（${esc(x.id)}）</option>`).join('');
      $('#evdirLabel').textContent = '';
    } catch (e) {
      $('#connText').textContent = '服务未连接';
      toast('无法连接服务: ' + e.message, 'err');
    }
    await refreshFiles();
    await refreshIOC();
  })();
}

document.addEventListener('DOMContentLoaded', init);
