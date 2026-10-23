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
  if (name === 'types') renderTypes();
  if (name === 'rules') refreshRules();
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

function copyText(txt, btn) {
  const done = () => {
    if (!btn) return;
    const o = btn.innerText; btn.innerText = '已复制';
    setTimeout(() => { btn.innerText = o; }, 1500);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(txt).then(done, () => fbCopy(txt, done));
  } else { fbCopy(txt, done); }
}
function fbCopy(txt, cb) {
  const ta = document.createElement('textarea');
  ta.value = txt; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select();
  try { document.execCommand('copy'); cb && cb(); } catch (e) {}
  document.body.removeChild(ta);
}

function playbookHtml(a) {
  const pb = a.playbook;
  if (!pb || !pb.stages || !pb.stages.length) return '';
  const plats = (pb.platform_labels || []).join(' / ');
  let miss = '';
  if (pb.missing_vars && pb.missing_vars.length) {
    miss = `<div class="pb-miss">⚠ 命令中的 ${pb.missing_vars.map((m) => '&lt;' + esc(m) + '&gt;').join('、')} 未能从日志自动取到，请按现场情况替换后再执行。</div>`;
  }
  const stages = pb.stages.map((st, si) => {
    const cmds = st.cmds.map((c, ci) => {
      const id = `cmd-${a.rule_id}-${si}-${ci}`;
      const pf = c.platform ? `<span class="pf">${esc(c.platform)}</span>` : '';
      const note = c.note ? `<div class="note">${esc(c.note)}</div>` : '';
      return `<div class="cmd">${pf}<div style="flex:1"><pre id="${id}">${esc(c.cmd)}</pre>${note}</div>` +
             `<button onclick="copyText(document.getElementById('${id}').innerText, this)">复制</button></div>`;
    }).join('');
    return `<div class="pb-stage"><div class="st-t">${esc(st.label)}</div>` +
           `<div class="st-h">${esc(st.hint || '')}</div>${cmds}</div>`;
  }).join('');
  return `<div class="pb"><div class="pb-h">🚨 应急响应处置剧本` +
         (plats ? `<span class="plats">适用平台: ${esc(plats)}</span>` : '') + `</div>${miss}${stages}</div>`;
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
      ${playbookHtml(a)}
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
  const btnPb = $('#btnPlaybook');
  if (btnPb) btnPb.style.display = (state.current?.report_playbook) ? '' : 'none';
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

function downloadPlaybook() {
  const runId = state.current?.run_id;
  if (!runId) { toast('没有可下载的处置手册', 'err'); return; }
  window.open(`/api/report/${encodeURIComponent(runId)}?format=playbook`, '_blank');
  toast('处置手册已在新标签页打开，可直接打印或转发', 'ok');
}

function exportFiltered() {  const list = filteredAlerts();
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

/* ---------- 类型分析 ---------- */
function renderTypes() {
  const d = state.current;
  const box = $('#typeReports');
  const corrBox = $('#correlationView');
  if (!d) {
    box.innerHTML = '<div class="empty"><span class="big">🧩</span>尚未运行分析。前往「分析中心」开始，或在「报告中心」载入历史结果。</div>';
    corrBox.innerHTML = '';
    $('#typePill').style.display = 'none';
    return;
  }
  const reports = d.type_reports || [];
  $('#typePill').style.display = reports.length ? 'inline-block' : 'none';
  $('#typePill').textContent = reports.length;
  box.innerHTML = reports.length ? reports.map(typeReportCard).join('')
    : '<div class="hint">未识别到已知类型的日志（仅有通用日志）。</div>';
  renderCorrelation(d.correlation || {});
}

function typeReportCard(r) {
  const kpis = (r.kpis || []).map((k) => `
    <div class="kpi ${k.tone === 'bad' ? 'bad' : k.tone === 'warn' ? 'warn' : k.tone === 'good' ? 'good' : ''}">
      <b>${fmtNum(k.value)}</b><span>${esc(k.label)}</span></div>`).join('');
  const concl = (r.conclusions || []).map((c) => `<div class="concl">${esc(c)}</div>`).join('');
  const hint = r.export_hint ? `<div class="export-hint">📌 此类日志取证导出方式：\n${esc(r.export_hint)}</div>` : '';
  return `<div class="type-card" style="border-left-color:${esc(r.color)}">
    <div class="tc-head">
      <span class="tc-name">${esc(r.name)}</span>
      <span class="tc-tag" style="background:${esc(r.color)}">${esc(r.short)}</span>
      <span class="tc-q">${esc(r.question)}</span>
      <span class="tc-q">告警 ${r.alert_count} 条 · 事件 ${fmtNum(r.events)}</span>
    </div>
    <div class="kpi-row">${kpis || '<span class="hint">（无统计）</span>'}</div>
    ${concl || '<div class="hint">（未生成结论）</div>'}
    ${hint}
  </div>`;
}

function renderCorrelation(corr) {
  const box = $('#correlationView');
  if (!corr || !Object.keys(corr).length) { box.innerHTML = '<div class="hint">无关联数据。</div>'; return; }
  let s = '';
  const concls = corr.conclusions || [];
  if (concls.length) {
    s += '<div style="margin-bottom:6px"><b>关联结论</b></div>';
    s += concls.map((c) => `<div class="corr-item"><span class="corr-lvl ${esc(c.level)}">${esc((c.level || '').toUpperCase())}</span>${esc(c.text)}</div>`).join('');
  }
  const ips = corr.ip_profiles || [];
  if (ips.length) {
    s += '<div style="margin:12px 0 6px"><b>统一攻击者 IP 画像</b></div>';
    s += `<table class="grid"><thead><tr><th>IP</th><th>风险</th><th>涉及类型</th><th>Web攻击</th><th>Win失败/成功</th><th>Linux失败/成功</th><th>DB风险</th><th>活跃时段</th></tr></thead><tbody>`
       + ips.map((p) => `<tr><td class="mono">${esc(p.ip)}</td>
          <td><span class="badge sev${p.risk === 'critical' ? 1 : p.risk === 'high' ? 2 : p.risk === 'medium' ? 3 : 4}">${esc(p.risk)}</span></td>
          <td>${esc((p.types || []).join('/'))}</td>
          <td>${fmtNum(p.web_attacks)}</td>
          <td>${fmtNum(p.win_fail)}/${fmtNum(p.win_ok)}</td>
          <td>${fmtNum(p.linux_fail)}/${fmtNum(p.linux_ok)}</td>
          <td>${fmtNum(p.db_risky)}</td>
          <td class="mono nowrap">${esc(p.first || '-')} ~ ${esc(p.last || '-')}</td></tr>`).join('')
       + '</tbody></table>';
  }
  const iocs = corr.iocs || {};
  const iocParts = [];
  if ((iocs.attack_ips || []).length) iocParts.push(iocBlock('攻击来源 IP', iocs.attack_ips));
  if ((iocs.target_accounts || []).length) iocParts.push(iocBlock('目标账号', iocs.target_accounts));
  if ((iocs.sensitive_paths || []).length) iocParts.push(iocBlock('敏感路径 / webshell', iocs.sensitive_paths));
  if ((iocs.risky_sql || []).length) iocParts.push(iocBlock('可疑 SQL 片段', iocs.risky_sql));
  if ((iocs.suspicious_commands || []).length) iocParts.push(iocBlock('可疑命令', iocs.suspicious_commands));
  if (iocParts.length) s += `<div style="margin:12px 0 6px"><b>全局 IOC 情报清单</b></div>` + iocParts.join('');
  const tl = corr.timeline || [];
  if (tl.length) {
    s += `<div style="margin:12px 0 6px"><b>跨源告警时间线（按时间）</b></div>`;
    s += `<table class="grid"><thead><tr><th>时间</th><th>来源IP</th><th>级别</th><th>规则</th><th>标题</th></tr></thead><tbody>`
       + tl.map((a) => `<tr><td class="mono nowrap">${esc(a.time || '-')}</td><td class="mono">${esc(a.ip || '')}</td>
          <td><span class="badge sev${a.severity}">${esc(a.severity_label || a.severity)}</span></td>
          <td>${esc(a.rule || '')}</td><td>${esc(a.title || '')}</td></tr>`).join('')
       + '</tbody></table>';
  }
  box.innerHTML = s || '<div class="hint">无关联数据。</div>';
}

function iocBlock(title, arr) {
  if (!arr || !arr.length) return '';
  return `<div><b>${esc(title)}（${arr.length}）</b><div class="ioc-box">${esc(arr.join('\n'))}</div></div>`;
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

/* ---------- 规则库 ---------- */
const RULE_STATE = { data: null, builtin: [] };

async function refreshRules() {
  try {
    const r = await api('/api/rulepack');
    RULE_STATE.data = r;
    RULE_STATE.builtin = r.builtin || [];
    $('#ruleMeta').textContent =
      `自定义规则 ${r.custom_count || 0} 条 · 附加特征 ${r.attachment_count || 0} 条`
      + (r.updated ? ` · 更新于 ${r.updated}` : '');
    renderRules();
    renderBuiltin();
  } catch (e) { toast('获取规则库失败: ' + e.message, 'err'); }
}

function renderRules() {
  const r = RULE_STATE.data;
  const tb = $('#ruleTable tbody');
  if (!r) { tb.innerHTML = '<tr><td colspan="8" class="hint">加载中…</td></tr>'; return; }
  const q = ($('#ruleSearch').value || '').trim().toLowerCase();
  const items = (r.custom || []).filter((c) => {
    if (!q) return true;
    const hay = (c.rule_id + ' ' + c.title + ' ' + (c.attaches_to || '') + ' '
      + (c.patterns || []).map((p) => p.value).join(' ')).toLowerCase();
    return hay.includes(q);
  });
  if (!items.length) {
    tb.innerHTML = '<tr><td colspan="8" class="empty"><span class="big">📚</span>暂无自定义规则。点击「新建规则」给自己环境追加特征，或给内置规则加 payload。</td></tr>';
    return;
  }
  tb.innerHTML = items.map((c) => {
    const attached = c.attaches_to ? `→ ${esc(c.attaches_to)}` : '独立分类';
    const sevl = c.severity;
    return `<tr>
      <td class="mono">${esc(c.rule_id)}</td>
      <td>${esc(c.title)}</td>
      <td><span class="badge sev${sevl}">${esc(SEV[sevl] || sevl)}</span></td>
      <td>${esc(attached)}</td>
      <td>${esc(c.scope || 'all')}</td>
      <td>${(c.patterns || []).length}</td>
      <td>${c.enabled ? '<span style="color:#27ae60">启用</span>' : '<span style="color:#b9770e">停用</span>'}</td>
      <td class="actions">
        <button class="small" onclick="openRuleEditor('${esc(c.rule_id)}')">编辑</button>
        <button class="small danger" onclick="deleteRule('${esc(c.rule_id)}')">删除</button>
      </td></tr>`;
  }).join('');
}

function renderBuiltin() {
  const box = $('#builtinRules');
  const list = RULE_STATE.builtin || [];
  if (!list.length) { box.innerHTML = '<div class="hint">（无）</div>'; return; }
  box.innerHTML = list.map((b) => {
    const pats = (b.patterns || []).map((p) =>
      `<tr><td class="mono">${(p.kind === 'regex' ? '正则' : '关键字')}</td>
        <td class="mono" style="word-break:break-all">${esc(p.value)}</td>
        <td class="hint">${esc(p.note || '')}</td></tr>`).join('');
    return `<details><summary><b>${esc(b.title)}</b> <span class="mono">(${esc(b.rule_id)})</span>`
      + `${b.mitre ? ` · <span class="tag-mitre">${esc(b.mitre)}</span>` : ''}</summary>
      <div style="margin:6px 0" class="hint">${esc(b.description || '')}</div>
      ${pats ? `<table class="grid"><thead><tr><th>类型</th><th>特征</th><th>说明</th></tr></thead><tbody>${pats}</tbody></table>` : ''}
      <div style="margin-top:6px">
        <button class="small" onclick="attachToBuiltin('${esc(b.rule_id)}','${esc(b.title)}')">＋ 给这条规则加 payload</button>
      </div>
    </details>`;
  }).join('');
}

function attachToBuiltin(id, title) {
  openRuleEditor(null, { attaches_to: id, title: '自定义 ' + title + ' payload', scope: 'all' });
}

function openRuleEditor(id, preset) {
  const data = RULE_STATE.data || { custom: [] };
  const rule = (data.custom || []).find((c) => c.rule_id === id) || (preset || {});
  const isEdit = !!id;
  const builtinIds = (RULE_STATE.builtin || []).map((b) => b.rule_id);
  const pats = (rule.patterns || []).map((p) => patRow(p)).join('');
  const builtinOpts = '<option value="">（独立的新规则分类）</option>'
    + builtinIds.map((b) => `<option value="${esc(b)}" ${rule.attaches_to === b ? 'selected' : ''}>${esc(b)}</option>`).join('');
  const sevOpts = [1, 2, 3, 4].map((s) =>
    `<option value="${s}" ${Number(rule.severity) === s ? 'selected' : ''}>${SEV[s]}（${s}）</option>`).join('');
  const scopeOpts = [['all', '全部字段'], ['uri', 'Web URI'], ['body', 'HTTP 请求体'],
    ['process', '进程/命令行'], ['raw', '原始日志行'], ['fields', '结构化字段']]
    .map(([v, l]) => `<option value="${v}" ${rule.scope === v ? 'selected' : ''}>${esc(l)}</option>`).join('');
  const body = `<form id="ruleForm" class="rule-form">
    <input type="hidden" id="rf_id_old" value="${esc(id || '')}">
    <label class="field">规则 ID（小写字母/数字/连字符，2-49 字符）
      <input id="rf_ruleid" value="${esc(rule.rule_id || '')}" ${isEdit ? 'readonly style="background:#f0f3f5"' : ''} placeholder="my-custom-rule"></label>
    <label class="field">规则名称 <input id="rf_title" value="${esc(rule.title || '')}" placeholder="如：某业务后台路径"></label>
    <label class="field">严重度 <select id="rf_sev">${sevOpts}</select></label>
    <label class="field">归属内置规则（留空=独立分类）
      <select id="rf_attach">${builtinOpts}</select></label>
    <label class="field">匹配范围 <select id="rf_scope">${scopeOpts}</select></label>
    <label class="field" style="flex:1;min-width:260px">描述
      <textarea id="rf_desc" rows="2" placeholder="这条规则想抓什么">${esc(rule.description || '')}</textarea></label>
    <label class="field">MITRE ATT&CK <input id="rf_mitre" value="${esc(rule.mitre || '')}" placeholder="如 T1190"></label>
    <label class="field" style="flex:1;min-width:260px">处置建议
      <textarea id="rf_rec" rows="2">${esc(rule.recommendation || '')}</textarea></label>
    <label class="field" style="display:flex;align-items:center;gap:6px"><input type="checkbox" id="rf_enabled" ${rule.enabled !== false ? 'checked' : ''}> 启用此规则</label>
    <div style="flex-basis:100%"><b>匹配特征</b>
      <div id="patList">${pats || patRow({})}</div>
      <button type="button" class="ghost small" onclick="addPatRow()">＋ 添加特征</button>
    </div>
    <div style="flex-basis:100%" class="row">
      <button type="button" onclick="testRule()">🔍 试测特征</button>
      <span id="rfTest" class="hint"></span>
      <span class="spacer"></span>
      <button type="button" class="ghost" onclick="closeModal()">取消</button>
      <button type="button" onclick="saveRule()">💾 保存</button>
    </div>
  </form>`;
  openModal(isEdit ? '编辑规则 · ' + id : '新建规则', body);
}

function patRow(p) {
  p = p || {};
  return `<div class="pat-row">
    <select class="pat-kind">
      <option value="keyword" ${p.kind === 'keyword' ? 'selected' : ''}>关键字</option>
      <option value="regex" ${p.kind === 'regex' ? 'selected' : ''}>正则</option>
    </select>
    <input class="pat-val" placeholder="特征内容" value="${esc(p.value || '')}">
    <input class="pat-note" placeholder="说明（可选）" value="${esc(p.note || '')}">
    <button type="button" class="small danger" onclick="this.closest('.pat-row').remove()">✕</button>
  </div>`;
}
function addPatRow() { $('#patList').insertAdjacentHTML('beforeend', patRow({})); }

function collectRuleForm() {
  const oldId = $('#rf_id_old').value;
  const rule_id = ($('#rf_ruleid').value || '').trim();
  const patterns = [...document.querySelectorAll('#patList .pat-row')].map((row, i) => ({
    id: 'p' + (i + 1),
    kind: row.querySelector('.pat-kind').value,
    value: row.querySelector('.pat-val').value,
    note: row.querySelector('.pat-note').value,
    enabled: true,
  })).filter((p) => p.value.trim());
  return {
    _old_id: oldId,
    rule_id,
    title: ($('#rf_title').value || '').trim(),
    severity: Number($('#rf_sev').value),
    attaches_to: ($('#rf_attach').value || '').trim(),
    scope: $('#rf_scope').value,
    description: ($('#rf_desc').value || '').trim(),
    mitre: ($('#rf_mitre').value || '').trim(),
    recommendation: ($('#rf_rec').value || '').trim(),
    enabled: $('#rf_enabled').checked,
    patterns,
  };
}

async function saveRule() {
  const body = collectRuleForm();
  try {
    const r = await api('/api/rulepack', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    toast('已保存规则 ' + r.rule_id, 'ok');
    closeModal();
    await refreshRules();
  } catch (e) { toast('保存失败: ' + e.message, 'err'); }
}

async function deleteRule(id) {
  if (!confirm('确认删除规则「' + id + '」？此操作会记入审计日志。')) return;
  try {
    const r = await api('/api/rulepack?name=' + encodeURIComponent(id), { method: 'DELETE' });
    toast('已删除 ' + r.deleted, 'ok');
    await refreshRules();
  } catch (e) { toast('删除失败: ' + e.message, 'err'); }
}

async function testRule() {
  const rule = collectRuleForm();
  const text = prompt('粘贴一段要试测的原始日志文本：');
  if (text == null) return;
  try {
    const r = await api('/api/rulepack/test', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rule, text }),
    });
    $('#rfTest').textContent = r.matched
      ? '✅ 命中：' + (r.results.find((x) => x.ok)?.match || '')
      : '❌ 未命中任何特征';
    $('#rfTest').style.color = r.matched ? '#27ae60' : '#b9770e';
  } catch (e) { toast('试测失败: ' + e.message, 'err'); }
}

function exportRules() {
  window.open('/api/rulepack/export', '_blank');
}

async function importRulesFile(input) {
  const f = input.files && input.files[0];
  if (!f) return;
  const text = await f.text();
  const mode = confirm('选择导入方式：\n确定 = 合并（同 ID 覆盖，新 ID 追加）\n取消 = 整体替换（先备份现有规则库）')
    ? 'merge' : 'replace';
  try {
    const r = await api('/api/rulepack/import', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode, content: text }),
    });
    toast(`已导入 ${r.rules} 条规则（共 ${r.total} 条）`, 'ok');
    await refreshRules();
  } catch (e) { toast('导入失败: ' + e.message, 'err'); }
  input.value = '';
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
  renderTypes();
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
