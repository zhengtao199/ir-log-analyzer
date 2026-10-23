"""自包含 HTML 应急响应报告（零外部依赖，可离线打开/分发）。

结构：案件信息 -> 证据链（SHA256） -> 态势概览 -> 告警明细（可展开证据）
-> 时间线（小时直方图 + 事件表）-> 错误与跳过 -> 页脚完整性声明。
所有日志原文均经 HTML 转义后嵌入，防 XSS。
"""
from __future__ import annotations

import html
import json
import time

from .models import SEVERITY_LABELS

SEV_COLORS = {1: "#c0392b", 2: "#e67e22", 3: "#2980b9", 4: "#7f8c8d"}
SEV_BG = {1: "#fdecea", 2: "#fef5e7", 3: "#ebf5fb", 4: "#f4f6f6"}

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: "Microsoft YaHei", "PingFang SC", "Segoe UI", sans-serif;
       background: #f0f2f5; color: #2c3e50; font-size: 14px; line-height: 1.6; }
.wrap { max-width: 1200px; margin: 0 auto; padding: 24px; }
header { background: linear-gradient(135deg, #1a5276, #2874a6); color: #fff;
         border-radius: 10px; padding: 28px 32px; margin-bottom: 20px; }
header h1 { font-size: 24px; margin-bottom: 8px; }
header .meta { display: flex; flex-wrap: wrap; gap: 18px; font-size: 13px; opacity: .92; }
.card { background: #fff; border-radius: 10px; padding: 22px 26px; margin-bottom: 18px;
        box-shadow: 0 1px 3px rgba(0,0,0,.08); }
.card h2 { font-size: 17px; border-left: 4px solid #2874a6; padding-left: 10px; margin-bottom: 14px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { border: 1px solid #e1e8ed; padding: 7px 10px; text-align: left; vertical-align: top; }
th { background: #f7f9fa; font-weight: 600; white-space: nowrap; }
tr:hover td { background: #fafbfc; }
.badge { display: inline-block; padding: 1px 10px; border-radius: 10px; color: #fff;
         font-size: 12px; white-space: nowrap; }
.stat-row { display: flex; flex-wrap: wrap; gap: 14px; margin-bottom: 6px; }
.stat { flex: 1; min-width: 130px; background: #f7f9fa; border-radius: 8px; padding: 12px 16px; }
.stat .num { font-size: 24px; font-weight: 700; }
.stat .lbl { font-size: 12px; color: #7f8c8d; }
.bar-row { display: flex; align-items: center; gap: 8px; margin: 3px 0; }
.bar-row .h { width: 110px; font-size: 12px; color: #566573; text-align: right; flex-shrink: 0; }
.bar-row .track { flex: 1; background: #eef2f5; border-radius: 4px; height: 16px; overflow: hidden; }
.bar-row .fill { height: 100%; background: #2874a6; border-radius: 4px; }
.bar-row .v { width: 56px; font-size: 12px; color: #566573; }
details { margin: 8px 0; border: 1px solid #e1e8ed; border-radius: 8px; }
details summary { cursor: pointer; padding: 10px 14px; background: #f7f9fa; border-radius: 8px;
                  display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
details[open] summary { border-radius: 8px 8px 0 0; }
details .body { padding: 12px 16px; }
.ev { font-family: Consolas, "Courier New", monospace; font-size: 12px; background: #fbfcfd;
      border: 1px solid #edf1f4; border-radius: 6px; padding: 8px 10px; margin: 6px 0;
      white-space: pre-wrap; word-break: break-all; }
.kv { font-size: 13px; margin: 4px 0; }
.kv b { color: #1a5276; }
.rec { background: #eafaf1; border-left: 4px solid #27ae60; padding: 10px 14px;
       border-radius: 0 8px 8px 0; margin-top: 8px; font-size: 13px; }
.mitre { display: inline-block; background: #f4ecf7; color: #6c3483; border-radius: 4px;
         padding: 1px 8px; font-size: 12px; }
.filters { margin-bottom: 12px; display: flex; gap: 8px; flex-wrap: wrap; }
.filters button { border: 1px solid #d5dbdb; background: #fff; border-radius: 16px;
                  padding: 4px 14px; font-size: 13px; cursor: pointer; }
.filters button.active { background: #2874a6; color: #fff; border-color: #2874a6; }
footer { text-align: center; color: #95a5a6; font-size: 12px; padding: 18px; }
.mono { font-family: Consolas, monospace; font-size: 12px; }
.hash { max-width: 340px; overflow: hidden; text-overflow: ellipsis; }
/* ---- 处置剧本 ---- */
.pb { margin-top: 12px; border: 1px solid #d6eaf8; border-radius: 8px; overflow: hidden; }
.pb-h { background: #ebf5fb; padding: 8px 14px; font-size: 13px; font-weight: 600;
        color: #1a5276; display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.pb-h .plats { font-weight: 400; font-size: 12px; color: #2874a6; }
.pb-stage { border-top: 1px solid #e8f1f8; padding: 10px 14px; }
.pb-stage > .st-t { font-weight: 600; font-size: 13px; color: #1a5276; }
.pb-stage > .st-h { font-size: 12px; color: #7f8c8d; margin: 2px 0 8px; }
.cmd { display: flex; gap: 8px; align-items: flex-start; margin: 6px 0;
       background: #fbfcfd; border: 1px solid #edf1f4; border-radius: 6px; padding: 8px 10px; }
.cmd pre { flex: 1; font-family: Consolas, "Courier New", monospace; font-size: 12px;
           white-space: pre-wrap; word-break: break-all; margin: 0; color: #1b2631; }
.cmd .note { font-size: 12px; color: #566573; margin-top: 4px; }
.cmd button { flex-shrink: 0; border: 1px solid #aed6f1; background: #fff; color: #1a5276;
              border-radius: 4px; padding: 3px 9px; font-size: 12px; cursor: pointer; }
.cmd button:hover { background: #ebf5fb; }
.cmd .pf { font-size: 11px; color: #95a5a6; border: 1px solid #e1e8ed; border-radius: 3px;
           padding: 0 5px; margin-right: 4px; }
.pb-miss { font-size: 12px; color: #b9770e; background: #fef9e7; border-radius: 4px;
           padding: 4px 10px; margin: 6px 14px 10px; }
"""

JS = """
function filterAlerts(sev, btn) {
  document.querySelectorAll('.filters button').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('details.alert').forEach(d => {
    d.style.display = (sev === 'all' || d.dataset.sev === String(sev)) ? '' : 'none';
  });
}
function copyCmd(btn, id) {
  var txt = document.getElementById(id).innerText;
  var done = function () {
    var old = btn.innerText; btn.innerText = '已复制';
    setTimeout(function () { btn.innerText = old; }, 1500);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(txt).then(done, function () { fallbackCopy(txt, done); });
  } else { fallbackCopy(txt, done); }
}
function fallbackCopy(txt, cb) {
  var ta = document.createElement('textarea');
  ta.value = txt; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select();
  try { document.execCommand('copy'); cb && cb(); } catch (e) {}
  document.body.removeChild(ta);
}
"""


def esc(s) -> str:
    return html.escape("" if s is None else str(s), quote=True)


def _basename(path: str) -> str:
    """跨平台取文件名（同时兼容 Windows 反斜杠与 Unix 斜杠）。"""
    return str(path or "").replace("\\", "/").rsplit("/", 1)[-1]


def _fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{unit}" if unit != "B" else f"{n}B"
        n /= 1024
    return f"{n:.1f}TB"


def _playbook_html(pb: dict, idx: int) -> str:
    """把一条告警的四阶段处置剧本渲染成 HTML（命令可一键复制）。"""
    if not pb or not pb.get("stages"):
        return ""
    plats = " / ".join(pb.get("platform_labels") or [])
    parts = [f'<div class="pb"><div class="pb-h">🚨 应急响应处置剧本'
             f'<span class="plats">适用平台: {esc(plats)}</span></div>']
    if pb.get("missing_vars"):
        tips = "、".join(f"&lt;{esc(m)}&gt;" for m in pb["missing_vars"])
        parts.append(f'<div class="pb-miss">⚠ 命令中的 {tips} 未能从日志中自动取到，'
                     f'请按现场实际情况替换后再执行。</div>')
    for st in pb["stages"]:
        parts.append(f'<div class="pb-stage"><div class="st-t">{esc(st["label"])}</div>'
                     f'<div class="st-h">{esc(st.get("hint", ""))}</div>')
        for j, c in enumerate(st["cmds"]):
            cid = f"cmd-{idx}-{st['key']}-{j}"
            pf = f'<span class="pf">{esc(c.get("platform", ""))}</span>' if c.get("platform") else ""
            note = f'<div class="note">{esc(c.get("note", ""))}</div>' if c.get("note") else ""
            parts.append(
                f'<div class="cmd">{pf}<div style="flex:1">'
                f'<pre id="{cid}">{esc(c["cmd"])}</pre>{note}</div>'
                f'<button onclick="copyCmd(this, \'{cid}\')">复制</button></div>')
        parts.append('</div>')
    parts.append('</div>')
    return "".join(parts)


def build_html(result, custody: dict) -> str:
    d = result.to_dict()
    alerts = d["alerts"]
    hist = result.timeline.get("hour_histogram", {})
    max_cnt = max(hist.values()) if hist else 1
    case_id = custody.get("case_id") or result.run_id

    sev_sum = result.severity_summary()
    sev_cards = "".join(
        f'<div class="stat"><div class="num" style="color:{SEV_COLORS.get(s, "#333")}">{sev_sum.get(s, 0)}</div>'
        f'<div class="lbl">{SEVERITY_LABELS.get(s, s)}告警</div></div>'
        for s in (1, 2, 3, 4)
    )

    # 证据链表
    ev_rows = "".join(
        f"<tr><td class='mono'>{esc(i['path'])}</td>"
        f"<td>{esc(i.get('log_type') or '-')}</td>"
        f"<td>{_fmt_size(i['size'])}</td>"
        f"<td class='mono hash' title='{esc(i['sha256'])}'>{esc(i['sha256'])}</td>"
        f"<td class='mono'>{esc(i['mtime_iso'])}</td></tr>"
        for i in custody.get("evidence", {}).get("items", [])
    )

    # 文件处理结果表
    file_rows = "".join(
        f"<tr><td class='mono'>{esc(f['path'])}</td><td>{esc(f.get('log_type') or '-')}</td>"
        f"<td>{f['events']}</td><td>{esc(f.get('skipped_reason') or '')}</td></tr>"
        for f in d["files"]
    )

    # 告警明细
    alert_blocks = []
    for idx, a in enumerate(alerts):
        sev = a["severity"]
        ent = " ".join(
            f"<span class='kv'><b>{esc(k)}:</b> {esc(v if not isinstance(v, (list, set)) else ', '.join(map(str, v)))}</span>"
            for k, v in a["entities"].items()
        )
        ev_html = "".join(
            f"<div class='ev'>[{esc(e['time'] or '?')}] ({esc(_basename(e['source']))})\n{esc(e['raw'])}</div>"
            for e in a["evidence"]
        )
        pb_html = _playbook_html(a.get("playbook"), idx)
        alert_blocks.append(f"""
<details class="alert" data-sev="{sev}">
  <summary>
    <span class="badge" style="background:{SEV_COLORS.get(sev, '#333')}">{esc(a['severity_label'])}</span>
    <b>{esc(a['title'])}</b>
    <span style="color:#566573">{esc(a['description'][:120])}</span>
    <span style="margin-left:auto;color:#7f8c8d;font-size:12px">{esc(a['first_time'] or '')} ~ {esc(a['last_time'] or '')} · {a['count']} 次</span>
  </summary>
  <div class="body">
    <div class="kv"><b>描述:</b> {esc(a['description'])}</div>
    <div class="kv"><b>关联实体:</b> {ent}</div>
    <div class="kv"><b>ATT&CK:</b> <span class="mitre">{esc(a['mitre'])}</span></div>
    <div class="rec"><b>处置建议:</b> {esc(a['recommendation'])}</div>
    {pb_html}
    <div style="margin-top:10px"><b>证据样本（原始日志，只读未改动）:</b></div>
    {ev_html or '<div class="kv">（无采样证据）</div>'}
  </div>
</details>""")

    # 时间线直方图
    bars = "".join(
        f'<div class="bar-row"><div class="h">{esc(h)}</div>'
        f'<div class="track"><div class="fill" style="width:{c * 100 // max_cnt}%"></div></div>'
        f'<div class="v">{c}</div></div>'
        for h, c in list(hist.items())
    )

    stats = d["stats"]
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>应急响应日志分析报告 - {esc(result.run_id)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">

<header>
  <h1>应急响应日志分析报告</h1>
  <div class="meta">
    <span>案件编号: <b>{esc(case_id)}</b></span>
    <span>分析时间: {esc(d['started'])} ~ {esc(d['finished'])}（{d['duration_sec']}s）</span>
    <span>分析人: {esc(custody.get('operator', '-'))}</span>
    <span>工具: {esc(custody.get('tool', '-'))}</span>
  </div>
</header>

<div class="card">
  <h2>一、态势概览</h2>
  <div class="stat-row">
    <div class="stat"><div class="num">{stats.get('total_events', 0):,}</div><div class="lbl">分析事件总数</div></div>
    <div class="stat"><div class="num">{stats.get('total_files', 0)}</div><div class="lbl">证据文件数</div></div>
    <div class="stat"><div class="num" style="color:#c0392b">{stats.get('alert_count', 0)}</div><div class="lbl">告警总数</div></div>
    <div class="stat"><div class="num">{stats.get('ioc_count', 0)}</div><div class="lbl">IOC 条目</div></div>
  </div>
  <div class="stat-row">{sev_cards}</div>
</div>

<div class="card">
  <h2>二、检测告警明细（按严重程度排序）</h2>
  <div class="filters">
    <button class="active" onclick="filterAlerts('all', this)">全部（{len(alerts)}）</button>
    <button onclick="filterAlerts(1, this)">紧急</button>
    <button onclick="filterAlerts(2, this)">高危</button>
    <button onclick="filterAlerts(3, this)">中危</button>
    <button onclick="filterAlerts(4, this)">低危</button>
  </div>
  {''.join(alert_blocks) if alert_blocks else '<div class="kv">未触发任何检测规则。</div>'}
</div>

<div class="card">
  <h2>三、事件时间线（按小时）</h2>
  {bars if bars else '<div class="kv">无带时间戳的事件。</div>'}
</div>

<div class="card">
  <h2>四、证据链信息（Chain of Custody）</h2>
  <div class="kv"><b>完整性说明:</b> {esc(custody.get('evidence_integrity', ''))}</div>
  <div class="kv"><b>分析开始:</b> {esc(custody.get('analysis_started', ''))} &nbsp; <b>分析结束:</b> {esc(custody.get('analysis_finished', ''))}</div>
  <table style="margin-top:10px">
    <tr><th>证据文件</th><th>识别类型</th><th>大小</th><th>SHA256</th><th>修改时间</th></tr>
    {ev_rows}
  </table>
</div>

<div class="card">
  <h2>五、证据文件处理明细</h2>
  <table>
    <tr><th>文件</th><th>解析器</th><th>解析事件数</th><th>跳过/异常原因</th></tr>
    {file_rows}
  </table>
</div>

<footer>
  本报告由 ir-log-analyzer 自动生成 · 原始证据全程只读，未做任何修改 · 证据完整性以 SHA256 为准<br>
  报告生成时间: {esc(time.strftime('%Y-%m-%d %H:%M:%S'))}
</footer>

</div>
<script>{JS}</script>
</body>
</html>"""


def write_html_report(path: str, result, custody: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_html(result, custody))
