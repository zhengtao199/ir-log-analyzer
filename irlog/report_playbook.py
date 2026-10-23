"""独立《应急响应处置手册》生成（HTML + Markdown）。

与主报告的区别：主报告是「给分析人看的全量结果」，本手册只保留**要动手的部分**——
按严重度排序的处置命令，可直接打印或转发给一线处置人员。
"""
from __future__ import annotations

from .models import SEVERITY_LABELS
from .report_html import CSS, SEV_COLORS, esc
from .respond import playbook_markdown

EXTRA_CSS = """
@media print { .no-print { display: none !important; } body { background: #fff; }
               .card { box-shadow: none; border: 1px solid #ddd; page-break-inside: avoid; } }
.pb-item { page-break-inside: avoid; }
.pb-item > .hd { display: flex; gap: 10px; align-items: center; flex-wrap: wrap;
                 border-bottom: 2px solid #eef2f5; padding-bottom: 8px; margin-bottom: 8px; }
.pb-item > .hd .t { font-size: 15px; font-weight: 700; }
.pb-item > .hd .m { margin-left: auto; font-size: 12px; color: #7f8c8d; }
.pb-ent { font-size: 12px; color: #566573; background: #f7f9fa; border-radius: 6px;
          padding: 6px 10px; margin: 6px 0; }
.pb-notice { background: #fef9e7; border-left: 4px solid #f39c12; padding: 10px 14px;
             border-radius: 0 8px 8px 0; font-size: 13px; margin-bottom: 14px; }
"""


def build_playbook_html(result, custody: dict) -> str:
    d = result.to_dict()
    alerts = d["alerts"]
    case_id = custody.get("case_id") or result.run_id

    urgent = [a for a in alerts if a["severity"] == 1]
    high = [a for a in alerts if a["severity"] == 2]
    rest = [a for a in alerts if a["severity"] >= 3]

    def _ent(a) -> str:
        ent = "；".join(
            f"{k}={v if not isinstance(v, (list, set)) else ','.join(map(str, v))}"
            for k, v in (a.get("entities") or {}).items()
        )
        return f'<div class="pb-ent"><b>关联实体：</b>{esc(ent) or "-"}</div>'

    def _item(a, idx: int) -> str:
        pb = a.get("playbook") or {}
        plats = " / ".join(pb.get("platform_labels") or [])
        miss = ""
        if pb.get("missing_vars"):
            tips = "、".join(f"&lt;{esc(m)}&gt;" for m in pb["missing_vars"])
            miss = f'<div class="pb-miss" style="font-size:12px;color:#b9770e">' \
                   f'⚠ {tips} 需按现场情况替换</div>'
        stages = []
        for st in pb.get("stages", []):
            cmds = []
            for j, c in enumerate(st["cmds"]):
                cid = f"p-{idx}-{st['key']}-{j}"
                pf = f'<span class="pf">{esc(c.get("platform", ""))}</span>' if c.get("platform") else ""
                note = f'<div class="note">{esc(c.get("note", ""))}</div>' if c.get("note") else ""
                cmds.append(
                    f'<div class="cmd">{pf}<div style="flex:1">'
                    f'<pre id="{cid}">{esc(c["cmd"])}</pre>{note}</div>'
                    f'<button class="no-print" onclick="copyCmd(this, \'{cid}\')">复制</button></div>')
            stages.append(
                f'<div class="pb-stage"><div class="st-t">{esc(st["label"])}</div>'
                f'<div class="st-h">{esc(st.get("hint", ""))}</div>{"".join(cmds)}</div>')
        return (f'<div class="pb-item card"><div class="hd">'
                f'<span class="badge" style="background:{SEV_COLORS.get(a["severity"], "#333")}">'
                f'{esc(a["severity_label"])}</span>'
                f'<span class="t">{idx}. {esc(a["title"])}</span>'
                f'<span class="m">{esc(a.get("first_time") or "")} ~ {esc(a.get("last_time") or "")}'
                f' · {a["count"]} 次 · {esc(plats)}</span></div>'
                f'<div class="kv"><b>规则:</b> {esc(a["rule_id"])} '
                f'&nbsp; <b>ATT&CK:</b> <span class="mitre">{esc(a.get("mitre") or "-")}</span></div>'
                f'<div class="kv"><b>说明:</b> {esc(a.get("description") or "-")}</div>'
                f'{_ent(a)}{miss}{"".join(stages) or "<div class=kv>（无处置命令）</div>"}</div>')

    def _group(title: str, items: list, start: int) -> str:
        if not items:
            return ""
        body = "".join(_item(a, start + i) for i, a in enumerate(items))
        return (f'<div class="card"><h2>{esc(title)}（{len(items)} 条）</h2>{body}</div>')

    if not alerts:
        body = '<div class="card"><div class="kv">未触发任何检测规则，无需处置。</div></div>'
    else:
        body = (_group("🔴 立即处置（紧急）", urgent, 1)
                + _group("🟠 尽快处置（高危）", high, len(urgent) + 1)
                + _group("🔵 核查后处置（中低危）", rest, len(urgent) + len(high) + 1))

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>应急响应处置手册 - {esc(case_id)}</title>
<style>{CSS}{EXTRA_CSS}</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>应急响应处置手册</h1>
  <div class="meta">
    <span>案件编号: <b>{esc(case_id)}</b></span>
    <span>生成时间: {esc(d['finished'])}</span>
    <span>分析人: {esc(custody.get('operator', '-'))}</span>
    <span>告警: 紧急 {len(urgent)} / 高危 {len(high)} / 中低危 {len(rest)}</span>
  </div>
</header>

<div class="pb-notice">
  <b>使用说明：</b>本手册中的命令<b>由处置人员复制后自行执行</b>，分析工具本身不执行任何命令、
  不对目标主机做任何写操作。命令已按告警实体自动回填 IP/账号/主机等值；
  标注 <b>&lt;尖括号&gt;</b> 的部分表示日志中未能自动取到，请按现场情况替换后再执行。<br>
  <b>执行顺序：</b>先「核查确认」排除误报 → 再「遏止血」限制影响面 → 「证据固定」留存易失证据 →
  最后「根除恢复」。除勒索扩散外，不要一上来就关机，内存和进程线索会随断电丢失。
</div>

{body}

<footer>
  本手册由 ir-log-analyzer 自动生成 · 原始证据全程只读，未做任何修改 · 证据完整性以 SHA256 为准<br>
  生成时间: {esc(d['finished'])}
</footer>
</div>
<script>{_JS}</script>
</body>
</html>"""


_JS = """
function copyCmd(btn, id) {
  var txt = document.getElementById(id).innerText;
  var done = function () { var o = btn.innerText; btn.innerText = '已复制';
                           setTimeout(function () { btn.innerText = o; }, 1500); };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(txt).then(done, function () { fb(txt, done); });
  } else { fb(txt, done); }
}
function fb(txt, cb) {
  var ta = document.createElement('textarea');
  ta.value = txt; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select();
  try { document.execCommand('copy'); cb && cb(); } catch (e) {}
  document.body.removeChild(ta);
}
"""


def write_playbook_html(path: str, result, custody: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_playbook_html(result, custody))


def write_playbook_markdown(path: str, result) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(playbook_markdown(result))
