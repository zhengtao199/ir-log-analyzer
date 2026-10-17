# -*- coding: utf-8 -*-
"""交互控制台端到端验证脚本（需服务已在 127.0.0.1:8612 启动）。

覆盖：静态资源、规则清单、证据识别、上传、字节保真、文件删除、路径穿越拦截、规则过滤、
阈值覆盖、IOC 增删/载入、历史运行、报告下载、审计留痕。
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

BASE = "http://127.0.0.1:" + (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("IRLOG_PORT", "8611"))
PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASSED = []


def req(method, path, data=None, headers=None, raw=False):
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            body = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            return resp.status, (body if raw else json.loads(body.decode("utf-8"))), ctype
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            return e.code, json.loads(body.decode("utf-8")), ""
        except (json.JSONDecodeError, UnicodeDecodeError):
            return e.code, body.decode("utf-8", "replace"), ""


def check(name, cond, extra=""):
    if cond:
        PASSED.append(name)
        print(f"  ✓ {name} {extra}")
    else:
        print(f"  ✗ FAILED: {name} {extra}")
        sys.exit(1)


def upload(path):
    boundary = uuid.uuid4().hex
    fn = os.path.basename(path)
    with open(path, "rb") as f:
        content = f.read()
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{fn}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return req("POST", "/api/upload", body,
               {"Content-Type": f"multipart/form-data; boundary={boundary}"})


def post_json(path, obj):
    return req("POST", path, json.dumps(obj).encode("utf-8"),
               {"Content-Type": "application/json"})


def resolve_evidence_dir():
    """定位服务端实际使用的证据目录。

    服务可能由源码仓（demo-evidence）或便携包（evidence）启动，写死路径会让
    E2E 在另一种部署形态下误报；而按已有文件名做交集又会被历史残留文件干扰。
    因此改用确定性探针：上传一个唯一命名的文件，再在候选目录中定位它。
    """
    root = os.path.dirname(PROJECT)
    candidates = [
        os.path.join(PROJECT, "demo-evidence"),
        os.path.join(PROJECT, "evidence"),
        os.path.join(root, "ir-log-analyzer-portable", "evidence"),
    ]
    probe = f"e2e_probe_{uuid.uuid4().hex}.log"
    boundary = "----ProbeBoundary"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
            f"filename=\"{probe}\"\r\nContent-Type: text/plain\r\n\r\nprobe\r\n"
            f"--{boundary}--\r\n").encode()
    req("POST", "/api/upload", body,
        {"Content-Type": f"multipart/form-data; boundary={boundary}"})
    for d in candidates:
        p = os.path.join(d, probe)
        if os.path.isfile(p):
            os.remove(p)
            return d
    raise SystemExit("无法确定服务端证据目录：候选目录均未出现探针文件 "
                     f"{candidates}")


def main():
    print("== 1. 静态资源 ==")
    st, body, ct = req("GET", "/", raw=True)
    check("index.html 可访问", st == 200 and "应急响应日志分析平台" in body.decode("utf-8"))
    st, body, ct = req("GET", "/static/app.js", raw=True)
    check("app.js 可访问", st == 200 and "javascript" in ct)
    st, body, ct = req("GET", "/static/style.css", raw=True)
    check("style.css 可访问", st == 200 and "css" in ct)
    st, _, _ = req("GET", "/static/..%2f..%2fserver.py", raw=True)
    check("静态路径穿越被拦截", st == 404)
    st, _, _ = req("GET", "/static/nonexistent.js", raw=True)
    check("不存在的静态文件返回 404", st == 404)

    print("== 2. 规则清单 ==")
    st, r, _ = req("GET", "/api/rules")
    ids = [x["id"] for x in r["rules"]]
    check("返回 12 类规则", len(r["rules"]) == 12 and "brute-force" in ids, str(ids))
    check("命令混淆规则已注册", "command-obfuscation" in ids)
    check("数据库攻击规则已注册", "db-attack" in ids)
    check("流量异常规则已注册", "net-anomaly" in ids)
    check("流内容规则已注册", "stream-content" in ids)
    check("HTTP 内容规则已注册", "http-content" in ids)
    check("版本号存在", bool(r["version"]))

    print("== 3. 证据识别 ==")
    st, files, _ = req("GET", "/api/files")
    names = {f["name"] for f in files}
    # 证据目录内容随部署形态变化（源码仓 demo-evidence / 便携包 evidence），
    # 因此只校验「非空 + 类型识别正确 + 指纹齐备」，不对具体文件名写死
    check("证据目录非空", len(files) > 0, str(sorted(names)))
    types = {f["name"]: f["log_type"] for f in files}
    for name, ltype in types.items():
        if "nginx" in name.lower() or "访问" in name:
            check("nginx 识别为 web-access", ltype == "web-access", f"{name}={ltype}")
        if name.lower().endswith("auth.log") or "认证" in name:
            check("auth 识别为 linux-auth", ltype == "linux-auth", f"{name}={ltype}")
    check("sha256 已计算", all(len(f["sha256"]) == 64 for f in files))
    # 必须在任何上传之前解析，否则测试文件本身会污染候选目录判定
    evdir = resolve_evidence_dir()
    print(f"    证据目录: {evdir}")

    print("== 4. 路径穿越拦截 ==")
    st, r, _ = post_json("/api/analyze", {"files": ["../irlog/server.py"], "operator": "e2e"})
    check("analyze 越界文件被拒", st == 400, str(r))

    print("== 5. 上传 ==")
    st, r, _ = upload(os.path.join(PROJECT, "tests", "fixtures", "auth.log"))
    check("上传成功", st == 200 and r.get("saved"), str(r))

    print("== 5b. 上传字节级保真（回归：早期 rstrip 实现会损坏日志尾部） ==")
    tricky = b"line1\nline2\n\n--\n"          # 尾部多换行 + 以 -- 结尾
    bname = "e2e_bytecheck.log"
    saved_path = os.path.join(evdir, bname)   # evdir 在第 3 步已解析
    boundary = "----E2EBoundary"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
            f"filename=\"{bname}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode() \
           + tricky + f"\r\n--{boundary}--\r\n".encode()
    st, r, _ = req("POST", "/api/upload", body,
                   {"Content-Type": f"multipart/form-data; boundary={boundary}"})
    check("边界内容上传成功", st == 200 and r.get("saved") == [bname], str(r))
    got = open(saved_path, "rb").read()
    check("上传内容字节级一致", got == tricky, f"{len(tricky)} -> {len(got)} bytes")
    os.remove(saved_path)

    print("== 5c. 删除证据文件 ==")
    dname = "e2e_delete_check.log"
    dpath = os.path.join(evdir, dname)
    with open(dpath, "wb") as f:
        f.write(b"temp evidence for delete test\n")
    st, files, _ = req("GET", "/api/files")
    check("临时文件出现在列表", any(f["name"] == dname for f in files))
    st, r, _ = req("DELETE", "/api/files?name=" + dname)
    check("删除成功", st == 200 and r.get("deleted") == dname, str(r))
    check("文件已不在磁盘", not os.path.exists(dpath))
    st, files, _ = req("GET", "/api/files")
    check("列表已移除该文件", not any(f["name"] == dname for f in files))
    st, r, _ = req("DELETE", "/api/files?name=" + dname)
    check("重复删除返回 404", st == 404, str(r))
    st, r, _ = req("DELETE", "/api/files?name=..%2f..%2fetc%2fpasswd")
    check("穿越路径被归一化且拒删", st in (400, 404), str(r))
    # 诱饵验证：证据目录外的文件必须不受影响（穿越剥离后的真实防护效果）
    canary = os.path.join(PROJECT, "canary_e2e.txt")
    with open(canary, "w", encoding="utf-8") as f:
        f.write("must not be deleted\n")
    st, r, _ = req("DELETE", "/api/files?name=..%2fcanary_e2e.txt")
    check("目录外诱饵文件未被删除", st in (400, 404) and os.path.exists(canary), str(r))
    os.remove(canary)
    st, r, _ = req("DELETE", "/api/files")
    check("缺少 name 参数返回 400", st == 400, str(r))

    print("== 6. 规则过滤 + 阈值覆盖 ==")
    # 部署形态无关：先把样本送进服务端证据目录，再按其文件名发起分析
    upload(os.path.join(PROJECT, "tests", "fixtures", "nginx_access.log"))
    st, r, _ = post_json("/api/analyze", {
        "files": ["nginx_access.log"], "operator": "e2e",
        "rules": "web-attack", "overrides": ["web_attack_404_burst=1"],
    })
    check("分析任务已启动", st == 200 and r.get("task_id"), str(r))
    tid = r["task_id"]
    result = None
    for _ in range(120):
        st, t, _ = req("GET", "/api/task/" + tid)
        if t.get("status") in ("done", "error"):
            break
        time.sleep(0.5)
    check("任务完成", t.get("status") == "done", t.get("error", ""))
    result = t["result"]
    check("仅 web-attack 规则触发", all(a["rule_id"] == "web-attack" for a in result["alerts"]),
          str([a["rule_id"] for a in result["alerts"]]))
    check("阈值覆盖生效（404 阈值=1 产生告警）", result["stats"]["alert_count"] > 0)
    check("结果含统计/时间线/证据链字段",
          result["stats"]["total_events"] > 0 and "hour_histogram" in result["timeline"])

    print("== 7. IOC 管理 ==")
    st, r, _ = post_json("/api/ioc", {"text": "203.0.113.99\nevil.example.com\n# 注释"})
    check("IOC 粘贴导入", st == 200 and r["count"] >= 2, str(r))
    st, r, _ = req("GET", "/api/ioc")
    check("IOC 列表返回", any(i["value"] == "203.0.113.99" for i in r["items"]))
    st, r, _ = post_json("/api/ioc", {"action": "load_file", "file": "demo_ioc.txt"})
    check("IOC 文件载入", st == 200 and r["loaded"] >= 3, str(r))
    st, r, _ = post_json("/api/ioc", {"action": "load_file", "file": "../etc/passwd"})
    check("IOC 文件越界被拒", st == 400, str(r))
    st, r, _ = req("DELETE", "/api/ioc")
    check("IOC 清空", st == 200 and r["count"] == 0)

    print("== 8. 历史运行 + 报告 ==")
    st, r, _ = req("GET", "/api/runs")
    check("历史运行列表非空", len(r["runs"]) >= 1, f"{len(r['runs'])} runs")
    run_id = result["run_id"]
    st, body, ct = req("GET", f"/api/report/{run_id}?format=json", raw=True)
    d = json.loads(body.decode("utf-8"))
    check("JSON 报告可下载", st == 200 and "chain_of_custody" in d)
    check("证据链含 SHA256", d["chain_of_custody"]["evidence"]["file_count"] >= 1)
    st, body, ct = req("GET", f"/api/report/{run_id}?format=html", raw=True)
    h = body.decode("utf-8")
    check("HTML 报告可下载且自包含", st == 200 and "证据链" in h and "src=\"http" not in h)
    st, _, _ = req("GET", f"/api/report/{run_id}?format=xml", raw=True)
    check("非法 format 回落 html", st == 200)

    print("== 9. 审计留痕 ==")
    st, r, _ = req("GET", "/api/audit?n=100")
    actions = [e["action"] for e in r["entries"]]
    check("审计记录上传", "upload" in actions)
    check("审计记录文件删除", "delete_file" in actions)
    check("审计记录分析", "analyze-start" in actions and "analyze-done" in actions)
    check("审计记录 IOC 操作", "ioc-import" in actions or "ioc-clear" in actions)

    print(f"\n全部通过（{len(PASSED)} 项检查）✔")


if __name__ == "__main__":
    main()
