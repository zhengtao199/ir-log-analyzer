"""类型分析面板 / 统计门面 / 自定义规则 / 规则库 API 测试。"""
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from irlog import models as M
from irlog.stats import LogStats
from irlog.profiles import build_type_reports, build_correlation
from irlog.config import Config
from irlog.engine import run_analysis
from irlog.rulepack import (RulePack, CustomRule, Pattern, builtin_inventory,
                           export_pack, parse_pack, backup_file)
from irlog.detectors.custom import CustomRuleDetector, test_rule_against_text
from irlog.server import Handler, State


def ev(**kw) -> M.Event:
    base = dict(ts=time.time(), log_type="", source="test", action="",
                src_ip=None, user=None, uri=None, method=None, status=None,
                detail={}, raw="")
    base.update(kw)
    e = M.Event(**{k: v for k, v in base.items() if k in M.Event.__dataclass_fields__})
    return e


class TestLogStatsFacade(unittest.TestCase):
    def test_by_log_type_and_passthrough(self):
        s = LogStats()
        # Web
        for _ in range(3):
            s.feed(ev(log_type="web-access", action=M.A_HTTP_REQUEST, src_ip="10.0.0.1",
                      method="GET", status=200, uri="/index.php"))
        # Windows
        s.feed(ev(log_type="winsec", action=M.A_LOGON_FAILED, src_ip="10.0.0.9", user="admin",
                  event_id="4625"))
        s.feed(ev(log_type="winsec", action=M.A_LOGON_SUCCESS, src_ip="10.0.0.9",
                  event_id="4624", logon_type="10"))
        # Linux
        s.feed(ev(log_type="linux-auth", action=M.A_LOGON_FAILED, src_ip="10.0.0.20", user="root"))
        # Database
        s.feed(ev(log_type="database", action=M.A_DB_QUERY, user="app",
                  detail={"sql": "SELECT * FROM users WHERE id=1"}))
        d = s.to_dict()
        self.assertEqual(d["by_log_type"]["web-access"], 3)
        self.assertEqual(d["by_log_type"]["winsec"], 2)
        self.assertEqual(d["web"]["distinct_clients"], 1)
        self.assertEqual(d["windows"]["logon_failed"], 1)
        self.assertEqual(d["windows"]["logon_success"], 1)
        self.assertEqual(d["linux"]["failed_logins"], 1)
        self.assertEqual(d["database"]["queries"], 1)

    def test_pcap_http_routes_to_web(self):
        s = LogStats()
        s.feed(ev(log_type="pcap", action=M.A_HTTP_REQUEST, src_ip="9.9.9.9",
                  method="POST", status=200, uri="/upload/skin.aspx"))
        d = s.to_dict()
        # pcap HTTP 重组成 web 统计，便于 pcap 类型 KPI 体现
        self.assertEqual(d["web"]["distinct_clients"], 1)


class TestTypeReportsAndCorrelation(unittest.TestCase):
    def _stats_alerts(self):
        events = [
            ev(log_type="web-access", action=M.A_HTTP_REQUEST, src_ip="10.0.0.1",
               method="POST", status=200, uri="/admin/login.php?do=login", ts=1000.0),
            ev(log_type="web-access", action=M.A_HTTP_REQUEST, src_ip="10.0.0.1",
               method="POST", status=200, uri="/upload/skin.aspx", ts=1010.0),
            ev(log_type="winsec", action=M.A_LOGON_FAILED, src_ip="10.0.0.9", user="admin",
               event_id="4625", ts=1005.0),
            ev(log_type="winsec", action=M.A_LOGON_SUCCESS, src_ip="10.0.0.9",
               event_id="4624", logon_type="3", ts=1008.0),
        ]
        s = LogStats()
        for e in events:
            s.feed(e)
        log_stats = s.to_dict()
        alerts = [{
            "rule_id": "attack-chain", "title": "攻击链", "severity": 1,
            "severity_label": "紧急", "first_time": "1970-01-01 08:16:40",
            "entities": {"src_ip": "10.0.0.1", "uri": "/upload/skin.aspx"},
        }]
        return log_stats, alerts

    def test_type_reports_loaded_only(self):
        log_stats, alerts = self._stats_alerts()
        reports = build_type_reports(log_stats, alerts)
        keys = [r["key"] for r in reports]
        self.assertIn("web-access", keys)
        self.assertIn("winsec", keys)
        # 未加载的类型不应出现
        self.assertNotIn("linux-auth", keys)

    def test_correlation_handles_list_srcip(self):
        log_stats, alerts = self._stats_alerts()
        # src_ip 为列表（自定义规则会产生列表）
        alerts[0]["entities"]["src_ip"] = ["10.0.0.1", "10.0.0.2"]
        corr = build_correlation(log_stats, alerts)
        profiled = [p["ip"] for p in corr["ip_profiles"]]
        # 列表形式 src_ip 应被完整拆解为多个 IP 画像，且不报错
        self.assertIn("10.0.0.1", profiled)
        self.assertIn("10.0.0.2", profiled)
        self.assertIn("10.0.0.9", profiled)
        # 关联结论应正常生成（无强关联时给出 info 兜底）
        self.assertTrue(corr["conclusions"])

    def test_correlation_iocs(self):
        log_stats, alerts = self._stats_alerts()
        corr = build_correlation(log_stats, alerts)
        # 攻击来源 IP（winsec 失败/成功、web 攻击告警）
        self.assertIn("10.0.0.1", corr["iocs"]["attack_ips"])
        self.assertIn("10.0.0.9", corr["iocs"]["attack_ips"])
        # 被爆破/登录的目标账号来自 winsec fail_by_user
        self.assertIn("admin", corr["iocs"]["target_accounts"])

    def test_correlation_critical_bruteforce(self):
        # 同一 IP 先大量登录失败、随后登录成功，且同期有账号变更 -> critical
        log_stats = {
            "by_log_type": {"winsec": 6},
            "windows": {
                "logon_failed": 5, "logon_success": 1,
                "fail_by_ip": [{"ip": "10.0.0.9", "count": 5}],
                "ok_by_ip": [{"ip": "10.0.0.9", "count": 1}],
                "account_changes": [{"event_id": "4722"}],
                "group_changes": [],
            },
            "web": {}, "linux": {}, "database": {},
        }
        corr = build_correlation(log_stats, [])
        self.assertTrue(any(c["level"] == "critical" for c in corr["conclusions"]))
        # 该 IP 画像应为 critical 风险
        prof = {p["ip"]: p["risk"] for p in corr["ip_profiles"]}
        self.assertEqual(prof.get("10.0.0.9"), "critical")


class TestCustomRuleDetector(unittest.TestCase):
    def test_independent_and_attachment(self):
        cfg = Config()
        r1 = CustomRule(rule_id="my-biz", title="业务后台", severity=3, scope="uri",
                        patterns=[Pattern(id="p1", kind="keyword", value="/upload/skin.aspx")])
        r2 = CustomRule(rule_id="add-payload", title="追加 webshell 特征", severity=2,
                        attaches_to="webshell",
                        patterns=[Pattern(id="p1", kind="regex", value=r"evilcmd=")])
        pack = RulePack(rules={"my-biz": r1, "add-payload": r2})
        det = CustomRuleDetector(cfg, pack)
        e = ev(log_type="web-access", action=M.A_HTTP_REQUEST, src_ip="5.5.5.5",
                method="POST", status=200, uri="/upload/skin.aspx?evilcmd=whoami", ts=1.0)
        det.feed(e)
        alerts = det.finalize()
        by_id = {a.rule_id: a for a in alerts}
        self.assertIn("my-biz", by_id)
        self.assertEqual(by_id["my-biz"].title, "业务后台")
        # 附属特征归入 webshell 规则 ID
        self.assertIn("webshell", by_id)
        self.assertEqual(by_id["webshell"].title, "追加 webshell 特征")

    def test_test_rule_against_text(self):
        r = CustomRule(rule_id="t", title="t", patterns=[Pattern(id="p1", kind="regex", value=r"union\s+select")])
        res = test_rule_against_text(r, "GET /x?id=1 UNION SELECT pass FROM u")
        self.assertTrue(res[0]["ok"])
        self.assertIn("UNION SELECT", res[0]["match"])


class TestRulePackModel(unittest.TestCase):
    def test_validate_and_roundtrip(self):
        r = CustomRule(rule_id="ok", title="T", severity=3, patterns=[Pattern(id="p1", kind="keyword", value="x")])
        self.assertEqual(r.validate(), [])
        bad = CustomRule(rule_id="BAD ID", title="", severity=9, patterns=[])
        self.assertTrue(bad.validate())

    def test_save_load_merge_replace_export_import(self):
        tmp = tempfile.mkdtemp()
        r1 = CustomRule(rule_id="r1", title="R1", patterns=[Pattern(id="p", kind="keyword", value="a")])
        p = RulePack(rules={"r1": r1})
        p.save(tmp)
        p2 = RulePack.load(tmp)
        self.assertIn("r1", p2.rules)
        # 合并
        r2 = CustomRule(rule_id="r2", title="R2", patterns=[Pattern(id="p", kind="keyword", value="b")])
        o = RulePack(rules={"r2": r2})
        stat = p2.merge(o)
        self.assertEqual(stat, {"added": ["r2"], "updated": [], "disabled_builtin": 0})
        # 导出 / 导入
        data = export_pack(p2)
        pack3, err = parse_pack(data)
        self.assertIsNone(err)
        self.assertEqual(set(pack3.rules), {"r1", "r2"})
        # 替换（先备份）
        r3 = CustomRule(rule_id="r3", title="R3", patterns=[Pattern(id="p", kind="keyword", value="c")])
        p2.replace_with(RulePack(rules={"r3": r3}))
        p2.save(tmp)
        self.assertIsNotNone(backup_file(RulePack.path_of(tmp)))

    def test_builtin_inventory_has_entries(self):
        inv = builtin_inventory()
        ids = {x["rule_id"] for x in inv}
        self.assertIn("webshell", ids)
        self.assertIn("attack-chain", ids)


class TestServerRulepackAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.state = State(None, cls.tmp)
        cls.port = 8731
        cls.httpd = None
        cls.thread = None

    def _handler(self, method, path, body=None):
        hd = Handler
        hd.state = self.state
        # 用内存字节流模拟请求
        import http.client
        out = io.BytesIO()
        hd_instance = type('H', (object,), {})()
        # 直接调用内部方法（不真起 socket）
        from unittest import mock
        req = mock.Mock()
        req.path = path
        req.headers = {}
        return req

    def test_rulepack_crud_via_engine(self):
        # 端到端：规则库落盘 -> 引擎加载并跑出告警
        r = CustomRule(rule_id="apitest", title="API 测试规则", severity=3, scope="uri",
                       patterns=[Pattern(id="p1", kind="keyword", value="/upload/skin.aspx")])
        pack = RulePack(rules={"apitest": r})
        pack.save(self.state.workdir)
        res = run_analysis(["demo-evidence/iis_w3c.log"], Config(), None, workdir=self.state.workdir)
        hits = [a for a in res.alerts if a.rule_id == "apitest"]
        self.assertTrue(hits, "自定义规则应通过规则库文件被引擎加载并命中")

    def test_rulepack_import_export(self):
        # 导出 -> 再导入（合并）应成功
        p1 = RulePack(rules={"rulex": CustomRule(rule_id="rulex", title="X",
                          patterns=[Pattern(id="p", kind="keyword", value="x")])})
        p1.save(self.state.workdir)
        data = export_pack(p1)
        p2, err = parse_pack(data)
        self.assertIsNone(err)
        self.assertIn("rulex", p2.rules)


if __name__ == "__main__":
    unittest.main(verbosity=2)
