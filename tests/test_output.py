from conftest import FakeQuerier, make_targets, ok
from dns_propagation.check import Expectation, run_check
from dns_propagation.emailauth import EmailReport
from dns_propagation.output import Style, clean, render_email, render_report, render_round


def test_clean_escapes_control_characters():
    assert clean("ok\x1b[31mred\x07") == "ok\\x1b[31mred\\x07"
    assert clean("v=spf1 -all") == "v=spf1 -all"


def test_report_table_escapes_and_truncates():
    fake = FakeQuerier({("*", "example.com", "TXT"): ok("evil\x1b]0;title\x07" + "x" * 200, "short")})
    report = run_check("example.com", "TXT", make_targets("192.0.2.1"), fake)
    text = render_report(report, Style(False))
    assert "\x1b" not in text and "\\x1b" in text
    assert "..." in text
    assert "x" * 200 in render_report(report, Style(False), wide=True)


def test_styles_only_when_enabled():
    assert Style(False)("x", "red") == "x"
    assert Style(True)("x", "red") == "\033[31mx\033[0m"


def test_round_line():
    fake = FakeQuerier({("*", "example.com", "A"): ok("192.0.2.1")})
    targets = make_targets("192.0.2.1", "192.0.2.2")
    report = run_check("example.com", "A", targets, fake, Expectation.build("A", ["192.0.2.1"]))
    assert render_round(4, [report], Style(False)) == "round 4: A 100% (2/2) done"


def test_email_render():
    report = EmailReport("example.com", records={"spf": ["v=spf1 -all"], "spf_lookups": 0})
    report.add("spf", "ok", "SPF record is valid")
    report.add("dmarc", "error", "no DMARC record at _dmarc.example.com")
    text = render_email(report, Style(False))
    assert "SPF" in text and "DNS lookups: 0/10" in text
    assert "ERROR   no DMARC record" in text
    assert text.endswith("Result: failed (1 error(s), 0 warning(s))")
