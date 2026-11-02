"""Cost-report e-mails keep RapidRadar-generated table markup but escape dynamic values."""
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

from messenger.sanitize import SafeHtml, escape_html, escape_html_args  # noqa: E402


def import_email_alerts():
    """Import messenger.email_alerts with its AWS dependencies stubbed (CI installs none)."""
    secretsmanager = types.ModuleType("utils.secretsmanager")
    secretsmanager.GetConfig = lambda _name: types.SimpleNamespace(values={})
    stubs = {"boto3": types.ModuleType("boto3"), "utils.secretsmanager": secretsmanager}
    with mock.patch.dict(sys.modules, stubs):
        sys.modules.pop("messenger.email_alerts", None)
        import messenger.email_alerts as email_alerts
    return email_alerts


class SafeHtmlDecoratorTest(unittest.TestCase):
    def test_safe_html_is_preserved_and_plain_strings_are_escaped(self):
        class Builder:
            @escape_html_args
            def message(self, user, table):
                return user, table

        user, table = Builder().message("<b>x</b>", table=SafeHtml("<table><tr><td>a</td></tr></table>"))
        self.assertEqual(user, "&lt;b&gt;x&lt;/b&gt;")
        self.assertEqual(table, "<table><tr><td>a</td></tr></table>")


class CostReportEmailTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.email_alerts = import_email_alerts()

    def setUp(self):
        self.messenger = self.email_alerts.EmailAlert("sender@example.com")
        self.sent = {}

        def capture(subject, body_html, receiver):
            self.sent.update(subject=subject, body=body_html, receiver=receiver)
            return True, "sent"

        # send_email is skipped by the hardening decorator, so patching the instance is enough.
        self.messenger.send_email = capture

    @staticmethod
    def table(resource_id):
        return SafeHtml(f"<table border=\"1\"><tr><td style='padding:5px'>{escape_html(resource_id)}</td></tr></table>")

    def test_daily_report_renders_table_and_escapes_values(self):
        hostile = '<img src=x onerror="alert(1)">'
        self.messenger.send_daily_cost_report(
            "<script>user</script>", "2026-11-02", self.table(hostile), [], [])
        body = self.sent["body"]
        self.assertIn('<table border="1">', body)
        self.assertIn("<td style='padding:5px'>", body)
        self.assertNotIn("&lt;table", body)
        self.assertNotIn("<img", body)
        self.assertIn("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;", body)
        self.assertNotIn("<script>", body)

    def test_weekly_report_renders_table(self):
        self.messenger.send_weekly_cost_report(
            "user@example.com", "Nov 01, 2026", "Oct 25, 2026", self.table("i-0abc"), "up by 5%")
        self.assertIn("<td style='padding:5px'>i-0abc</td>", self.sent["body"])

    def test_monthly_report_renders_table(self):
        import datetime
        self.messenger.send_monthly_cost_report(
            "user@example.com", datetime.date(2026, 10, 31), datetime.date(2026, 10, 1),
            self.table("i-0abc"), "unchanged")
        self.assertIn("<td style='padding:5px'>i-0abc</td>", self.sent["body"])

    def test_unmarked_markup_is_still_escaped(self):
        self.messenger.send_weekly_cost_report(
            "user@example.com", "Nov 01, 2026", "Oct 25, 2026", "<table>", "unchanged")
        self.assertIn("&lt;table&gt;", self.sent["body"])


if __name__ == "__main__":
    unittest.main()
