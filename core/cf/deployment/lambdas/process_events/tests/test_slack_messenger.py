import sys
import types
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

# slack.py imports requests and the SSO helper (boto3) at module load; neither
# is needed to build a message, so stub them when they are not installed.
sys.modules.setdefault("requests", types.ModuleType("requests"))
if "utils.sso_helper" not in sys.modules:
    sso_helper = types.ModuleType("utils.sso_helper")
    sso_helper.SSOHelper = object
    sys.modules["utils.sso_helper"] = sso_helper

from messenger.channels.slack import SlackMessenger  # noqa: E402


class SlackMessengerEscapingTest(unittest.TestCase):
    def message_text(self, account_name, org_name):
        messenger = SlackMessenger("111122223333", account_name, org_name, "us-east-1")
        message = messenger.get_message(
            "resource_creation_without_tags_message",
            {
                "severity": "HIGH",
                "iam_user": "user@example.com",
                "resource_type": "S3 Bucket",
                "resource_id": "bucket",
                "tags": ["Owner"],
                "incident_number": None,
                "incident_url": None,
            },
        )
        return message["blocks"][0]["elements"][0]["text"]

    def test_names_are_escaped_exactly_once(self):
        text = self.message_text("Research & Development", "<Acme>")
        self.assertIn("AWS Account Name: Research &amp; Development", text)
        self.assertIn("AWS Organization: &lt;Acme&gt;", text)
        self.assertNotIn("&amp;amp;", text)
        self.assertNotIn("&amp;lt;", text)

    def test_missing_names_are_allowed(self):
        text = self.message_text(None, None)
        self.assertIn("AWS Account Name: None", text)


if __name__ == "__main__":
    unittest.main()
