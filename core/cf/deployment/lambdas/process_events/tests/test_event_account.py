import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

from utils.event_account import validate_event_account  # noqa: E402

MANAGEMENT = "999900001111"
TARGETS = {"111122223333": "child-a", "444455556666": "child-b"}


def cloudtrail_event(envelope_account, identity_account, **extra):
    event = {
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.ec2",
        "detail": {
            "eventSource": "ec2.amazonaws.com",
            "eventName": "DeleteUser",
            "userIdentity": {"type": "IAMUser", "accountId": identity_account},
        },
    }
    if envelope_account is not None:
        event["recipientAccountId"] = envelope_account
    event.update(extra)
    return event


class ValidateEventAccountTest(unittest.TestCase):
    def test_target_account_is_accepted(self):
        self.assertIsNone(validate_event_account(
            cloudtrail_event("111122223333", "111122223333"), MANAGEMENT, TARGETS))

    def test_management_account_is_accepted(self):
        self.assertIsNone(validate_event_account(
            cloudtrail_event(MANAGEMENT, MANAGEMENT), MANAGEMENT, TARGETS))

    def test_forged_envelope_account_is_rejected(self):
        # The envelope claims a valid deployment target, but the CloudTrail identity comes from
        # another account: this is the forged-event path that used to reach AssumeRole.
        reason = validate_event_account(
            cloudtrail_event("111122223333", "777788889999"), MANAGEMENT, TARGETS)
        self.assertIsNotNone(reason)
        self.assertIn("does not match", reason)

    def test_unknown_account_is_rejected(self):
        reason = validate_event_account(
            cloudtrail_event("777788889999", "777788889999"), MANAGEMENT, TARGETS)
        self.assertIsNotNone(reason)
        self.assertIn("not a configured deployment target", reason)

    def test_event_without_account_is_not_rejected_by_this_guard(self):
        self.assertIsNone(validate_event_account({"detail": {}}, MANAGEMENT, TARGETS))


if __name__ == "__main__":
    unittest.main()
