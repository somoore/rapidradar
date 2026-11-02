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

    def test_cross_account_caller_on_target_resource_is_accepted(self):
        # CloudTrail records cross-account access with the caller's account in userIdentity, e.g.
        # an external account calling PutBucketAcl on a monitored bucket. It must reach the
        # detectors.
        event = cloudtrail_event("111122223333", "777788889999")
        event["detail"]["eventSource"] = "s3.amazonaws.com"
        event["detail"]["eventName"] = "PutBucketAcl"
        self.assertIsNone(validate_event_account(event, MANAGEMENT, TARGETS))

    def test_cross_account_caller_between_targets_is_accepted(self):
        self.assertIsNone(validate_event_account(
            cloudtrail_event("111122223333", "444455556666"), MANAGEMENT, TARGETS))

    def test_non_target_envelope_with_target_identity_is_rejected(self):
        # A publisher outside the deployment targets cannot borrow a target identity in detail.
        reason = validate_event_account(
            cloudtrail_event("777788889999", "111122223333"), MANAGEMENT, TARGETS)
        self.assertIsNotNone(reason)
        self.assertIn("not a configured deployment target", reason)

    def test_eventbridge_account_field_is_validated(self):
        event = cloudtrail_event(None, "111122223333", account="777788889999")
        reason = validate_event_account(event, MANAGEMENT, TARGETS)
        self.assertIsNotNone(reason)

    def test_unknown_account_is_rejected(self):
        reason = validate_event_account(
            cloudtrail_event("777788889999", "777788889999"), MANAGEMENT, TARGETS)
        self.assertIsNotNone(reason)
        self.assertIn("not a configured deployment target", reason)

    def test_event_without_account_is_not_rejected_by_this_guard(self):
        self.assertIsNone(validate_event_account({"detail": {}}, MANAGEMENT, TARGETS))


if __name__ == "__main__":
    unittest.main()
