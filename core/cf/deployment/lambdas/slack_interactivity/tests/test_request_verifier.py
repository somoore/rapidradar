import importlib.util
import sys
import time
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1] / "request_verifier"
sys.path.insert(0, str(BASE))

_spec = importlib.util.spec_from_file_location("request_verifier_main", BASE / "main.py")
verifier = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verifier)


def policy_effect(response):
    return response["policyDocument"]["Statement"][0]["Effect"]


def event(signature, timestamp):
    headers = {}
    if signature is not None:
        headers["X-Slack-Signature"] = signature
    if timestamp is not None:
        headers["X-Slack-Request-Timestamp"] = timestamp
    return {
        "methodArn": "arn:aws:execute-api:us-east-1:111122223333:abc/POST/interactivity",
        "headers": headers,
    }


class RequestVerifierTest(unittest.TestCase):
    """The authorizer is a documented pre-filter; these tests pin its actual contract."""

    def test_missing_headers_are_denied(self):
        self.assertEqual(policy_effect(verifier.lambda_handler(event(None, None), None)), "Deny")

    def test_malformed_signature_is_denied(self):
        result = verifier.lambda_handler(event("not-a-signature", str(int(time.time()))), None)
        self.assertEqual(policy_effect(result), "Deny")

    def test_nan_timestamp_is_denied(self):
        result = verifier.lambda_handler(event("v0=" + "a" * 64, "nan"), None)
        self.assertEqual(policy_effect(result), "Deny")

    def test_infinite_timestamp_is_denied(self):
        result = verifier.lambda_handler(event("v0=" + "a" * 64, "inf"), None)
        self.assertEqual(policy_effect(result), "Deny")

    def test_expired_timestamp_is_denied(self):
        result = verifier.lambda_handler(event("v0=" + "a" * 64, str(int(time.time()) - 400)), None)
        self.assertEqual(policy_effect(result), "Deny")

    def test_format_valid_fresh_envelope_passes_prefilter(self):
        # This is NOT authentication: the handler re-computes the HMAC before acting.
        result = verifier.lambda_handler(event("v0=" + "a" * 64, str(int(time.time()))), None)
        self.assertEqual(policy_effect(result), "Allow")


if __name__ == "__main__":
    unittest.main()
