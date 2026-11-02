import math
import re
import time
from logger import LOGGER

SLACK_SIGNATURE_PATTERN = re.compile(r"^v0=[a-fA-F0-9]{64}$")

# NOTE: this REQUEST authorizer is a cheap pre-filter, NOT authentication. API Gateway REQUEST
# authorizers do not receive the request body, so the HMAC over `v0:<timestamp>:<body>` cannot be
# computed here. The authoritative Slack signature check is performed by
# responses_handler.verify_slack_request (constant-time compare, 300 s window) before any action is
# taken. Keep both: this filter rejects malformed/expired envelopes at the edge and WAF rate-limits
# the endpoint.
def lambda_handler(event, context):
    LOGGER.info("Received Slack authorizer request for method ARN: %s", event.get('methodArn', 'unknown'))

    headers = event.get('headers', {})
    slack_signature = headers.get('X-Slack-Signature')
    slack_timestamp = headers.get('X-Slack-Request-Timestamp')

    if not slack_signature or not slack_timestamp:
        LOGGER.error("Unauthorized: Missing signature or timestamp.")
        return generate_policy('user', 'Deny', event['methodArn'])
    if not SLACK_SIGNATURE_PATTERN.match(slack_signature):
        LOGGER.error("Unauthorized: Invalid signature format.")
        return generate_policy('user', 'Deny', event['methodArn'])
    try:
        ts = float(slack_timestamp)
    except ValueError:
        LOGGER.error("Unauthorized: Invalid timestamp.")
        return generate_policy('user', 'Deny', event['methodArn'])
    if not math.isfinite(ts):
        LOGGER.error("Unauthorized: Invalid timestamp.")
        return generate_policy('user', 'Deny', event['methodArn'])

    if abs(time.time() - ts) > 300:
        LOGGER.error("Unauthorized: Request expired.")
        return generate_policy('user', 'Deny', event['methodArn'])
    LOGGER.info("Request verified successfully!")
    return generate_policy('user', 'Allow', event['methodArn'])

def generate_policy(principal_id, effect, resource):
    return {
        'principalId': principal_id,
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [{
                'Action': 'execute-api:Invoke',
                'Effect': effect,
                'Resource': resource
            }]
        }
    }
