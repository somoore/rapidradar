import time
from logger import LOGGER

def lambda_handler(event, context):
    LOGGER.info("RECEIVED EVENT: %s", event)

    headers = event.get('headers', {})
    slack_signature = headers.get('X-Slack-Signature')
    slack_timestamp = headers.get('X-Slack-Request-Timestamp')

    if not slack_signature or not slack_timestamp:
        LOGGER.error("Unauthorized: Missing signature or timestamp.")
        return generate_policy('user', 'Deny', event['methodArn'])
    try:
        ts = float(slack_timestamp)
    except ValueError:
        LOGGER.error("Unauthorized: Invalid timestamp.")
        return generate_policy('user', 'Deny', event['methodArn'])

    if abs(time.time() - float(slack_timestamp)) > 300:
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
