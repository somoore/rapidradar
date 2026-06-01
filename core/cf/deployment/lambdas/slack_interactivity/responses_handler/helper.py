import json
from os import getenv
import time
import hmac
import hashlib
import requests
import boto3
from logger import LOGGER

BACKGROUND_TASK_LAMBDA = getenv('BACKGROUND_TASK_LAMBDA')

def verify_slack_request(slack_signing_secret: str, headers: dict, body: str):
    """
    Verify Slack request signature and timestamp.
    Returns (True, None) if valid; otherwise, (False, error_message).
    """
    slack_signature = headers.get("X-Slack-Signature")
    slack_timestamp = headers.get("X-Slack-Request-Timestamp")
    # Checking if slack signature and slack timestamp exist in request
    if not slack_signature or not slack_timestamp:
        LOGGER.error("Missing Slack signature or timestamp in verification.")
        return False, "Missing Slack signature or timestamp."
    try:
        ts = float(slack_timestamp)
    except ValueError:
        LOGGER.error("Invalid timestamp format.")
        return False, "Invalid timestamp format."
    # Prevent replay attacks (older than 5 minutes)
    if abs(time.time() - ts) > 300:
        LOGGER.error("Request timestamp is too old.")
        return False, "Request timestamp is too old."
    # Validating Slack Signature
    sig_basestring = f"v0:{slack_timestamp}:{body}"
    computed_signature = "v0=" + hmac.new(
        slack_signing_secret.encode('utf-8'),
        sig_basestring.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(computed_signature, slack_signature):
        LOGGER.error("Invalid Slack signature")
        return False, "Invalid Slack signature."
    return True, None

def invoke_background_task(payload: json):
    client = boto3.client("lambda")
    try:
        client.invoke(
            FunctionName=BACKGROUND_TASK_LAMBDA,
            InvocationType='Event',
            Payload=json.dumps(payload)
        )
        LOGGER.info("Successfully triggered background task runner with payload: %s", payload)
        return True
    except Exception as e:
        LOGGER.error("Error invoking background Lambda: %s", e)
        return False

def get_secret_value(name: str) -> str:
    client = boto3.client('secretsmanager')
    try:
        response = client.get_secret_value(SecretId=name)
        return json.loads(response["SecretString"])
    except Exception as error:
        LOGGER.error(str(error))
    return ''

def send_post_request(url: str, headers: dict, json_payload: dict, timeout=30):
    return requests.post(url, headers=headers, json=json_payload, timeout=timeout)

def send_confirmation_message(headers: dict, response_url: str, text: str, title: str, account_name: str, account_id: str, region: str, resource_type: str, resource_id: str):
    response_payload = {
        "replace_original": True,
        "text": text,
        "attachments": [{
            "color": "#36a64f",
            "title": f"{title}",
            "footer": "AWS",
            "footer_icon": "https://images.seeklogo.com/logo-png/31/1/amazon-web-services-aws-logo-png_seeklogo-319188.png",
            "fields": [
                {
                    "title": "Account ID",
                    "value": f"{account_id}",
                    "short": True
                },
                {
                    "title": "Account Name",
                    "value": f"{account_name}",
                    "short": True
                },
                {
                    "title": "Region",
                    "value": f"{region}",
                    "short": True
                },
                {
                    "title": f"{resource_type}",
                    "value": f"{resource_id}",
                    "short": True
                }
            ]
        }]
    }
    try:
        response = send_post_request(response_url, headers, response_payload)
        response_json = response.json()
        if not response_json.get("ok"):
            return False, f"Failed to send confirmation message: {response_json.get('error')}"
        return True, response_json
    except Exception as error:
        return False, str(error)

def open_tagging_modal(headers: dict, trigger_id: str, response_url: str, alert_title: str, missing_tags: list, metadata: dict):
    metadata_str = json.dumps(metadata)
    modal_title = f"Tag {metadata['resource_type']}"
    if len(modal_title) > 25:
        modal_title = "Tag Resource"
    input_blocks = []
    for tag in missing_tags:
        key_value = tag.split("=")
        tag_input = {
            "type": "input",
            "block_id": f"block_{key_value[0]}",
            "element": {
                "type": "plain_text_input",
                "action_id": f"input_{key_value[0]}",
                "placeholder": {
                    "type": "plain_text",
                    "text": f"Enter value for {key_value[0]}"
                }
            },
            "label": {
                "type": "plain_text",
                "text": f"{key_value[0]} (required)"
            }
        }
        if "=" in tag:
            tag_input["element"]["initial_value"] = key_value[1]
        input_blocks.append(tag_input)
    modal_payload = {
        "trigger_id": trigger_id,
        "view": {
            "type": "modal",
            "private_metadata": json.dumps({"response_url": response_url, "alert_title": alert_title, "metadata": metadata_str}),
            "callback_id": "tagging_modal",
            "title": {
                "type": "plain_text",
                "text": modal_title
            },
            "blocks": input_blocks,
            "submit": {
                "type": "plain_text",
                "text": "Tag"
            }
        }
    }
    try:
        response = send_post_request("https://slack.com/api/views.open", headers, modal_payload)
        response_json = response.json()
        if not response_json.get("ok"):
            return False, f"Failed to open modal: {response_json.get('error')}"
        return True, response_json
    except Exception as error:
        return False, str(error)

def report_security_channel(headers: dict, security_channel_id: str, user_id: str, alert_title: str, resource_type: str, resource_id: str, account_name: str, account_id: str, region: str):
    message_payload = {
        "channel": security_channel_id,
        "blocks": [{
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": ":rotating_light: *Security Alert: User Denied Resource Ownership* :rotating_light:"
            }
        },
        {
            "type": "section",
            "fields": [{
                "type": "mrkdwn",
                "text": f"*Alert Title:*\n{alert_title}"
            },{
                "type": "mrkdwn",
                "text": "*Issue:*\nResource creation flagged by a user."
            },
            {
                "type": "mrkdwn",
                "text": f"*Resource:*\n{resource_type}: `{resource_id}`" if resource_id else f"*Resource:*\n{resource_type}"
            },
            {
                "type": "mrkdwn",
                "text": f"*Account:*\n{account_id} ({account_name})"
            },
            {
                "type": "mrkdwn",
                "text": f"*Region:*\n{region}"
            }]
        },
        {
            "type": "section",
            "fields": [{
                "type": "mrkdwn",
                "text": f"*User:*\n <@{user_id}>"
            },
            {
                "type": "mrkdwn",
                "text": "*Action Taken:*\nReported \"Not me, report to security!\""
            },
            {
                "type": "mrkdwn",
                "text": "*Potential Concern:*\nCredentials leakage or unauthorized access."
            }]
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Recommended Next Steps:*\n- Investigate the resource creation logs (CloudTrail) to verify the initiating identity.\n- Check for anomalous activity or unusual patterns in the account.\n- Consider immediate containment steps, such as rotating IAM credentials or locking down the account."
            }
        }]
    }
    try:
        response = send_post_request("https://slack.com/api/chat.postMessage", headers, message_payload)
        response_json = response.json()
        if not response_json.get("ok"):
            return False, f"Failed to send security channel message: {response_json.get('error')}"
        return True, response_json
    except Exception as error:
        return False, str(error)
