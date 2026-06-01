import json
import urllib.parse
from os import getenv
from logger import LOGGER
import helper
from response_lib import success, failure

SLACK_BOT_CONFIG_SECRET_NAME = getenv('SLACK_BOT_CONFIG_SECRET_NAME')
ALLOWED_SLACK_RESPONSE_HOSTS = {"hooks.slack.com", "hooks.slack-gov.com"}

def is_valid_slack_response_url(response_url: str) -> bool:
    parsed_url = urllib.parse.urlparse(response_url)
    hostname = (parsed_url.hostname or "").lower().rstrip(".")
    return parsed_url.scheme == "https" and hostname in ALLOWED_SLACK_RESPONSE_HOSTS

def lambda_handler(event, context):
    try:
        SLACK_BOT_CONFIG = helper.get_secret_value(SLACK_BOT_CONFIG_SECRET_NAME)
        if not SLACK_BOT_CONFIG:
            LOGGER.error("Failed to fetch SLACK_BOT_CONFIG secret.")
            return {
                "statusCode": 500,
                "body": json.dumps({"error": "Failed to fetch SLACK_BOT_CONFIG secret."})
            }
        oauth_token = SLACK_BOT_CONFIG.get("BOT_OAUTH_TOKEN", "")
        security_channel_id = SLACK_BOT_CONFIG.get("SECURITY_CHANNEL_ID", "")
        slack_signing_secret = SLACK_BOT_CONFIG.get("SLACK_SIGNING_SECRET", "")
        if not oauth_token or not security_channel_id or not slack_signing_secret:
            LOGGER.error("Values for either BOT_OAUTH_TOKEN or SECURITY_CHANNEL_ID or SLACK_SIGNING_SECRET missing fetched secret %s", SLACK_BOT_CONFIG_SECRET_NAME)
            return {
                "statusCode": 500,
                "body": json.dumps({"error": f"Values for either BOT_OAUTH_TOKEN or SECURITY_CHANNEL_ID or SLACK_SIGNING_SECRET missing fetched secret {SLACK_BOT_CONFIG_SECRET_NAME}"})
            }

        # Parse the Slack interactivity payload
        body = event['body']
        headers = event.get("headers", {})

        # Verify Slack request (signature, timestamp)
        valid, error_message = helper.verify_slack_request(slack_signing_secret, headers, body)
        if not valid:
            return {
                "statusCode": 401,
                "body": json.dumps({"error": error_message})
            }

        # Parse the URL-encoded form data to get the 'payload' parameter
        parsed_body = urllib.parse.parse_qs(body)
        payload_str = parsed_body.get("payload", [None])[0]
        if not payload_str:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "Missing 'payload' in request body"})
            }
        # Parse the payload JSON
        slack_payload = None
        try:
            slack_payload = json.loads(payload_str)
        except json.JSONDecodeError:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "Invalid JSON in 'payload'"})
            }
        # Validate required fields in payload
        required_keys = ["type", "user", "actions", "response_url"]
        for key in required_keys:
            if key not in slack_payload:
                return {
                    "statusCode": 400,
                    "body": json.dumps({"error": f"Missing required field '{key}'"})
                }
        # Validate that response_url is within the Slack domain
        response_url = slack_payload.get("response_url", "")
        if not is_valid_slack_response_url(response_url):
            parsed_url = urllib.parse.urlparse(response_url)
            LOGGER.error("Invalid response_url domain: %s", parsed_url.netloc)
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "Invalid response_url domain."})
            }
        LOGGER.info("Slack Payload verified successfully!")

        # Prepare headers for outgoing Slack API calls (sanitize sensitive data)
        headers_out = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {oauth_token}"
        }
        user_id = slack_payload["user"]["id"]
        trigger_id = slack_payload["trigger_id"]

        # Process block_actions or view_submission types
        if slack_payload["type"] == "block_actions":
            chosen_action = slack_payload["actions"][0]
            action = chosen_action["action_id"]
            action_value = json.loads(chosen_action["value"])
            resource_metadata = json.loads(action_value["metadata"])

            if action == "action_acknowledge":
                message_text = "✅ Alert acknowledged."
                status, response = helper.send_confirmation_message(headers_out, response_url, message_text, action_value["alert_title"], resource_metadata["account_name"], resource_metadata["account_id"], resource_metadata["region"], resource_metadata["resource_type"], resource_metadata["resource_id"])
                if not status:
                    LOGGER.error("Error sending confirmation message: %s", response)
                    return failure(response)
                return success(response)
            if action == "action_tag_resource":
                status, response = helper.open_tagging_modal(headers_out, trigger_id, response_url, action_value["alert_title"], json.loads(action_value["missing_tags"]), resource_metadata)
                if not status:
                    LOGGER.error("Error opening tagging modal: %s", response)
                    return failure(response)
                return success(response)
            if action == "action_delete_resource":
                task_payload = {
                    "Action": "DELETE",
                    "Detail": resource_metadata
                }
                if not helper.invoke_background_task(task_payload):
                    LOGGER.error("Failed to invoke background task runner")
                    return failure({"error": "Failed to invoke background task runner"})
                message_text = f"🗑 {resource_metadata['resource_type']} *{resource_metadata['resource_id']}* has been deleted successfully."
                helper.send_confirmation_message(headers_out, response_url, message_text, action_value["alert_title"], resource_metadata["account_name"], resource_metadata["account_id"], resource_metadata["region"], resource_metadata["resource_type"], resource_metadata["resource_id"])
                return success({})
            if action == "action_remediate_resource":
                task_payload = {
                    "Action": "REMEDIATE",
                    "Detail": resource_metadata
                }
                if not helper.invoke_background_task(task_payload):
                    LOGGER.error("Failed to invoke background task runner")
                    return failure({"error": "Failed to invoke background task runner"})
                message_text = f"🔒 *{resource_metadata['resource_type']}* {resource_metadata['resource_id']} has been remediated successfully."
                helper.send_confirmation_message(headers_out, response_url, message_text, action_value["alert_title"], resource_metadata["account_name"], resource_metadata["account_id"], resource_metadata["region"], resource_metadata["resource_type"], resource_metadata["resource_id"])
                return success({})
            if action == "action_report_security":
                status, response = helper.report_security_channel(headers_out, security_channel_id, user_id, action_value["alert_title"], resource_metadata["resource_type"], resource_metadata["resource_id"], resource_metadata["account_name"], resource_metadata["account_id"], resource_metadata["region"])
                if not status:
                    LOGGER.error("Error reporting to Security Channel: %s", response)
                    return failure(response)
                message_text = "🚨 Alert reported to the Security team."
                status, response = helper.send_confirmation_message(headers_out, response_url, message_text, action_value["alert_title"], resource_metadata["account_name"], resource_metadata["account_id"], resource_metadata["region"], resource_metadata["resource_type"], resource_metadata["resource_id"])
                if not status:
                    LOGGER.error("Error sending confirmation message: %s", response)
                    return failure(response)
                return success(response)
            message_text = "⚠️ Unknown action. Please try again."
            status, response = helper.send_confirmation_message(headers_out, response_url, message_text, action_value["alert_title"], resource_metadata["account_name"], resource_metadata["account_id"], resource_metadata["region"], resource_metadata["resource_type"], resource_metadata["resource_id"])
            if not status:
                LOGGER.error("Error sending confirmation message: %s", response)
                return failure(response)
            return success(response)
        if slack_payload["type"] == "view_submission":
            view_payload = slack_payload["view"]
            private_metadata = json.loads(view_payload["private_metadata"])
            alert_title = private_metadata["alert_title"]
            resource_metadata = json.loads(private_metadata["metadata"])
            tags_values = view_payload["state"]["values"]
            tags_to_add = []
            for block_key, block_val in tags_values.items():
                tag_key = block_key.rsplit("block_", 1)[-1]
                tag_value = ""
                for _, input_val in block_val.items():
                    tag_value = input_val["value"]
                tags_to_add.append({"Key": tag_key, "Value": tag_value})
            task_payload = {
                "Action": "TAG",
                "Detail": resource_metadata,
                "Tags": tags_to_add
            }
            if not helper.invoke_background_task(task_payload):
                LOGGER.error("Failed to invoke background task runner")
                return failure({"error": "Failed to invoke background task runner"})
            message_text = f"🏷 {resource_metadata['resource_type']} tagged successfully!"
            helper.send_confirmation_message(headers_out, response_url, message_text, alert_title, resource_metadata["account_name"], resource_metadata["account_id"], resource_metadata["region"], resource_metadata["resource_type"], resource_metadata["resource_id"])
            return success({})
        return success({"message": "Action processed successfully"})
    except Exception as e:
        LOGGER.error("Error processing Slack interactivity: %s", e)
        return failure({"error": str(e)})
