"""Module used to handle slack app's interactions"""
import os
import json
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from utils.logger import LOGGER
import helper

SLACK_BOT_CONFIG_SECRET_NAME = os.environ.get("SLACK_BOT_CONFIG_SECRET_NAME")
SLACK_BOT_CONFIG = helper.get_secret_value(SLACK_BOT_CONFIG_SECRET_NAME)
if not SLACK_BOT_CONFIG:
    LOGGER.error("Failed to fetch SLACK_BOT_CONFIG secret.")
    raise Exception("Failed to fetch SLACK_BOT_CONFIG secret.")

OAUTH_TOKEN = SLACK_BOT_CONFIG.get("BOT_OAUTH_TOKEN", "")
APP_TOKEN = SLACK_BOT_CONFIG.get("BOT_APP_TOKEN", "")
SECURITY_CHANNEL_ID = SLACK_BOT_CONFIG.get("SECURITY_CHANNEL_ID", "")
if not OAUTH_TOKEN or not SECURITY_CHANNEL_ID or not APP_TOKEN:
    LOGGER.error("Missing BOT_OAUTH_TOKEN or SECURITY_CHANNEL_ID or APP_TOKEN in secret %s", SLACK_BOT_CONFIG_SECRET_NAME)
    raise Exception("Missing required Slack configuration.")

app = App(token=OAUTH_TOKEN)

@app.action("action_acknowledge")
def handle_acknowledge_action(ack, body, respond):
    """Handle Acknowledge action"""
    ack()
    try:
        LOGGER.info("Received action_acknowledge event: %s", body)
        chosen_action = body["actions"][0]
        action_value = json.loads(chosen_action["value"])
        resource_metadata = json.loads(action_value["metadata"])

        message_text = "✅ Alert acknowledged."
        respond(helper.get_confirmation_message(message_text, action_value["alert_title"], resource_metadata["account_name"], resource_metadata["account_id"], resource_metadata["region"], resource_metadata["resource_type"], resource_metadata["resource_id"]))
    except Exception as e:
        LOGGER.error("Error processing action_acknowledge: %s", e)

@app.action("action_tag_resource")
def handle_tagging_action(ack, body):
    """Handle tagging action"""
    ack()
    try:
        LOGGER.info("Received action_tag_resource event: %s", body)
        chosen_action = body["actions"][0]
        action_value = json.loads(chosen_action["value"])
        trigger_id = body["trigger_id"]
        resource_metadata = json.loads(action_value["metadata"])

        modal_json = helper.get_tagging_modal_json(
            body["container"]["channel_id"],
            body["container"]["message_ts"],
            action_value.get("alert_title", ""),
            json.loads(action_value.get("missing_tags", "[]")),
            resource_metadata
        )
        result = app.client.views_open(trigger_id=trigger_id, view=modal_json)
        LOGGER.info("Modal opened successfully: %s", result)
    except Exception as e:
        LOGGER.error("Error processing action_tag_resource: %s", e)

@app.action("action_delete_resource")
def handle_delete_action(ack, body, fail, respond):
    """Handle Delete action"""
    ack()
    try:
        LOGGER.info("Received action_delete_resource event: %s", body)
        chosen_action = body["actions"][0]
        action_value = json.loads(chosen_action["value"])
        resource_metadata = json.loads(action_value["metadata"])

        if not helper.delete_resource(resource_metadata["account_id"], resource_metadata["region"], resource_metadata["resource_type"], resource_metadata["resource_id"]):
            fail(f"Failed to delete {resource_metadata['resource_type']} {resource_metadata['resource_id']} in Account {resource_metadata['account_id']} and Region {resource_metadata['region']}")
        else:
            message_text = f"🗑 {resource_metadata['resource_type']} *{resource_metadata['resource_id']}* has been deleted successfully."
            respond(helper.get_confirmation_message(message_text, action_value["alert_title"], resource_metadata["account_name"], resource_metadata["account_id"], resource_metadata["region"], resource_metadata["resource_type"], resource_metadata["resource_id"]))
    except Exception as e:
        LOGGER.error("Error processing action_delete_resource: %s", e)

@app.action("action_remediate_resource")
def handle_remediate_action(ack, body, fail, respond):
    """Handle Remediate action"""
    ack()
    try:
        LOGGER.info("Received action_remediate_resource event: %s", body)
        chosen_action = body["actions"][0]
        action_value = json.loads(chosen_action["value"])
        resource_metadata = json.loads(action_value["metadata"])

        if not helper.remediate_resource(resource_metadata["account_id"], resource_metadata["region"], resource_metadata["resource_type"], resource_metadata["resource_id"]):
            fail(f"Failed to remediate {resource_metadata['resource_type']} {resource_metadata['resource_id']} in Account {resource_metadata['account_id']} and Region {resource_metadata['region']}")
        else:
            message_text = f"🔒 *{resource_metadata['resource_type']}* {resource_metadata['resource_id']} has been remediated successfully."
            respond(helper.get_confirmation_message(message_text, action_value["alert_title"], resource_metadata["account_name"], resource_metadata["account_id"], resource_metadata["region"], resource_metadata["resource_type"], resource_metadata["resource_id"]))
    except Exception as e:
        LOGGER.error("Error processing action_remediate_resource: %s", e)

@app.action("action_report_security")
def handle_report_to_security_action(ack, body, respond):
    """Handle Report to Security Channel action"""
    ack()
    try:
        LOGGER.info("Received action_report_security event: %s", body)
        user_id = body["user"]["id"]
        chosen_action = body["actions"][0]
        action_value = json.loads(chosen_action["value"])
        resource_metadata = json.loads(action_value["metadata"])

        # Send report to the designated security channel using Slack's chat_postMessage
        app.client.chat_postMessage(channel=SECURITY_CHANNEL_ID, text=":rotating_light: *Security Alert: User Denied Resource Ownership* :rotating_light:", **helper.get_report_to_security_channel_message(user_id, action_value["alert_title"], resource_metadata["resource_type"], resource_metadata["resource_id"], resource_metadata["account_name"], resource_metadata["account_id"], resource_metadata["region"]))
        message_text = "🚨 Alert reported to the Security team."
        respond(helper.get_confirmation_message(message_text, action_value["alert_title"], resource_metadata["account_name"], resource_metadata["account_id"], resource_metadata["region"], resource_metadata["resource_type"], resource_metadata["resource_id"]))
    except Exception as e:
        LOGGER.error("Error processing action_report_security: %s", e)

@app.view("tagging_modal")
def handle_view_submission_events(ack, body, fail):
    """Handle Modal Form submission action"""
    ack()
    try:
        LOGGER.info("Received tagging_modal event: %s", body)
        view_payload = body["view"]
        private_metadata = json.loads(view_payload["private_metadata"])
        channel_id = private_metadata["channel_id"]
        message_ts = private_metadata["message_ts"]

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
        if not helper.tag_resource(resource_metadata["account_id"], resource_metadata["region"], resource_metadata["resource_type"], resource_metadata["resource_id"], tags_to_add):
            fail(f"Failed to add tags to {resource_metadata['resource_type']} {resource_metadata['resource_id']} in Account {resource_metadata['account_id']} and Region {resource_metadata['region']}")
        else:
            message_text = f"🏷 {resource_metadata['resource_type']} tagged successfully!"
            app.client.chat_update(channel=channel_id, ts=message_ts, **helper.get_confirmation_message(message_text, alert_title, resource_metadata["account_name"], resource_metadata["account_id"], resource_metadata["region"], resource_metadata["resource_type"], resource_metadata["resource_id"]))
    except Exception as e:
        LOGGER.error("Error processing tagging_modal: %s", e)

if __name__ == "__main__":
    handler = SocketModeHandler(app, APP_TOKEN)
    handler.start()
