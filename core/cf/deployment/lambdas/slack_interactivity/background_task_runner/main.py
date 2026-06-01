from utils.logger import LOGGER
import helper

def lambda_handler(event, context):
    try:
        LOGGER.info("RECEIVED EVENT: %s", event)
        resource_metadata = event["Detail"]

        if event["Action"] == "DELETE":
            if not helper.delete_resource(resource_metadata["account_id"], resource_metadata["region"], resource_metadata["resource_type"], resource_metadata["resource_id"]):
                raise Exception(f"Failed to delete {resource_metadata['resource_type']} {resource_metadata['resource_id']} in Account {resource_metadata['account_id']} and Region {resource_metadata['region']}")
            LOGGER.info("Successfully deleted resource %s: %s", resource_metadata['resource_type'], resource_metadata["resource_id"])
        elif event["Action"] == "REMEDIATE":
            if not helper.remediate_resource(resource_metadata["account_id"], resource_metadata["region"], resource_metadata["resource_type"], resource_metadata["resource_id"]):
                raise Exception(f"Failed to remediate {resource_metadata['resource_type']} {resource_metadata['resource_id']} in Account {resource_metadata['account_id']} and Region {resource_metadata['region']}")
            LOGGER.info("Successfully remediated resource %s: %s", resource_metadata['resource_type'], resource_metadata["resource_id"])
        elif event["Action"] == "TAG":
            if "Tags" not in event:
                raise ValueError("Tags are required for the TAG action.")
            if not helper.tag_resource(resource_metadata["account_id"], resource_metadata["region"], resource_metadata["resource_type"], resource_metadata["resource_id"], event["Tags"]):
                raise Exception(f"Failed to add tags to {resource_metadata['resource_type']} {resource_metadata['resource_id']} in Account {resource_metadata['account_id']} and Region {resource_metadata['region']}")
            LOGGER.info("Successfully added tags to resource %s: %s", resource_metadata['resource_type'], resource_metadata["resource_id"])
        else:
            raise ValueError(f"Unsupported action: {event['Action']}")
        return {"status": "success", "message": f"{event['Action']} action completed successfully"}
    except Exception as e:
        LOGGER.error("Error processing task for Slack: %s", e)
        return {"status": "error", "message": str(e)}
