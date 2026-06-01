from utils.rds import RDS
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, slack_oauth_token, sender_email, send_logs_to_azure, customer_id, shared_key, log_type, auto_remediate_public_rds_snapshots, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
    email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
    slack_bot = None
    if slack_oauth_token:
        slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)
    active_session = helper.get_active_session()
    rds_utils = RDS(active_session, helper.region)

    if 'errorCode' not in event and 'errorMessage' not in event and 'requestParameters' in event:
        request_params = event['requestParameters']
        db_cluster_snapshot_id = request_params['dBClusterSnapshotIdentifier']
        is_snapshot_public = False

        if request_params['attributeName'] == 'restore':
            if 'valuesToAdd' in request_params:
                for val in request_params['valuesToAdd']:
                    if val == 'all':
                        is_snapshot_public = True
            if is_snapshot_public:
                severity = ''
                if auto_remediate_public_rds_snapshots:
                    severity = 'Informational'
                    if not rds_utils.make_public_db_snapshot_private(db_cluster_snapshot_id, True):
                        LOGGER.error("Could not make public RDS DB Cluster Snapshot %s private", db_cluster_snapshot_id)
                else:
                    severity = 'Critical'
                alert_args = {
                    "severity": severity,
                    "iam_user": helper.iam_user,
                    "resource_type": "RDS DB Cluster Snapshot",
                    "resource_id": db_cluster_snapshot_id,
                    "auto_remediate": auto_remediate_public_rds_snapshots
                }
                azure_data = {
                    "Severity": severity,
                    "AccountID": helper.account_id,
                    "AccountName": messenger.account_name,
                    "Region": helper.region,
                    "User": helper.iam_user,
                    "Event": f"User {helper.iam_user} made RDS DB Cluster Snapshot with ID {db_cluster_snapshot_id} public{' but since, auto-remediation is on for public RDS Snapshots, it has automatically been made PRIVATE' if auto_remediate_public_rds_snapshots else ''}"
                }
                alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                alerts_handler.handler('public_resource_message', alert_args, email_messenger, slack_bot)
    else:
        LOGGER.info("Not notifying")
