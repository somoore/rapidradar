import re
import json
from utils.sts import DecodeMessage
from utils.ec2 import EC2
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, slack_oauth_token, sender_email, send_logs_to_azure, customer_id, shared_key, log_type, auto_remediate_ebs_public_snapshots, make_ebs_snapshot_public_blocked, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
    email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
    slack_bot = None
    if slack_oauth_token:
        slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)
    active_session = helper.get_active_session()
    ec2_client = EC2(active_session, helper.region)

    if 'requestParameters' in event:
        azure_data = {
            "AccountID": helper.account_id,
            "AccountName": messenger.account_name,
            "Region": helper.region,
            "User": helper.iam_user
        }
        if 'errorCode' in event and 'errorMessage' in event and event['errorCode'] == 'Client.UnauthorizedOperation':
            request_params = event['requestParameters']
            snapshot_id = request_params['snapshotId']
            encoded_error_message = event['errorMessage'].split(': ')[-1].strip()
            severity = 'Informational'
            alert_args = {
                "severity": severity,
                "iam_user": helper.iam_user,
                "snapshot_id": snapshot_id
            }
            azure_data['Severity'] = severity
            azure_data['Event'] = f"User {helper.iam_user} tried to modify permissions for EBS Snapshot {snapshot_id} to make it public which failed due to an SCP policy"
            scp_blocked_creation = False
            if not encoded_error_message.endswith('...'):
                decoded_message = DecodeMessage(active_session, encoded_error_message).decoded_message
                LOGGER.debug(decoded_message)
                if len(decoded_message['matchedStatements']['items']) > 0:
                    for item in decoded_message['matchedStatements']['items']:
                        if 'statementId' in item and 'MakeSnapshotPublic' in item['statementId']:
                            scp_blocked_creation = True
                else:
                    LOGGER.info("Deployment didn't fail because of SCP")
            elif encoded_error_message.endswith('...'):
                if make_ebs_snapshot_public_blocked:
                    LOGGER.debug("EBS Snapshot's Permissions modification failed because of SCP, but could not decode encoded error message in CloudTrail API because it got truncated, as it can only consist of 1024B")
                    if request_params['attributeType'] == 'CREATE_VOLUME_PERMISSION':
                        if 'add' in request_params['createVolumePermission'] and 'items' in request_params['createVolumePermission']['add']:
                            for item in request_params['createVolumePermission']['add']['items']:
                                group_match = re.search(r'(G|g)roup', json.dumps(item))
                                if group_match is not None:
                                    if item[group_match.group(0)] == 'all':
                                        scp_blocked_creation = True

            if scp_blocked_creation:
                alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                alerts_handler.handler('public_ebs_snapshot_scp_block_error_message', alert_args, email_messenger, slack_bot)
            else:
                LOGGER.info("Deployment didn't fail because of SCP")

        elif 'errorCode' not in event and 'errorMessage' not in event:
            request_params = event['requestParameters']
            snapshot_id = request_params['snapshotId']
            is_snapshot_public = False
            if request_params['attributeType'] == 'CREATE_VOLUME_PERMISSION':
                if 'add' in request_params['createVolumePermission'] and 'items' in request_params['createVolumePermission']['add']:
                    for item in request_params['createVolumePermission']['add']['items']:
                        group_match = re.search(r'(G|g)roup', json.dumps(item))
                        if group_match is not None:
                            if item[group_match.group(0)] == 'all':
                                is_snapshot_public = True
            if is_snapshot_public:
                severity = ''
                if auto_remediate_ebs_public_snapshots:
                    severity = 'Informational'
                    if not ec2_client.make_public_snapshot_private(snapshot_id):
                        LOGGER.error("Could not make public EBS Snapshot %s private", snapshot_id)
                else:
                    severity = 'Critical'
                alert_args = {
                    "severity": severity,
                    "iam_user": helper.iam_user,
                    "resource_type": "EBS Snapshot",
                    "resource_id": snapshot_id,
                    "auto_remediate": auto_remediate_ebs_public_snapshots
                }
                azure_data['Severity'] = severity
                azure_data['Event'] = f"User {helper.iam_user} made EBS Snapshot with ID {snapshot_id} public{' but since, auto-remediation is on for public EBS Snapshots, snapshot has automatically been made PRIVATE' if auto_remediate_ebs_public_snapshots else ''}"
                alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                alerts_handler.handler('public_resource_message', alert_args, email_messenger, slack_bot)
    else:
        LOGGER.info("Not notifying")
