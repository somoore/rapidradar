import re
import json
from utils.ec2 import EC2
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, slack_oauth_token, sender_email, send_logs_to_azure, customer_id, shared_key, log_type, auto_remediate_public_amis, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
    email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
    slack_bot = None
    if slack_oauth_token:
        slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)
    active_session = helper.get_active_session()
    ec2_client = EC2(active_session, helper.region)

    if 'errorCode' not in event and 'errorMessage' not in event:
        if 'requestParameters' in event:
            request_params = event['requestParameters']
            ami_id = request_params['imageId']
            is_ami_public = False
            if request_params['attributeType'] == 'launchPermission':
                if 'add' in request_params['launchPermission'] and 'items' in request_params['launchPermission']['add']:
                    for item in request_params['launchPermission']['add']['items']:
                        group_match = re.search(r'(G|g)roup', json.dumps(item))
                        if group_match is not None:
                            if item[group_match.group(0)] == 'all':
                                is_ami_public = True
                if is_ami_public:
                    severity = ''
                    if auto_remediate_public_amis:
                        severity = 'Informational'
                        if not ec2_client.make_public_ami_private(ami_id):
                            LOGGER.error("Could not make public AMI %s private", ami_id)
                    else:
                        severity = 'Critical'
                    alert_args = {
                        "severity": severity,
                        "iam_user": helper.iam_user,
                        "resource_type": "EC2 AMI",
                        "resource_id": ami_id,
                        "auto_remediate": auto_remediate_public_amis
                    }
                    azure_data = {
                        "Severity": severity,
                        "AccountID": helper.account_id,
                        "AccountName": messenger.account_name,
                        "Region": helper.region,
                        "User": helper.iam_user,
                        "Event": f"User {helper.iam_user} made an AMI with ID {ami_id} public{' but since, auto-remediation is on for public AMIs, it has automatically been made PRIVATE' if auto_remediate_public_amis else ''}"
                    }
                    alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                    alerts_handler.handler('public_resource_message', alert_args, email_messenger, slack_bot)
    else:
        LOGGER.info("Image Attribute modification failed for some reason. Not notifying...")
