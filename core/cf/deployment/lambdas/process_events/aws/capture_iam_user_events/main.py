import json
from utils.iam import IAM
from utils.dynamodb import (
    IAMKeyPairAccessTrackerData,
    GetData
)
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert

def handle_event(helper: AWSHelper, event, event_time, event_name, event_service, notification_app, webhook_urls, send_logs_to_azure, customer_id, shared_key, log_type, iam_keypair_access_tracker_table, is_pd_integration_type_restapi):
    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
    active_session = helper.get_active_session()
    try:
        iam_utils = IAM(active_session)
        access_key_id = event['userIdentity']['accessKeyId']
        iam_user = event['userIdentity']['userName']
        iam_user_tags, created_by = iam_utils.get_iam_user_tags_created_by(iam_user)
        key_status = iam_utils.get_access_key_status(iam_user, access_key_id)
        key_last_used = iam_utils.get_access_key_last_used(access_key_id)
        if not key_last_used:
            key_last_used = event_time
        user_agent = ''
        if 'aws-cli' in helper.user_agent:
            user_agent = helper.user_agent.split(" ")[0][1:]
        else:
            user_agent = helper.user_agent

        records = GetData(iam_keypair_access_tracker_table).get_by_id('iam_user', iam_user, 'access_key_id', access_key_id)
        if len(records) > 0:
            ip_addresses = []
            if records[0]['key_activity']['SS'] != [""]:
                for ind, ip in enumerate(records[0]['key_activity']['SS']):
                    if ip:
                        ip_data = json.loads(ip)
                        ip_addresses.append(ip_data['IpAddress'])
                        if helper.user_ip_address == ip_data['IpAddress']:
                            updated_user_agents = []
                            if user_agent not in ip_data['UserAgents']:
                                ip_data['UserAgents'].append(user_agent)
                                updated_user_agents = ip_data['UserAgents']
                                records[0]['key_activity']['SS'][ind] = json.dumps({ 'IpAddress': helper.user_ip_address, 'UserAgents': updated_user_agents, 'Timestamp': event_time })

            if helper.user_ip_address not in ip_addresses:
                records[0]['key_activity']['SS'].append(json.dumps({'IpAddress': helper.user_ip_address, 'UserAgents': [user_agent], 'Timestamp': event_time}))
                while "" in records[0]['key_activity']['SS']:
                    records[0]['key_activity']['SS'].remove("")

                severity = 'High'
                azure_data = {
                    "Severity": severity,
                    "AccountID": helper.account_id,
                    "AccountName": messenger.account_name,
                    "Region": helper.region,
                    "User": helper.iam_user,
                    "Event": f"An unknown activity was detected using Secret-Access KeyPair with ID {access_key_id} of IAM User {iam_user} performing {event_service}:{event_name} action. SourceIPAddress: {helper.user_ip_address}, UserAgent: {user_agent}. Please review this activity and ensure that it was authorized."
                }
                alert_args = {
                    "severity": severity,
                    "iam_user": iam_user,
                    "access_key_id": access_key_id,
                    "action": f'{event_service}:{event_name}',
                    "source_ip_address": helper.user_ip_address,
                    "user_agent": user_agent
                }
                alerts_handler = Alert(None, [], is_pd_integration_type_restapi, True, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                alerts_handler.handler('captured_new_iam_user_event', alert_args, None, None)

            if not IAMKeyPairAccessTrackerData(iam_keypair_access_tracker_table).store(records[0]['account_id']['S'], records[0]['account_name']['S'], iam_user, access_key_id, key_status, created_by, records[0]['create_date']['S'], key_last_used, records[0]['key_activity']['SS'] if records[0]['key_activity']['SS'] else [""], records[0]['expiry_reminders']['SS'], iam_user_tags if iam_user_tags else [""]):
                LOGGER.error("Could not update record for Access Key ID %s of IAM User %s", access_key_id, iam_user)
            else:
                LOGGER.info("Known IP Address. Skipping...")
        else:
            LOGGER.info("No record found for Access Key ID %s of IAM User %s of Account %s", access_key_id, iam_user, helper.account_id)
    except Exception as error:
        LOGGER.error(str(error))
