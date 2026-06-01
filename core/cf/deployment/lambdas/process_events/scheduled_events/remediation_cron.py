import re
from utils.ec2 import EC2
from utils.events import Events
from utils.dynamodb import (
    SecurityGroupsData
)
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.slack_bot import SlackBot

def handle_event(event, notification_app, webhook_urls, slack_oauth_token, security_groups_table, send_logs_to_azure, customer_id, shared_key, log_type, auto_delete_all_traffic_sg_rule, auto_remediate_remote_access_ports, auto_remediate_traffic_ports, is_pd_integration_type_restapi):
    event_trigger_name = event['resources'][0].split('/')[-1]
    sg_id_regex_pattern = r'sg-(\w+)'
    match = re.search(sg_id_regex_pattern, event_trigger_name)
    security_group_id = match.group(0) if match else None
    event_port, event_protocol = event_trigger_name.split(f"{security_group_id}-")[-1].rsplit('-', 1)
    event_port = -1 if event_port == "alltraffic" else event_port
    event_protocol = '-1' if event_protocol == "all" else event_protocol
    account_id, region, ports_userip = SecurityGroupsData(security_groups_table).query_by_group_id(security_group_id)

    if account_id is not None:
        detail = { 'account': account_id, 'region': region }
        helper = AWSHelper(detail)
        active_session = helper.get_active_session()
        ec2_utils = EC2(active_session, helper.region)
        events_utils = Events(helper.account_id, helper.region)

        found_critical_ports, rule_details = ec2_utils.found_critical_ports_open(security_group_id, event_port, ports_userip)
        if found_critical_ports:
            messenger = EventAlert(notification_app, account_id, region, webhook_urls)
            slack_bot = None
            if slack_oauth_token:
                slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)
            is_port_remediated = False
            if event_protocol == '-1':
                if auto_delete_all_traffic_sg_rule:
                    if not ec2_utils.delete_security_group_rule(security_group_id, rule_details['RuleId']):
                        LOGGER.error("Could not delete Security Group Rule with all traffic open for %s", security_group_id)
                    else:
                        is_port_remediated = True
            else:
                if auto_remediate_remote_access_ports or auto_remediate_traffic_ports:
                    if not ec2_utils.close_opened_security_group_rule(security_group_id, rule_details['RuleId'], event_port, event_protocol, rule_details['UserIpAddress']):
                        LOGGER.error("Could not close Opened Critical Port in %s", security_group_id)
                    else:
                        is_port_remediated = True
            if is_port_remediated:
                severity = 'Informational'
                alert_args = {
                    "severity": severity,
                    "security_group_id": security_group_id,
                    "ip_protocol": "All traffic" if event_protocol == '-1' else event_protocol,
                    "port": event_port
                }
                azure_data = {
                    "Severity": severity,
                    "AccountID": account_id,
                    "AccountName": messenger.account_name,
                    "Region": region,
                    "User": "threatOps",
                    "Event": f"{'All traffic' if event_protocol == '-1' else event_protocol} port{'' if event_port == '-1' else f' {event_port}'} was open to the 0.0.0.0/0 IP range, which is against our company's security policy. Therefore, necessary steps to {'delete' if event_port == '-1' else 'close'} this port were taken to prevent unauthorized access to your resources via Security group {security_group_id}"
                }
                alerts_handler = Alert(None, [], is_pd_integration_type_restapi, True, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                alerts_handler.handler('critical_port_closed_message', alert_args, None, slack_bot)
        if not events_utils.cleanup_security_group_rule_remediation_cron(security_group_id, event_port, event_protocol):
            LOGGER.error("Could not cleanup Event rule for Security Group %s", security_group_id)
