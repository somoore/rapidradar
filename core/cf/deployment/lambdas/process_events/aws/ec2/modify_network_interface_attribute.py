import time
import json
import copy
from utils.ec2 import EC2
from utils.events import Events
from utils.utility import AWSHelper, Helper, Alert
from utils.logger import LOGGER
from utils.dynamodb import (
    SecurityGroupsData,
    GetData
)
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, slack_oauth_token, sender_email, send_logs_to_azure, customer_id, shared_key, log_type, table_name, ec2_security_group_ingress_remote_access_ports, ec2_security_group_ingress_traffic_ports, ec2_security_group_ingress_ignore_ports, loadbalancer_security_group_ingress_remote_access_ports, loadbalancer_security_group_ingress_traffic_ports, loadbalancer_security_group_ingress_ignore_ports, target_arn, auto_delete_all_traffic_sg_rule, auto_remediate_remote_access_ports, auto_remediate_traffic_ports, auto_remediate_launch_wizard_sg, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    if 'errorCode' not in event and 'requestParameters' in event:
        request_params = event['requestParameters']
        messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
        email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
        slack_bot = None
        if slack_oauth_token:
            slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)
        active_session = helper.get_active_session()
        ec2_utils = EC2(active_session, helper.region)
        events_utils = Events(helper.account_id, helper.region)
        try:
            if 'networkInterfaceId' in request_params and 'groupSet' in request_params:
                network_interface_id = request_params['networkInterfaceId']
                instance_id = ec2_utils.get_instance_id_for_network_interface(network_interface_id)
                attached_security_groups = [ item['groupId'] for item in request_params['groupSet']['items'] ]
                azure_data = {
                    "AccountID": helper.account_id,
                    "AccountName": messenger.account_name,
                    "Region": helper.region,
                    "User": helper.iam_user
                }
                for group_id in attached_security_groups:
                    group_name = ec2_utils.get_security_group_name(group_id)
                    if group_name is not None:
                        if not group_name.startswith('launch-wizard-') or not auto_remediate_launch_wizard_sg:
                            is_attached, attached_ec2_instances, attached_loadbalancers = ec2_utils.found_security_group_attachments(group_id)

                            public_instances = []
                            internet_facing_lb = []
                            for instance in attached_ec2_instances:
                                if not ec2_utils.is_instance_private(instance['ResourceId']):
                                    public_instances.append(instance['ResourceId'])
                            for lb in attached_loadbalancers:
                                if lb['Context'] == 'Inbound & Outbound':
                                    internet_facing_lb.append(lb['ResourceId'])

                            security_group_open_ports = ec2_utils.get_security_group_open_ports(group_id)
                            if security_group_open_ports[0]:
                                scan_records = GetData(table_name).get_by_id('account_id', helper.account_id, 'security_group_id', group_id)
                                is_critical_finding = False
                                is_high_finding = False
                                is_medium_finding = False
                                ports_userip = []
                                for item in security_group_open_ports[1]:
                                    if not Helper().matches_given_ports(item['Port'], item['Protocol'], ec2_security_group_ingress_ignore_ports, True) and not Helper().matches_given_ports(item['Port'], item['Protocol'], loadbalancer_security_group_ingress_ignore_ports, True):
                                        port_userip = Helper().extract_ports_with_userip(item, scan_records)
                                        group_rule_id = item['RuleId']
                                        if Helper().is_all_traffic_port(item['Port']):
                                            if public_instances or internet_facing_lb:
                                                is_critical_finding = True
                                            else:
                                                is_medium_finding = True
                                            if is_critical_finding and auto_delete_all_traffic_sg_rule:
                                                if port_userip:
                                                    if not events_utils.create_security_group_rule_remediation_cron(group_id, item['Port'], item['Protocol'], target_arn):
                                                        LOGGER.error("Could not create All Traffic Events Rule")
                                                else:
                                                    if not ec2_utils.delete_security_group_rule(group_id, group_rule_id):
                                                        LOGGER.error("Could not delete security group rule with all traffic open to public for Security Group %s in Account=%s and Region=%s", group_id, helper.account_id, helper.region)
                                        elif Helper().matches_given_ports(item['Port'], item['Protocol'], ec2_security_group_ingress_remote_access_ports, False) or Helper().matches_given_ports(item['Port'], item['Protocol'], loadbalancer_security_group_ingress_remote_access_ports, False):
                                            if public_instances or internet_facing_lb:
                                                is_critical_finding = True
                                            else:
                                                is_medium_finding = True
                                            if is_critical_finding and auto_remediate_remote_access_ports:
                                                if port_userip:
                                                    if not ec2_utils.close_opened_security_group_rule(group_id, group_rule_id, item['Port'], item['Protocol'], port_userip['UserIpAddress']):
                                                        LOGGER.error("Could not close Opened Critical Port in %s", group_id)
                                                    else:
                                                        severity = 'Informational'
                                                        alert_args = {
                                                            "severity": severity,
                                                            "security_group_id": group_id,
                                                            "ip_protocol": item['Protocol'],
                                                            "port": item['Port']
                                                        }
                                                        azure_data['Severity'] = severity
                                                        azure_data['Event'] = f"{'All Traffic' if Helper().is_all_traffic_port(item['Port']) else item['Protocol']} port{'' if Helper().is_all_traffic_port(item['Port']) else ' '+str(item['Port'])} was open to the 0.0.0.0/0 IP range, which is against our company's security policy. Therefore, necessary steps to {'delete' if Helper().is_all_traffic_port(item['Port']) else 'close'} this port were taken to prevent unauthorized access to your resources via Security group {group_id}"
                                                        alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                                                        alerts_handler.handler('critical_port_closed_message', alert_args, None, None)
                                                else:
                                                    if not ec2_utils.delete_security_group_rule(group_id, group_rule_id):
                                                        LOGGER.error("Could not delete critical rule from Security Group %s in Account=%s and Region=%s", group_id, helper.account_id, helper.region)
                                        elif Helper().matches_given_ports(item['Port'], item['Protocol'], ec2_security_group_ingress_traffic_ports, False) or Helper().matches_given_ports(item['Port'], item['Protocol'], loadbalancer_security_group_ingress_traffic_ports, False):
                                            if public_instances or internet_facing_lb:
                                                is_high_finding = True
                                            if is_high_finding and auto_remediate_traffic_ports:
                                                if port_userip:
                                                    if not ec2_utils.close_opened_security_group_rule(group_id, group_rule_id, item['Port'], item['Protocol'], port_userip['UserIpAddress']):
                                                        LOGGER.error("Could not close Opened Critical Port in %s", group_id)
                                                else:
                                                    if not ec2_utils.delete_security_group_rule(group_id, group_rule_id):
                                                        LOGGER.error("Could not delete critical rule from Security Group %s in Account=%s and Region=%s", group_id, helper.account_id, helper.region)
                                        if port_userip:
                                            ports_userip.append(Helper().format_ports_entry(port_userip['Port'], port_userip['Protocol'], port_userip['UserIpAddress']))
                                        else:
                                            ports_userip.append(Helper().format_ports_entry(item['Port'], item['Protocol'], ''))

                                if ports_userip:
                                    updated_incident_ids = []
                                    if pagerduty_helper is not None and scan_records:
                                        if 'pagerduty_incident_id' in scan_records[0]:
                                            for incident_id in scan_records[0]['pagerduty_incident_id']['SS']:
                                                incident_status, incident_number, incident_url = pagerduty_helper.get_incident_details(incident_id)
                                                if incident_status not in ['resolved']:
                                                    updated_incident_ids.append(incident_id)
                                        elif 'pagerduty_dedup_keys' in scan_records[0]:
                                            for dedup_key in scan_records[0]['pagerduty_dedup_keys']['SS']:
                                                updated_incident_ids.append(dedup_key)
                                    found_suppression_tag = GetData(table_name).found_suppression_tag(helper.account_id, 'security_group_id', group_id)

                                    severity = 'Critical' if is_critical_finding else 'High' if is_high_finding else 'Medium' if is_medium_finding else 'Low'
                                    alert_args = {
                                        "severity": severity,
                                        "iam_user": helper.iam_user,
                                        "security_group_id": group_id,
                                        "resource_type": "EC2 Instance(s)",
                                        "ports": [ str(json.loads(port)['Port']) for port in ports_userip ],
                                        "is_attached": is_attached,
                                        "attached_instances": attached_ec2_instances,
                                        "attached_lb": attached_loadbalancers
                                    }
                                    azure_data['Severity'] = severity
                                    azure_data['Event'] = f"Security Group {group_id} with ports [{', '.join(str(json.loads(port)['Port']) for port in ports_userip).replace('-1', 'All Traffic')}] Open to 0.0.0.0/0 got attached to EC2 Instance(s) {instance_id}"
                                    if not found_suppression_tag:
                                        alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                                        updated_incident_ids.append(alerts_handler.handler('security_group_ingress_open_to_all_attached_to_public_resource', alert_args, None, slack_bot))
                                    if not SecurityGroupsData(table_name).store(helper.account_id, helper.region, group_id, ports_userip, is_attached, found_suppression_tag, pagerduty_incident_id=updated_incident_ids if is_pd_integration_type_restapi else None, pagerduty_dedup_keys=None if is_pd_integration_type_restapi else updated_incident_ids):
                                        LOGGER.error("Could not add metadata for Security Group %s in Account ID=%s and Region=%s", group_id, helper.account_id, helper.region)
                            else:
                                LOGGER.info("Not sending any notification since no ports are open.")
                        else:
                            LOGGER.info("Is a Launch Wizard Security Group and auto-remediation is enabled.")
                            new_security_group_ids = copy.copy(attached_security_groups)
                            new_security_group_ids.remove(group_id)
                            is_replaced_by_blackhole_sg = False
                            if len(attached_security_groups) == 1:
                                security_group_id = ec2_utils.get_blackhole_sg_id(ec2_utils.get_vpc_id_for_network_interface(network_interface_id), 'blackhole-security-group')
                                if security_group_id is not None:
                                    new_security_group_ids.append(security_group_id)
                                    is_replaced_by_blackhole_sg = True
                            if not ec2_utils.modify_ec2_security_groups(instance_id, new_security_group_ids):
                                LOGGER.error("Could not attach updated list of security groups to EC2 Instance %s", instance_id)
                            time.sleep(5)
                            is_deleted, reason = ec2_utils.delete_security_group(group_id)
                            if not is_deleted:
                                LOGGER.error("Could not delete security group %s in account %s and region %s. Reason: %s", group_id, helper.account_id, helper.region, reason)
                            severity = 'Low'
                            alert_args = {
                                "is_create_event": False,
                                "severity": severity,
                                "iam_user": helper.iam_user,
                                "group_name": group_name,
                                "resource_type": "EC2 Instance",
                                "attachments": [instance_id],
                                "is_replaced_by_blackhole_sg": is_replaced_by_blackhole_sg,
                                "is_deleted": is_deleted
                            }
                            azure_data['Severity'] = severity
                            azure_data['Event'] = f"User {helper.iam_user} attached {group_name} security group to EC2 Instance {instance_id} which {'has been replaced by blackhole security group and' if is_replaced_by_blackhole_sg else ''} {'has been deleted' if is_deleted else 'hasnt been deleted because its also attached to some other resource'}"
                            alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                            alerts_handler.handler('launch_wizard_security_group_replaced', alert_args, email_messenger, slack_bot)
            else:
                LOGGER.info("Not notifying")
        except Exception as error:
            LOGGER.error(str(error))
    else:
        LOGGER.info("Network Interface Attributes were not modified for some reason")
