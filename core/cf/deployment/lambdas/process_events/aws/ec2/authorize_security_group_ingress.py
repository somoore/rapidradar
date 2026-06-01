from utils.ec2 import EC2
from utils.utility import AWSHelper, Helper, Alert
from utils.logger import LOGGER
from utils.events import Events
from utils.dynamodb import (
    SecurityGroupsData,
    GetData
)
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, slack_oauth_token, sender_email, send_logs_to_azure, customer_id, shared_key, log_type, table_name, ec2_security_group_ingress_remote_access_ports, ec2_security_group_ingress_traffic_ports, ec2_security_group_ingress_ignore_ports, loadbalancer_security_group_ingress_remote_access_ports, loadbalancer_security_group_ingress_traffic_ports, loadbalancer_security_group_ingress_ignore_ports, target_arn, auto_delete_all_traffic_sg_rule, auto_remediate_remote_access_ports, auto_remediate_traffic_ports, auto_remediate_launch_wizard_sg, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    if 'errorCode' not in event and 'responseElements' in event and 'requestParameters' in event:
        response_elements = event['responseElements']
        request_params = event['requestParameters']
        security_group_id = request_params['groupId']
        active_session = helper.get_active_session()
        ec2_utils = EC2(active_session, helper.region)
        events_utils = Events(helper.account_id, helper.region)
        messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
        email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
        slack_bot = None
        if slack_oauth_token:
            slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)
        try:
            group_name = ec2_utils.get_security_group_name(security_group_id)
            if group_name is not None:
                if not group_name.startswith('launch-wizard-') or not auto_remediate_launch_wizard_sg:
                    found_suppression_tag = GetData(table_name).found_suppression_tag(helper.account_id, 'security_group_id', security_group_id)
                    is_attached, attached_ec2_instances, attached_loadbalancers = ec2_utils.found_security_group_attachments(security_group_id)

                    public_instances = []
                    internet_facing_lb = []
                    for instance in attached_ec2_instances:
                        if not ec2_utils.is_instance_private(instance['ResourceId']):
                            public_instances.append(instance['ResourceId'])
                    for lb in attached_loadbalancers:
                        if lb['Context'] == 'Inbound & Outbound':
                            internet_facing_lb.append(lb['ResourceId'])

                    new_ports = []
                    new_pagerduty_incidents_ids = []
                    for item in response_elements['securityGroupRuleSet']['items']:
                        if 'cidrIpv4' in item and not item['isEgress'] and item['cidrIpv4'] == '0.0.0.0/0':
                            security_group_rule_id = item['securityGroupRuleId']
                            ip_protocol = item['ipProtocol']
                            is_all_traffic_open = Helper().is_all_traffic_port(ip_protocol)
                            port = item['fromPort'] if item['fromPort']==item['toPort'] else f"{item['fromPort']}-{item['toPort']}"
                            is_critical_finding = False
                            is_high_finding = False
                            is_medium_finding = False
                            is_low_finding = False

                            if not Helper().matches_given_ports(port, ip_protocol, ec2_security_group_ingress_ignore_ports, True) and not Helper().matches_given_ports(port, ip_protocol, loadbalancer_security_group_ingress_ignore_ports, True):
                                new_ports.append({"Port": port, "Protocol": ip_protocol, "UserIpAddress": helper.user_ip_address})
                                if is_all_traffic_open:
                                    if is_attached:
                                        if public_instances or internet_facing_lb:
                                            is_critical_finding = True
                                        else:
                                            is_medium_finding = True
                                    else:
                                        is_low_finding = True
                                    if is_critical_finding and auto_delete_all_traffic_sg_rule:
                                        if not events_utils.create_security_group_rule_remediation_cron(security_group_id, port, ip_protocol, target_arn):
                                            LOGGER.error("Could not create All Traffic Events Rule")
                                elif Helper().matches_given_ports(port, ip_protocol, ec2_security_group_ingress_remote_access_ports, False) or Helper().matches_given_ports(port, ip_protocol, loadbalancer_security_group_ingress_remote_access_ports, False):
                                    if is_attached:
                                        if public_instances or internet_facing_lb:
                                            is_critical_finding = True
                                        else:
                                            is_medium_finding = True
                                    else:
                                        is_low_finding = True
                                    if is_critical_finding and auto_remediate_remote_access_ports:
                                        if not events_utils.create_security_group_rule_remediation_cron(security_group_id, port, ip_protocol, target_arn):
                                            LOGGER.error("Could not create Security Group rule remediation cron for Security Group %s for remote access port %s", security_group_id, str(port))
                                elif Helper().matches_given_ports(port, ip_protocol, ec2_security_group_ingress_traffic_ports, False) or Helper().matches_given_ports(port, ip_protocol, loadbalancer_security_group_ingress_traffic_ports, False):
                                    if is_attached:
                                        if public_instances or internet_facing_lb:
                                            is_high_finding = True
                                        else:
                                            is_low_finding = True
                                    else:
                                        is_low_finding = True
                                    if is_high_finding and auto_remediate_traffic_ports:
                                        if not events_utils.create_security_group_rule_remediation_cron(security_group_id, port, ip_protocol, target_arn):
                                            LOGGER.error("Could not create Security Group rule remediation cron for Security Group %s for traffic port %s", security_group_id, str(port))
                                else:
                                    is_low_finding = True

                                if is_critical_finding or is_high_finding or is_medium_finding or is_low_finding:
                                    severity = 'Critical' if is_critical_finding else 'High' if is_high_finding else 'Medium' if is_medium_finding else 'Low'
                                    alert_args = {
                                        "severity": severity,
                                        "iam_user": helper.iam_user,
                                        "ip_protocol": 'All traffic' if is_all_traffic_open else ip_protocol,
                                        "port": 'All' if is_all_traffic_open else port,
                                        "security_group_id": security_group_id,
                                        "security_group_rule_id": security_group_rule_id,
                                        "is_attached": is_attached,
                                        "attached_instances": attached_ec2_instances,
                                        "attached_lb": attached_loadbalancers,
                                        "is_critical": True if is_critical_finding else False
                                    }
                                    azure_data = {
                                        "Severity": severity,
                                        "AccountID": helper.account_id,
                                        "AccountName": messenger.account_name,
                                        "Region": helper.region,
                                        "User": helper.iam_user,
                                        "Event": f"User {helper.iam_user} opened a {'All traffic' if is_all_traffic_open else ip_protocol} port {'' if is_all_traffic_open else str(port)+' '}to 0.0.0.0/0 in Security Group Ingress of Security Group {security_group_id}."
                                    }
                                    if not found_suppression_tag:
                                        alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                                        pagerduty_incident_id = alerts_handler.handler('security_group_ingress_open_to_all', alert_args, email_messenger, slack_bot)
                                        if pagerduty_incident_id:
                                            new_pagerduty_incidents_ids.append(pagerduty_incident_id)
                            else:
                                LOGGER.info("Is a port to be bypassed. Skipping...")

                    security_group_open_ports = ec2_utils.get_security_group_open_ports(security_group_id)
                    if security_group_open_ports[0]:
                        ports_userip = []
                        scan_records = GetData(table_name).get_by_id('account_id', helper.account_id, 'security_group_id', security_group_id)
                        updated_incident_ids = []
                        if pagerduty_helper is not None and scan_records and is_pd_integration_type_restapi:
                            if 'pagerduty_incident_id' in scan_records[0]:
                                for incident_id in scan_records[0]['pagerduty_incident_id']['SS']:
                                    incident_status, incident_number, incident_url = pagerduty_helper.get_incident_details(incident_id)
                                    if incident_status not in ['resolved']:
                                        updated_incident_ids.append(incident_id)
                            elif 'pagerduty_dedup_keys' in scan_records[0]:
                                for dedup_key in scan_records[0]['pagerduty_dedup_keys']['SS']:
                                    updated_incident_ids.append(dedup_key)
                        if new_pagerduty_incidents_ids:
                            updated_incident_ids += new_pagerduty_incidents_ids
                        for item in security_group_open_ports[1]:
                            if not Helper().matches_given_ports(item['Port'], item['Protocol'], ec2_security_group_ingress_ignore_ports, True) and not Helper().matches_given_ports(item['Port'], item['Protocol'], loadbalancer_security_group_ingress_ignore_ports, True):
                                port_userip = Helper().extract_ports_with_userip(item, scan_records)
                                is_new_port = False
                                for new_port in new_ports:
                                    if item['Port'] == new_port['Port'] and item['Protocol'] == new_port['Protocol']:
                                        is_new_port = True
                                        port_userip = new_port

                                if not is_new_port:
                                    if public_instances or internet_facing_lb:
                                        group_rule_id = item['RuleId']
                                        if Helper().is_all_traffic_port(item['Port']):
                                            if auto_delete_all_traffic_sg_rule:
                                                if not ec2_utils.delete_security_group_rule(security_group_id, group_rule_id):
                                                    LOGGER.error("Could not delete security group rule with all traffic open to public for Security Group %s in Account=%s and Region=%s", security_group_id, helper.account_id, helper.region)
                                        elif Helper().matches_given_ports(item['Port'], item['Protocol'], ec2_security_group_ingress_remote_access_ports, False) or Helper().matches_given_ports(item['Port'], item['Protocol'], loadbalancer_security_group_ingress_remote_access_ports, False):
                                            if auto_remediate_remote_access_ports:
                                                if not ec2_utils.delete_security_group_rule(security_group_id, group_rule_id):
                                                    LOGGER.error("Could not delete security group rule with remote access port open to public for Security Group %s in Account=%s and Region=%s", security_group_id, helper.account_id, helper.region)
                                        elif Helper().matches_given_ports(item['Port'], item['Protocol'], ec2_security_group_ingress_traffic_ports, False) or Helper().matches_given_ports(item['Port'], item['Protocol'], loadbalancer_security_group_ingress_traffic_ports, False):
                                            if auto_remediate_traffic_ports:
                                                if not ec2_utils.delete_security_group_rule(security_group_id, group_rule_id):
                                                    LOGGER.error("Could not delete security group rule with traffic port %s open to public for Security Group %s in Account=%s and Region=%s", str(item['Port']), security_group_id, helper.account_id, helper.region)
                                if port_userip:
                                    ports_userip.append(Helper().format_ports_entry(port_userip['Port'], port_userip['Protocol'], port_userip['UserIpAddress']))
                                else:
                                    ports_userip.append(Helper().format_ports_entry(item['Port'], item['Protocol'], ''))
                        if not SecurityGroupsData(table_name).store(helper.account_id, helper.region, security_group_id, ports_userip, is_attached, found_suppression_tag, pagerduty_incident_id=updated_incident_ids if is_pd_integration_type_restapi else None, pagerduty_dedup_keys=None if is_pd_integration_type_restapi else updated_incident_ids):
                            LOGGER.error("Could not add metadata for Security Group %s in Account ID=%s and Region=%s", security_group_id, helper.account_id, helper.region)
                    else:
                        LOGGER.info("No ports are open in security group %s", security_group_id)
                else:
                    LOGGER.info("Is a Launch Wizard Security Group and auto-remediation is enabled. Skipping...")
        except Exception as error:
            LOGGER.error(str(error))
