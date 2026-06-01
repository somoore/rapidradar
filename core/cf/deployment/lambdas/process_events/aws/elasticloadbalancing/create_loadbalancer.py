import json
import re
import time
import copy
from utils.ec2 import EC2
from utils.elb import ELB
from utils.ssm import SSM
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

def handle_event(helper: AWSHelper, event, sender_email, notification_app, webhook_urls, slack_oauth_token, send_logs_to_azure, customer_id, shared_key, log_type, security_groups_table, loadbalancer_creation_blocked, loadbalancer_creation_blocked_bypass_tag_key, alert_on_loadbalancer_creation_bypass, project_name, tag_loadbalancers, tag_loadbalancers_using_tag_template_for_tf_deployment, tags_key_value_loadbalancers, send_missing_tags_notification_loadbalancers, aws_service_deployment_action, target_arn, loadbalancer_security_group_ingress_remote_access_ports, loadbalancer_security_group_ingress_traffic_ports, loadbalancer_security_group_ingress_ignore_ports, auto_remediate_launch_wizard_sg, auto_delete_all_traffic_sg_rule, auto_remediate_remote_access_ports, auto_remediate_traffic_ports, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
    email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
    slack_bot = None
    if slack_oauth_token:
        slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)
    active_session = helper.get_active_session()
    ec2_utils = EC2(active_session, helper.region)
    elb_utils = ELB(active_session, helper.region)
    ssm_utils = SSM(active_session, helper.region)
    events_utils = Events(helper.account_id, helper.region)
    azure_data = {
        "AccountID": helper.account_id,
        "AccountName": messenger.account_name,
        "Region": helper.region,
        "User": helper.iam_user
    }

    if 'errorCode' not in event and 'responseElements' in event and 'requestParameters' in event:
        response_elements = event['responseElements']
        request_params = event['requestParameters']
        try:
            loadbalancer_name = response_elements['loadBalancers'][0]['loadBalancerName'] if 'loadBalancers' in response_elements else request_params['loadBalancerName']
            loadbalancer_type = request_params['type'].capitalize() if 'type' in request_params else 'Classic'
            lb_prefix = 'clb'
            if loadbalancer_type == 'Application':
                lb_prefix = 'alb'
            elif loadbalancer_type == 'Network':
                lb_prefix = 'nlb'
            elif loadbalancer_type == 'Gateway':
                lb_prefix = 'glb'
            resource_id = response_elements['loadBalancers'][0]['loadBalancerArn'] if 'loadBalancers' in response_elements else loadbalancer_name
            found_tf_deploy_method = False
            is_tf_deployment = False
            loadbalancer_tag_keys = []
            found_bypass_tag = False
            vpc_id, subnet_ids, attached_security_groups, scheme = elb_utils.get_lb_details(loadbalancer_type, resource_id)

            for group_id in attached_security_groups:
                group_name = ec2_utils.get_security_group_name(group_id)
                if group_name is not None:
                    if not group_name.startswith('launch-wizard-') or not auto_remediate_launch_wizard_sg:
                        internet_facing_lb = []
                        context = ec2_utils.get_ec2_subnet_context(subnet_ids[0])
                        if context == 'Inbound & Outbound' and scheme == 'internet-facing':
                            internet_facing_lb.append(resource_id.split(f'arn:aws:elasticloadbalancing:{helper.region}:{helper.account_id}:loadbalancer/')[-1])

                        security_group_open_ports = ec2_utils.get_security_group_open_ports(group_id)
                        if security_group_open_ports[0]:
                            scan_records = GetData(security_groups_table).get_by_id('account_id', helper.account_id, 'security_group_id', group_id)
                            is_critical_finding = False
                            is_high_finding = False
                            is_medium_finding = False
                            ports_userip = []
                            for item in security_group_open_ports[1]:
                                if not Helper().matches_given_ports(item['Port'], item['Protocol'], loadbalancer_security_group_ingress_ignore_ports, True):
                                    port_userip = Helper().extract_ports_with_userip(item, scan_records)
                                    group_rule_id = item['RuleId']
                                    if Helper().is_all_traffic_port(item['Port']):
                                        if internet_facing_lb:
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
                                    elif Helper().matches_given_ports(item['Port'], item['Protocol'], loadbalancer_security_group_ingress_remote_access_ports, False):
                                        if internet_facing_lb:
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
                                    elif Helper().matches_given_ports(item['Port'], item['Protocol'], loadbalancer_security_group_ingress_traffic_ports, False):
                                        if internet_facing_lb:
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
                                found_suppression_tag = GetData(security_groups_table).found_suppression_tag(helper.account_id, 'security_group_id', group_id)

                                severity = 'Critical' if is_critical_finding else 'High' if is_high_finding else 'Medium' if is_medium_finding else 'Low'
                                alert_args = {
                                    "severity": severity,
                                    "iam_user": helper.iam_user,
                                    "security_group_id": group_id,
                                    "resource_type": "LoadBalancer",
                                    "ports": [ str(json.loads(port)['Port']) for port in ports_userip ],
                                    "is_attached": True,
                                    "attached_instances": [],
                                    "attached_lb": [{'ResourceId': resource_id.split(f'arn:aws:elasticloadbalancing:{helper.region}:{helper.account_id}:loadbalancer/')[-1], 'Context': context}]
                                }
                                azure_data['Severity'] = severity
                                azure_data['Event'] = f"Security Group {group_id} with ports [{', '.join(str(json.loads(port)['Port']) for port in ports_userip).replace('-1', 'All Traffic')}] Open to 0.0.0.0/0 got attached to LoadBalancer {resource_id}"
                                if not found_suppression_tag:
                                    alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                                    updated_incident_ids.append(alerts_handler.handler('security_group_ingress_open_to_all_attached_to_public_resource', alert_args, email_messenger, slack_bot))
                                if not SecurityGroupsData(security_groups_table).store(helper.account_id, helper.region, group_id, ports_userip, True, found_suppression_tag, pagerduty_incident_id=updated_incident_ids if is_pd_integration_type_restapi else None, pagerduty_dedup_keys=None if is_pd_integration_type_restapi else updated_incident_ids):
                                    LOGGER.error("Could not add metadata for Security Group %s in Account ID=%s and Region=%s", group_id, helper.account_id, helper.region)
                    else:
                        new_security_group_ids = copy.copy(attached_security_groups)
                        new_security_group_ids.remove(group_id)
                        is_replaced_by_blackhole_sg = False
                        if len(attached_security_groups) == 1:
                            security_group_id = ec2_utils.get_blackhole_sg_id(vpc_id, 'blackhole-security-group')
                            if security_group_id is not None:
                                new_security_group_ids.append(security_group_id)
                                is_replaced_by_blackhole_sg = True
                        if not elb_utils.update_attached_lb_security_groups(loadbalancer_type, resource_id, new_security_group_ids):
                            LOGGER.error("Could not attach updated list of security groups to loadbalancer %s in Account=%s and Region=%s", resource_id, helper.account_id, helper.region)
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
                            "resource_type": f"{loadbalancer_type} LoadBalancer",
                            "attachments": [resource_id],
                            "is_replaced_by_blackhole_sg": is_replaced_by_blackhole_sg,
                            "is_deleted": is_deleted
                        }
                        azure_data['Severity'] = severity
                        azure_data['Event'] = f"User {helper.iam_user} attached {group_name} security group to {loadbalancer_type} LoadBalancer {resource_id} which {'has been replaced by blackhole security group and' if is_replaced_by_blackhole_sg else ''} {'has been deleted' if is_deleted else 'hasnt been deleted because its also attached to some other resource'}"
                        alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                        alerts_handler.handler('launch_wizard_security_group_replaced', alert_args, email_messenger, slack_bot)

            if 'tags' in request_params:
                for tag in request_params['tags']:
                    loadbalancer_tag_keys.append(tag['key'])
                    if tag['key'] == loadbalancer_creation_blocked_bypass_tag_key:
                        found_bypass_tag = True
                    if tag['key'] in ['DeployMethod','Deploymethod','deploymethod','deployMethod']:
                        if tag['value'] in ['Terraform','terraform']:
                            found_tf_deploy_method = True

            if 'Terraform' in helper.user_agent or found_tf_deploy_method:
                is_tf_deployment = True

            if helper.is_invoked_by_service is not None:
                if loadbalancer_creation_blocked and not found_bypass_tag and aws_service_deployment_action == 'Delete':
                    severity = 'High'
                    alert_args = {
                        "severity": severity,
                        "loadbalancer": loadbalancer_name,
                        "service": helper.is_invoked_by_service,
                        "action": aws_service_deployment_action
                    }
                    alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, False, azure_data, customer_id, shared_key, log_type)
                    alerts_handler.handler('loadbalancer_creation_invoked_by_aws_service_action_message', alert_args, None, None)
                    if not events_utils.create_10_min_delete_scp_bypassed_resource_rule(f"{lb_prefix}-{loadbalancer_name}", target_arn):
                        LOGGER.error("Could not create 10 min scheduler for deletion of scp bypassed resource %s", loadbalancer_name)
            else:
                if loadbalancer_creation_blocked and found_bypass_tag and alert_on_loadbalancer_creation_bypass:
                    severity = 'Informational'
                    alert_args = {
                        "severity": severity,
                        "iam_user": helper.iam_user,
                        "loadbalancer_name": loadbalancer_name,
                        "lb_type": loadbalancer_type
                    }
                    azure_data['Severity'] = severity
                    azure_data['Event'] = f"User {helper.iam_user} created a {loadbalancer_type} LoadBalancer named {loadbalancer_name} against SCP applied on your Organization using bypass tag"
                    alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                    alerts_handler.handler('loadbalancer_creation_bypass_tag_message', alert_args, email_messenger, slack_bot)

            if tag_loadbalancers:
                use_params_tags = True
                if tag_loadbalancers_using_tag_template_for_tf_deployment and is_tf_deployment:
                    decrypted_value = json.loads(ssm_utils.get_decrypted_value(f'/{project_name}/LOADBALANCER_TAG_TEMPLATE'))
                    for key, value in decrypted_value.items():
                        if value != f"< {key.upper()} >":
                            use_params_tags = False
                            if not elb_utils.tag_loadbalancer(loadbalancer_type, resource_id, [{'Key': key, 'Value': value}]):
                                LOGGER.error("Could not add tag %s to Loadbalancer %s in Account=%s and Region=%s", key, resource_id, helper.account_id, helper.region)
                if use_params_tags:
                    for tag_key_value in tags_key_value_loadbalancers:
                        key_value = tag_key_value.split('=')
                        if key_value[0] not in loadbalancer_tag_keys:
                            if not elb_utils.tag_loadbalancer(loadbalancer_type, resource_id, [{'Key': key_value[0], 'Value': key_value[1]}]):
                                LOGGER.error("Could not add tag %s to Loadbalancer %s in Account=%s and Region=%s", key_value[0], resource_id, helper.account_id, helper.region)

            if send_missing_tags_notification_loadbalancers and not tag_loadbalancers:
                loadbalancer_tags_key_value_missing = []
                for tag in tags_key_value_loadbalancers:
                    tag_key = tag.split('=')[0]
                    if tag_key not in loadbalancer_tag_keys:
                        loadbalancer_tags_key_value_missing.append(tag)
                if not all(value in loadbalancer_tag_keys for value in tags_key_value_loadbalancers):
                    severity = 'Low'
                    alert_args = {
                        "severity": severity,
                        "iam_user": helper.iam_user,
                        "loadbalancer_name": loadbalancer_name,
                        "loadbalancer_arn": resource_id,
                        "lb_type": loadbalancer_type,
                        "tags": loadbalancer_tags_key_value_missing
                    }
                    azure_data['Severity'] = severity
                    azure_data['Event'] = f"User {helper.iam_user} created a LoadBalancer named {loadbalancer_name} of type {loadbalancer_type} without proper tags"
                    alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                    alerts_handler.handler('loadbalancer_creation_without_tags_message', alert_args, email_messenger, slack_bot)
                else:
                    LOGGER.info("LoadBalancer was created with proper tags")
        except Exception as error:
            LOGGER.error(str(error))

    elif 'errorCode' in event and event['errorCode'] == 'AccessDenied' and 'explicit deny' in event['errorMessage'] and loadbalancer_creation_blocked:
        try:
            loadbalancer_type = ''
            lb_type_match = re.search(r'arn:aws:elasticloadbalancing:'+helper.region+':'+helper.account_id+':loadbalancer/(app|net|gwy)/([A-Za-z0-9-]+)/([a-z0-9*]+)',
                                      event['errorMessage'])
            clb_type_match = re.search(r'arn:aws:elasticloadbalancing:'+helper.region+':'+helper.account_id+':loadbalancer/([A-Za-z0-9-]+)',
                                                event['errorMessage'])
            if lb_type_match is not None:
                lb_type = lb_type_match.group(0).partition(f'{helper.account_id}:loadbalancer/')[-1].split('/')[0]
                if lb_type == 'gwy':
                    loadbalancer_type = 'Gateway'
                elif lb_type == 'app':
                    loadbalancer_type = 'Application'
                elif lb_type == 'net':
                    loadbalancer_type = 'Network'
            elif clb_type_match is not None:
                loadbalancer_type = 'Classic'
            severity = 'Informational'
            alert_args = {
                "severity": severity,
                "iam_user": helper.iam_user,
                "lb_type": loadbalancer_type
            }
            azure_data['Severity'] = severity
            azure_data['Event'] = f"User {helper.iam_user} tried to create a LoadBalancer of type {loadbalancer_type} but it was blocked due to explicit deny in a service control policy"
            alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
            alerts_handler.handler('loadbalancer_creation_scp_block_error_message', alert_args, email_messenger, slack_bot)
        except Exception as error:
            LOGGER.error(str(error))
    else:
        LOGGER.info("LoadBalancer was not created for some reason")
