import json
from utils.sts import DecodeMessage
from utils.ec2 import EC2
from utils.events import Events
from utils.utility import AWSHelper, Helper, Alert
from utils.logger import LOGGER
from utils.dynamodb import (
    SecurityGroupsData,
    ActiveResourcesData,
    GetData
)
from utils.ssm import SSM
from utils.pricing import Pricing
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, event_time, sender_email, notification_app, webhook_urls, slack_oauth_token, send_logs_to_azure, customer_id, shared_key, log_type, sg_table_name, ec2_security_group_ingress_remote_access_ports, ec2_security_group_ingress_traffic_ports, ec2_security_group_ingress_ignore_ports, active_resources_table, deploy_cmdb_project, project_name, tag_ec2_instances, tag_ec2_instances_using_tag_template_for_tf_deployment, ec2_tags_key_value, auto_delete_all_traffic_sg_rule, auto_remediate_remote_access_ports, auto_remediate_traffic_ports, disable_finding_for_ec2_launch_wo_imdsv2, ec2_launch_blocked_wo_imdsv2, ec2_launch_blocked_wo_imdsv2_bypass_tag_key, alert_on_ec2_launch_imdsv2_bypass, disable_finding_for_ec2_launch_w_public_ip, ec2_launch_blocked_w_public_ip, ec2_launch_blocked_w_public_ip_bypass_tag_key, alert_on_ec2_launch_public_ip_bypass, ec2_launch_blocked_wo_certain_tags, ec2_instance_launch_scp_tag_keys, disable_finding_for_unencrypted_ebs_volume, unencrypted_ebs_volume_creation_blocked, unencrypted_ebs_volume_creation_blocked_bypass_tag_key, alert_on_unencrypted_ebs_volume_creation_bypass, aws_service_deployment_action, send_missing_tags_notification_ec2_instances, target_arn, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
    email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
    slack_bot = None
    if slack_oauth_token:
        slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)
    active_session = helper.get_active_session()
    ec2_utils = EC2(active_session, helper.region)
    events_utils = Events(helper.account_id, helper.region)
    pricing_utils = Pricing(active_session, helper.region)
    ssm_utils = SSM(active_session, helper.region)
    event_by, account_name = helper.get_cmdb_event_details()

    if 'errorCode' in event and 'errorMessage' in event and event['errorCode'] == 'Client.UnauthorizedOperation':
        if 'requestParameters' in event:
            request_params = event['requestParameters']
            instance_tag_keys = []
            found_imdsv2_bypass_tag_key = False
            found_public_ip_bypass_tag_key = False
            found_unencrypted_ebs_volume_bypass_tag_key = False
            if 'tagSpecificationSet' in request_params and 'items' in request_params['tagSpecificationSet']:
                for item in request_params['tagSpecificationSet']['items']:
                    if item['resourceType'] == 'instance':
                        for tag in item['tags']:
                            instance_tag_keys.append(tag['key'])
                            if tag['key'] == ec2_launch_blocked_wo_imdsv2_bypass_tag_key:
                                found_imdsv2_bypass_tag_key = True
                    elif item['resourceType'] == 'network-interface':
                        for tag in item['tags']:
                            if tag['key'] == ec2_launch_blocked_w_public_ip_bypass_tag_key:
                                found_public_ip_bypass_tag_key = True
                    elif item['resourceType'] == 'volume':
                        for tag in item['tags']:
                            if tag['key'] == unencrypted_ebs_volume_creation_blocked_bypass_tag_key:
                                found_unencrypted_ebs_volume_bypass_tag_key = True
            severity = 'Informational'
            encoded_error_message = event['errorMessage'].split(': ')[-1].strip()
            if not encoded_error_message.endswith('...'):
                decoded_message = DecodeMessage(active_session, encoded_error_message).decoded_message
                LOGGER.debug(decoded_message)

                if len(decoded_message['matchedStatements']['items']) > 0:
                    for item in decoded_message['matchedStatements']['items']:
                        azure_data = {
                            "Severity": severity,
                            "AccountID": helper.account_id,
                            "AccountName": messenger.account_name,
                            "Region": helper.region,
                            "User": helper.iam_user
                        }
                        if 'statementId' in item:
                            alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                            if 'IMDSV2' in item['statementId'] and not found_imdsv2_bypass_tag_key:
                                alert_args = {
                                    "severity": severity,
                                    "iam_user": helper.iam_user,
                                    "bypass_tag_key": ec2_launch_blocked_wo_imdsv2_bypass_tag_key,
                                    "is_imdsv2_failure": True
                                }
                                azure_data['Event'] = f"User {helper.iam_user} tried to launch EC2 Instance without enabling IMDSv2 which failed due to an SCP policy"
                                alerts_handler.handler('ec2_launch_scp_block_error_message', alert_args, email_messenger, slack_bot)
                            if 'PublicIp' in item['statementId'] and not found_public_ip_bypass_tag_key:
                                alert_args = {
                                    "severity": severity,
                                    "iam_user": helper.iam_user,
                                    "is_publicip_failure": True
                                }
                                azure_data['Event'] = f"User {helper.iam_user} tried to launch EC2 Instance with public IP which failed due to an SCP policy"
                                alerts_handler.handler('ec2_launch_scp_block_error_message', alert_args, email_messenger, slack_bot)
                            if 'UnencryptedVol' in item['statementId'] and not found_unencrypted_ebs_volume_bypass_tag_key:
                                alert_args = {
                                    "severity": severity,
                                    "iam_user": helper.iam_user,
                                    "bypass_tag_key": unencrypted_ebs_volume_creation_blocked_bypass_tag_key,
                                    "is_unencrypted_ebs_failure": True
                                }
                                azure_data['Event'] = f"User {helper.iam_user} tried to launch EC2 Instance without enabling encryption on Root EBS Volume which failed due to an SCP policy"
                                alerts_handler.handler('ec2_launch_scp_block_error_message', alert_args, email_messenger, slack_bot)
                            if item['statementId'].startswith('DenyRunInstancesWithoutTags') and deploy_cmdb_project:
                                severity = 'Informational'
                                missing_tags = []
                                for scp_tag in ec2_instance_launch_scp_tag_keys:
                                    if scp_tag not in instance_tag_keys:
                                        missing_tags.append(scp_tag)
                                alert_args = {
                                    "severity": severity,
                                    "resource_type": "EC2 Instance",
                                    "iam_user": helper.iam_user,
                                    "tags": missing_tags
                                }
                                azure_data['Event'] = f"User {helper.iam_user} tried to launch EC2 Instance with missing tags {missing_tags} which failed due to an SCP policy"
                                alerts_handler.handler('resource_creation_wo_required_tags_scp_block_error_message', alert_args, email_messenger, slack_bot)
                else:
                    LOGGER.info("Deployment didn't fail because of SCP")
            elif encoded_error_message.endswith('...'):
                LOGGER.info("EC2 Deployment Failed Because of SCP, but could not decode encoded error message in CloudTrail API because it got truncated, as it can only consist of 1024B")
                is_root_vol_encrypted = False
                is_imdsv2_enabled = False
                found_failure_reason = False

                # Check if EC2 launch failed because of certain missing tags
                if ec2_launch_blocked_wo_certain_tags:
                    alert_args = {
                        "severity": severity,
                        "iam_user": helper.iam_user
                    }
                    azure_data = {
                        "Severity": severity,
                        "AccountID": helper.account_id,
                        "AccountName": messenger.account_name,
                        "Region": helper.region,
                        "User": helper.iam_user
                    }
                    missing_tags = []
                    for scp_tag in ec2_instance_launch_scp_tag_keys:
                        if scp_tag not in instance_tag_keys:
                            missing_tags.append(scp_tag)

                    if not all(value in instance_tag_keys for value in ec2_instance_launch_scp_tag_keys):
                        if not found_failure_reason:
                            found_failure_reason = True
                            severity = 'Informational'
                            alert_args = {
                                "severity": severity,
                                "resource_type": "EC2 Instance",
                                "iam_user": helper.iam_user,
                                "tags": missing_tags
                            }
                            azure_data['Event'] = f"User {helper.iam_user} tried to launch EC2 Instance with missing tags {missing_tags} which failed due to an SCP policy"
                            alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                            alerts_handler.handler('resource_creation_wo_required_tags_scp_block_error_message', alert_args, email_messenger, slack_bot)

                # Check if EC2 launch failed because of public IP
                if ec2_launch_blocked_w_public_ip and not found_public_ip_bypass_tag_key:
                    alert_args = {
                        "severity": severity,
                        "iam_user": helper.iam_user,
                        "is_publicip_failure": True
                    }
                    azure_data = {
                        "Severity": severity,
                        "AccountID": helper.account_id,
                        "AccountName": messenger.account_name,
                        "Region": helper.region,
                        "User": helper.iam_user
                    }
                    if 'networkInterfaceSet' in request_params and 'items' in request_params['networkInterfaceSet']:
                        for item in request_params['networkInterfaceSet']['items']:
                            if 'associatePublicIpAddress' in item and item['associatePublicIpAddress'] and not found_failure_reason:
                                found_failure_reason = True
                                azure_data['Event'] = f"User {helper.iam_user} tried to launch EC2 Instance with public IP which failed due to an SCP policy"
                                alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                                alerts_handler.handler('ec2_launch_scp_block_error_message', alert_args, email_messenger, slack_bot)
                # Check if EC2 launch failed because of disabled IMDSv2
                if ec2_launch_blocked_wo_imdsv2 and not found_imdsv2_bypass_tag_key:
                    alert_args = {
                        "severity": severity,
                        "iam_user": helper.iam_user,
                        "bypass_tag_key": ec2_launch_blocked_wo_imdsv2_bypass_tag_key,
                        "is_imdsv2_failure": True
                    }
                    azure_data = {
                        "Severity": severity,
                        "AccountID": helper.account_id,
                        "AccountName": messenger.account_name,
                        "Region": helper.region,
                        "User": helper.iam_user
                    }
                    if 'metadataOptions' in request_params and 'httpTokens' in request_params['metadataOptions'] and request_params['metadataOptions']['httpTokens'] == 'required':
                        is_imdsv2_enabled = True
                        LOGGER.info("IMDSV2 is enabled.")
                    else:
                        if not is_imdsv2_enabled and not found_failure_reason:
                            found_failure_reason = True
                            azure_data['Event'] = f"User {helper.iam_user} tried to launch EC2 Instance without enabling IMDSv2 which failed due to an SCP policy"
                            alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                            alerts_handler.handler('ec2_launch_scp_block_error_message', alert_args, email_messenger, slack_bot)

                # Check if EC2 launch failed because of unencrypted Root EBS Volume
                if 'items' in request_params['blockDeviceMapping']:
                    is_root_vol_encrypted = request_params['blockDeviceMapping']['items'][0]['ebs']['encrypted']
                if not is_root_vol_encrypted and not found_failure_reason and not found_unencrypted_ebs_volume_bypass_tag_key:
                    alert_args = {
                        "severity": severity,
                        "iam_user": helper.iam_user,
                        "bypass_tag_key": unencrypted_ebs_volume_creation_blocked_bypass_tag_key,
                        "is_unencrypted_ebs_failure": True
                    }
                    azure_data = {
                        "Severity": severity,
                        "AccountID": helper.account_id,
                        "AccountName": messenger.account_name,
                        "Region": helper.region,
                        "User": helper.iam_user
                    }
                    azure_data['Event'] = f"User {helper.iam_user} tried to launch EC2 Instance without enabling encryption on Root EBS Volume which failed due to an SCP policy"
                    alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, email_messenger, azure_data, customer_id, shared_key, log_type)
                    alerts_handler.handler('ec2_launch_scp_block_error_message', alert_args, email_messenger, slack_bot)
        else:
            LOGGER.info("requestParameters block not found in event response")
    else:
        instances = []
        skip_notifier = False
        public_ip_bypass_tag_found = False
        if 'responseElements' in event and 'requestParameters' in event:
            response_elements = event['responseElements']
            request_params = event['requestParameters']

            if response_elements is not None and 'omitted' in response_elements and response_elements['omitted']:
                LOGGER.info("%s. Instances will be handled using EC2 Instance State Change Event Rule. Exiting now..", response_elements['reason'])
                return
            is_public_ip_associated = None
            imdsv2_not_enabled = None
            is_unencrypted_root_ebs_vol = None
            is_missing_tags = []
            azure_data = {
                "AccountID": helper.account_id,
                "AccountName": messenger.account_name,
                "Region": helper.region,
                "User": helper.iam_user
            }

            if response_elements is not None and 'instancesSet' in response_elements and 'items' in response_elements['instancesSet']:
                found_imdsv2_bypass_tag_key = False
                found_unencrypted_ebs_volume_bypass_tag_key = False
                imdsv2_enabled = False
                is_root_vol_encrypted = False
                security_groups = []
                resource_type = 'EC2Instance'
                found_tf_deploy_method = False
                is_tf_deployment = False

                instances = [ item['instanceId'] for item in response_elements['instancesSet']['items'] ]
                if 'tagSpecificationSet' in request_params and 'items' in request_params['tagSpecificationSet']:
                    for item in request_params['tagSpecificationSet']['items']:
                        if item['resourceType'] == 'instance':
                            for tag in item['tags']:
                                if tag['key'] == ec2_launch_blocked_wo_imdsv2_bypass_tag_key:
                                    found_imdsv2_bypass_tag_key = True
                        elif item['resourceType'] == 'network-interface':
                            for tag in item['tags']:
                                if tag['key'] == ec2_launch_blocked_w_public_ip_bypass_tag_key:
                                    public_ip_bypass_tag_found = True
                        elif item['resourceType'] == 'volume':
                            for tag in item['tags']:
                                if tag['key'] == unencrypted_ebs_volume_creation_blocked_bypass_tag_key:
                                    found_unencrypted_ebs_volume_bypass_tag_key = True

                public_instances = []
                if 'networkInterfaceSet' in request_params and 'items' in request_params['networkInterfaceSet']:
                    for item in request_params['networkInterfaceSet']['items']:
                        if 'associatePublicIpAddress' in item and item['associatePublicIpAddress']:
                            public_instances = [instances]
                            if helper.is_invoked_by_service is not None:
                                if ec2_launch_blocked_w_public_ip and not public_ip_bypass_tag_found:
                                    is_public_ip_associated = '• Disassociate Public IP'
                            else:
                                severity = 'Informational' if public_ip_bypass_tag_found else 'High'
                                alert_args = {
                                    "severity": severity,
                                    "iam_user": helper.iam_user,
                                    "instance_id": ', '.join(instances),
                                    "found_bypass_tag": public_ip_bypass_tag_found,
                                    "is_publicip": True
                                }
                                azure_data['Severity'] = severity
                                azure_data['Event'] = f"User {helper.iam_user} launched EC2 Instance {', '.join(instances)} {'bypassing Public IP SCP using bypass tag' if public_ip_bypass_tag_found else 'with Public IP'}"
                                if not disable_finding_for_ec2_launch_w_public_ip:
                                    alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                                    alert_id = None
                                    if ec2_launch_blocked_w_public_ip and public_ip_bypass_tag_found and alert_on_ec2_launch_public_ip_bypass:
                                        alert_id = 'ec2_launch_scp_bypass_tag_message'
                                    elif not ec2_launch_blocked_w_public_ip:
                                        alert_id = 'ec2_launch_scp_bypass_tag_message'
                                    alerts_handler.handler(alert_id, alert_args, email_messenger, slack_bot)

                for item in response_elements['instancesSet']['items']:
                    instance_id = item['instanceId']
                    instance_type = item['instanceType']
                    subnet_id = item['subnetId']
                    context = ec2_utils.get_ec2_subnet_context(subnet_id)

                    if 'groupSet' in item and 'items' in item['groupSet']:
                        security_groups = [ group['groupId'] for group in item['groupSet']['items'] ]
                    if 'metadataOptions' in item and 'httpTokens' in item['metadataOptions'] and item['metadataOptions']['httpTokens'] == 'required':
                        if 'metadataOptions' not in request_params:
                            skip_notifier = True
                        imdsv2_enabled = True
                    is_root_vol_encrypted = ec2_utils.is_instance_root_vol_encrypted(instance_id, unencrypted_ebs_volume_creation_blocked_bypass_tag_key)
                    for group_id in security_groups:
                        security_group_open_ports = ec2_utils.get_security_group_open_ports(group_id)
                        if security_group_open_ports[0]:
                            scan_records = GetData(sg_table_name).get_by_id('account_id', helper.account_id, 'security_group_id', group_id)
                            is_critical_finding = False
                            is_high_finding = False
                            is_medium_finding = False
                            ports_userip = []
                            for open_port_item in security_group_open_ports[1]:
                                if not Helper().matches_given_ports(open_port_item['Port'], open_port_item['Protocol'], ec2_security_group_ingress_ignore_ports, True):
                                    port_userip = Helper().extract_ports_with_userip(open_port_item, scan_records)
                                    group_rule_id = open_port_item['RuleId']
                                    if Helper().is_all_traffic_port(open_port_item['Port']):
                                        if public_instances:
                                            is_critical_finding = True
                                        else:
                                            is_medium_finding = True
                                        if is_critical_finding and auto_delete_all_traffic_sg_rule:
                                            if port_userip:
                                                if not events_utils.create_security_group_rule_remediation_cron(group_id, open_port_item['Port'], open_port_item['Protocol'], target_arn):
                                                    LOGGER.error("Could not create All Traffic Events Rule")
                                            else:
                                                if not ec2_utils.delete_security_group_rule(group_id, group_rule_id):
                                                    LOGGER.error("Could not delete security group rule with all traffic open to public for Security Group %s in Account=%s and Region=%s", group_id, helper.account_id, helper.region)
                                    elif Helper().matches_given_ports(open_port_item['Port'], open_port_item['Protocol'], ec2_security_group_ingress_remote_access_ports, False):
                                        if public_instances:
                                            is_critical_finding = True
                                        else:
                                            is_medium_finding = True
                                        if is_critical_finding and auto_remediate_remote_access_ports:
                                            if port_userip:
                                                if not ec2_utils.close_opened_security_group_rule(group_id, group_rule_id, open_port_item['Port'], open_port_item['Protocol'], port_userip['UserIpAddress']):
                                                    LOGGER.error("Could not close Opened Critical Port in %s", group_id)
                                                else:
                                                    severity = 'Informational'
                                                    alert_args = {
                                                        "severity": severity,
                                                        "security_group_id": group_id,
                                                        "ip_protocol": open_port_item['Protocol'],
                                                        "port": open_port_item['Port']
                                                    }
                                                    azure_data['Severity'] = severity
                                                    azure_data['Event'] = f"{'All Traffic' if Helper().is_all_traffic_port(open_port_item['Port']) else open_port_item['Protocol']} port{'' if Helper().is_all_traffic_port(open_port_item['Port']) else ' '+str(open_port_item['Port'])} was open to the 0.0.0.0/0 IP range, which is against our company's security policy. Therefore, necessary steps to {'delete' if Helper().is_all_traffic_port(open_port_item['Port']) else 'close'} this port were taken to prevent unauthorized access to your resources via Security group {group_id}"
                                                    alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                                                    alerts_handler.handler('critical_port_closed_message', alert_args, None, None)
                                            else:
                                                if not ec2_utils.delete_security_group_rule(group_id, group_rule_id):
                                                    LOGGER.error("Could not delete critical rule from Security Group %s in Account=%s and Region=%s", group_id, helper.account_id, helper.region)
                                    elif Helper().matches_given_ports(open_port_item['Port'], open_port_item['Protocol'], ec2_security_group_ingress_traffic_ports, False):
                                        if public_instances:
                                            is_high_finding = True
                                        if is_high_finding and auto_remediate_traffic_ports:
                                            if port_userip:
                                                if not ec2_utils.close_opened_security_group_rule(group_id, group_rule_id, open_port_item['Port'], open_port_item['Protocol'], port_userip['UserIpAddress']):
                                                    LOGGER.error("Could not close Opened Critical Port in %s", group_id)
                                            else:
                                                if not ec2_utils.delete_security_group_rule(group_id, group_rule_id):
                                                    LOGGER.error("Could not delete critical rule from Security Group %s in Account=%s and Region=%s", group_id, helper.account_id, helper.region)
                                    if port_userip:
                                        ports_userip.append(Helper().format_ports_entry(port_userip['Port'], port_userip['Protocol'], port_userip['UserIpAddress']))
                                    else:
                                        ports_userip.append(Helper().format_ports_entry(open_port_item['Port'], open_port_item['Protocol'], ''))

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
                                found_suppression_tag = GetData(sg_table_name).found_suppression_tag(helper.account_id, 'security_group_id', group_id)

                                severity = 'Critical' if is_critical_finding else 'High' if is_high_finding else 'Medium' if is_medium_finding else 'Low'
                                alert_args = {
                                    "severity": severity,
                                    "iam_user": helper.iam_user,
                                    "security_group_id": group_id,
                                    "resource_type": "EC2 Instance(s)",
                                    "ports": [ str(json.loads(port)['Port']) for port in ports_userip ],
                                    "is_attached": True,
                                    "attached_instances": [{'ResourceId': instance_id, 'Context': context}],
                                    "attached_lb": []
                                }
                                azure_data['Severity'] = severity
                                azure_data['Event'] = f"Security Group {group_id} with ports [{', '.join(str(json.loads(port)['Port']) for port in ports_userip).replace('-1', 'All Traffic')}] Open to 0.0.0.0/0 got attached to EC2 Instance {instance_id}"
                                if not found_suppression_tag:
                                    alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                                    updated_incident_ids.append(alerts_handler.handler('security_group_ingress_open_to_all_attached_to_public_resource', alert_args, email_messenger, slack_bot))
                                if not SecurityGroupsData(sg_table_name).store(helper.account_id, helper.region, group_id, ports_userip, True, found_suppression_tag, pagerduty_incident_id=updated_incident_ids if is_pd_integration_type_restapi else None, pagerduty_dedup_keys=None if is_pd_integration_type_restapi else updated_incident_ids):
                                    LOGGER.error("Could not add metadata for Security Group %s in Account ID=%s and Region=%s", group_id, helper.account_id, helper.region)

                    if not skip_notifier and not imdsv2_enabled:
                        if helper.is_invoked_by_service is not None:
                            if ec2_launch_blocked_wo_imdsv2 and not found_imdsv2_bypass_tag_key:
                                imdsv2_not_enabled = '• Enable IMDSv2'
                        else:
                            severity = 'Informational' if found_imdsv2_bypass_tag_key else 'High'
                            alert_args = {
                                "severity": severity,
                                "iam_user": helper.iam_user,
                                "instance_id": instance_id,
                                "found_bypass_tag": found_imdsv2_bypass_tag_key,
                                "is_imdsv2": True
                            }
                            azure_data['Severity'] = severity
                            azure_data['Event'] = f"User {helper.iam_user} launched EC2 Instance {instance_id} without enabling IMDSV2 {'with' if found_imdsv2_bypass_tag_key else 'and without using'} bypass tag"
                            if not disable_finding_for_ec2_launch_wo_imdsv2:
                                alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                                alert_id = None
                                if ec2_launch_blocked_wo_imdsv2 and found_imdsv2_bypass_tag_key and alert_on_ec2_launch_imdsv2_bypass:
                                    alert_id = 'ec2_launch_scp_bypass_tag_message'
                                elif not ec2_launch_blocked_wo_imdsv2:
                                    alert_id = 'ec2_launch_scp_bypass_tag_message'
                                alerts_handler.handler(alert_id, alert_args, email_messenger, slack_bot)

                    if not is_root_vol_encrypted:
                        if helper.is_invoked_by_service is not None:
                            if unencrypted_ebs_volume_creation_blocked and not found_unencrypted_ebs_volume_bypass_tag_key:
                                is_unencrypted_root_ebs_vol = '• Attach Encrypted Root EBS Volume'
                        else:
                            severity = 'Informational' if found_unencrypted_ebs_volume_bypass_tag_key else 'High'
                            alert_args = {
                                "severity": severity,
                                "iam_user": helper.iam_user,
                                "instance_id": instance_id,
                                "found_bypass_tag": found_unencrypted_ebs_volume_bypass_tag_key
                            }
                            azure_data['Severity'] = severity
                            azure_data['Event'] = f"User {helper.iam_user} launched EC2 Instance {instance_id} with unencrypted Root EBS Volume{' against SCP applied on your Organization using bypass tag' if found_unencrypted_ebs_volume_bypass_tag_key else ''}"
                            if not disable_finding_for_unencrypted_ebs_volume:
                                alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                                alert_id = None
                                if unencrypted_ebs_volume_creation_blocked and found_unencrypted_ebs_volume_bypass_tag_key and alert_on_unencrypted_ebs_volume_creation_bypass:
                                    alert_id = 'root_volume_unencrypted_bypass_tag_message'
                                elif not unencrypted_ebs_volume_creation_blocked:
                                    alert_id = 'root_volume_unencrypted_bypass_tag_message'
                                alerts_handler.handler(alert_id, alert_args, email_messenger, slack_bot)

                    deploy_method_key_exists = False
                    deployed_by_key_exists = False
                    current_state = ''
                    if 'instanceState' in item:
                        current_state = item['instanceState']['name']
                    existing_tags = []
                    instance_tag_keys = []
                    deploy_method = ''
                    spot_request_id = ''
                    team, team_key_exists = '', False

                    if 'tagSet' in item and 'items' in item['tagSet']:
                        for tag_item in item['tagSet']['items']:
                            if 'key' in tag_item and 'value' in tag_item:
                                instance_tag_keys.append(tag_item['key'])
                                existing_tags.append(f"{tag_item['key']}: {tag_item['value']}")
                                if tag_item['key'].startswith('aws:ec2spot:'):
                                    spot_request_id = tag_item['value']
                                if tag_item['key'] in ['DeployMethod', 'deployMethod', 'Deploymethod', 'deploymethod']:
                                    deploy_method = tag_item['value']
                                    deploy_method_key_exists = True
                                    if deploy_method in ['Terraform','terraform']:
                                        found_tf_deploy_method = True
                                if tag_item['key'] in ['Team', 'team']:
                                    team = tag_item['value']
                                    team_key_exists = True
                                if tag_item['key'] in ['DeployedBy', 'deployedBy', 'Deployedby', 'deployedby']:
                                    event_by = tag_item['value']
                                    deployed_by_key_exists = True

                    if 'Terraform' in helper.user_agent or found_tf_deploy_method:
                        is_tf_deployment = True

                    if deploy_cmdb_project:
                        cost_type, tenancy, usage_operation, platform_detail, platform = ec2_utils.get_instance_cost_details(instance_id)
                        hourly_cost, daily_cost, monthly_cost = '', '', ''
                        is_instance_ssm_managed = 'Yes' if ssm_utils.is_instance_ssm_managed(instance_id) else 'No'
                        is_imdsv2_enabled = 'Yes' if ec2_utils.is_instance_imdsv2_enabled(instance_id) else 'No'
                        if cost_type:
                            if cost_type == 'spot':
                                hourly_cost, daily_cost, monthly_cost = ec2_utils.get_spot_price(instance_type, platform_detail, spot_request_id)
                            else:
                                hourly_cost, daily_cost, monthly_cost = pricing_utils.get_instance_cost(instance_type, cost_type, usage_operation, tenancy)

                        print(hourly_cost, daily_cost, monthly_cost)

                        if not deploy_method_key_exists:
                            deploy_method='aws-console'
                            ec2_utils.add_tags_to_ec2_resource(instance_id, [{'Key': 'DeployMethod', 'Value': deploy_method}])
                        if not deployed_by_key_exists:
                            ec2_utils.add_tags_to_ec2_resource(instance_id, [{'Key': 'DeployedBy', 'Value': event_by}])
                        if not team_key_exists:
                            team='unknown'
                            ec2_utils.add_tags_to_ec2_resource(instance_id, [{'Key': 'Team', 'Value': team}])
                        if not ActiveResourcesData(active_resources_table).store(helper.account_id, account_name, helper.region, deploy_method, team, event_by, instance_id, instance_type, resource_type, current_state, '', event_time, event_time, hourly_cost, daily_cost, monthly_cost, cost_type, platform, is_instance_ssm_managed, is_imdsv2_enabled, existing_tags if existing_tags else [""]):
                            LOGGER.error("Could not store data for Instance %s in Account=%s and Region=%s", instance_id, helper.account_id, helper.region)
                    if ec2_launch_blocked_wo_certain_tags:
                        for tag in ec2_instance_launch_scp_tag_keys:
                            if tag not in instance_tag_keys:
                                is_missing_tags.append(tag)
                    elif send_missing_tags_notification_ec2_instances and not tag_ec2_instances:
                        ec2_tags_key_value_missing = []
                        for tag in ec2_tags_key_value:
                            tag_key = tag.split('=')[0]
                            if tag_key not in instance_tag_keys:
                                ec2_tags_key_value_missing.append(tag)
                        if not all(value in instance_tag_keys for value in ec2_tags_key_value):
                            severity = 'Low'
                            alert_args = {
                                "severity": severity,
                                "iam_user": helper.iam_user,
                                "resource_type": "EC2 Instance",
                                "resource_id": instance_id,
                                "tags": ec2_tags_key_value_missing
                            }
                            azure_data['Severity'] = severity
                            azure_data['Event'] = f"User {helper.iam_user} launched EC2 Instance {instance_id} with missing tags [{', '.join(ec2_tags_key_value_missing)}]"
                            alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                            alerts_handler.handler('resource_creation_without_tags_message', alert_args, email_messenger, slack_bot)

                    if tag_ec2_instances:
                        use_params_tags = True
                        if tag_ec2_instances_using_tag_template_for_tf_deployment and is_tf_deployment:
                            decrypted_value = json.loads(ssm_utils.get_decrypted_value(f'/{project_name}/EC2_INSTANCE_TAG_TEMPLATE'))
                            for key, value in decrypted_value.items():
                                if value != f"< {key.upper()} >":
                                    use_params_tags = False
                                    if not ec2_utils.add_tags_to_ec2_resource(instance_id, [{'Key': key, 'Value': value}]):
                                        LOGGER.error("Could not add tag %s to EC2 Instance %s in Account=%s and Region=%s", key, instance_id, helper.account_id, helper.region)
                        if use_params_tags:
                            for ec2_tag in ec2_tags_key_value:
                                key_value = ec2_tag.split('=')
                                if deploy_method_key_exists and key_value[0] in ['DeployMethod', 'deployMethod', 'Deploymethod', 'deploymethod']:
                                    continue
                                if deployed_by_key_exists and key_value[0] in ['DeployedBy', 'deployedBy', 'Deployedby', 'deployedby']:
                                    continue
                                if not ec2_utils.add_tags_to_ec2_resource(instance_id, [{'Key': key_value[0], 'Value': key_value[1]}]):
                                    LOGGER.error("Could not add tag %s to EC2 Instance %s", key_value[0], instance_id)
            if helper.is_invoked_by_service is not None:
                if aws_service_deployment_action == 'Delete':
                    if is_public_ip_associated is not None or imdsv2_not_enabled is not None or is_unencrypted_root_ebs_vol is not None or is_missing_tags:
                        to_do_list = []
                        if is_public_ip_associated:
                            to_do_list.append(is_public_ip_associated)
                        if imdsv2_not_enabled:
                            to_do_list.append(imdsv2_not_enabled)
                        if is_unencrypted_root_ebs_vol:
                            to_do_list.append(is_unencrypted_root_ebs_vol)
                        if is_missing_tags:
                            to_do_list_tags = f"• Add Following missing tags: [{', '.join(list(set(is_missing_tags)))}]"
                            to_do_list.append(to_do_list_tags)

                        severity = 'Critical'
                        alert_args = {
                            "severity": severity,
                            "instances": instances,
                            "service": helper.is_invoked_by_service,
                            "action": aws_service_deployment_action,
                            "to_do_list": to_do_list
                        }
                        alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, False, azure_data, customer_id, shared_key, log_type)
                        alerts_handler.handler('ec2_creation_invoked_by_aws_service_action_message', alert_args, None, None)
                        for instance in instances:
                            if not events_utils.create_10_min_delete_scp_bypassed_resource_rule(instance, target_arn):
                                LOGGER.error("Could not create 10 min scheduler for deletion of scp bypassed resource %s", instance)
        else:
            LOGGER.info("responseElements or requestParameters not found in event details. Not notifying...")
