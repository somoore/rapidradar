from messenger.events_messenger import EventAlert
from pagerduty.main import PagerDuty
from utils.ec2 import EC2
from utils.iam import IAM
from utils.s3 import S3
from utils.ssm import SSM
from utils.eks import EKS
from utils.rds import RDS
from utils.efs import EFS
from utils.pricing import Pricing
from utils.dynamodb import (
    SecurityGroupsData,
    RemediatedResourcesData,
    ActiveResourcesData,
    DeletedResourcesData,
    IAMUsersData,
    S3BucketsData,
    UsersIPData,
    GetData,
    DeleteData
)
from utils.cloudtrail import CloudTrail
from utils.utility import AWSHelper, Alert, Helper, Tailscale
from utils.logger import LOGGER

def handle_event(engineer_facing_notification_app, engineer_facing_webhook_urls, security_admin_facing_notification_app, security_admin_facing_webhook_urls, create_incidents_on_pagerduty, is_pd_integration_type_restapi, pagerduty_routing_key, pagerduty_api_token, pagerduty_service_id, pagerduty_user_email_address, security_groups_table, ec2_security_group_ingress_remote_access_ports, ec2_security_group_ingress_traffic_ports, ec2_security_group_ingress_ignore_ports, loadbalancer_security_group_ingress_remote_access_ports, loadbalancer_security_group_ingress_traffic_ports, loadbalancer_security_group_ingress_ignore_ports, iam_table, s3_buckets_table, remediated_table_name, active_resources_table, deleted_resources_table, ip_correlation_table, track_ssm_doc_assoc_failures, create_pagerduty_incidents_for_ssm_failures, enable_hourly_ssm_failure_reminders, ssm_document_association_failure_tracker_table, send_logs_to_azure, customer_id, shared_key, log_type, deploy_cmdb_project, deploy_ip_tracker_project, track_tailscale_ips, tailnet_name, tailscale_client_id, tailscale_client_secret, auto_delete_all_traffic_sg_rule, auto_remediate_remote_access_ports, auto_remediate_traffic_ports, hourly_alerts_severity_types):
    remediated_table_ops = RemediatedResourcesData(remediated_table_name)
    active_resources_table_ops = ActiveResourcesData(active_resources_table)
    deleted_resources_table_ops = DeletedResourcesData(deleted_resources_table)
    iam_users_table_ops = IAMUsersData(iam_table)
    s3_buckets_table_ops = S3BucketsData(s3_buckets_table)

    scan_response = GetData(security_groups_table).get()
    for item in scan_response:
        is_attached = item['attached']['S']
        account_id = item['account_id']['S']
        region = item['region']['S']
        security_group_id = item['security_group_id']['S']
        detail = { 'account': account_id, 'region': region }
        helper = AWSHelper(detail)
        active_session = helper.get_active_session()
        ec2_utils = EC2(active_session, helper.region)
        messenger = EventAlert(engineer_facing_notification_app, account_id, region, engineer_facing_webhook_urls)
        try:
            is_attached, attached_ec2_instances, attached_loadbalancers = ec2_utils.found_security_group_attachments(security_group_id)
            public_instances = []
            internet_facing_lb = []
            for instance in attached_ec2_instances:
                if not ec2_utils.is_instance_private(instance['ResourceId']):
                    public_instances.append(instance['ResourceId'])
            for lb in attached_loadbalancers:
                if lb['Context'] == 'Inbound & Outbound':
                    internet_facing_lb.append(lb['ResourceId'])

            is_critical_finding = False
            is_high_finding = False
            is_medium_finding = False
            ports_userip = []
            open_ports = []
            all_open_ports = []
            azure_data = {
                "AccountID": account_id,
                "AccountName": messenger.account_name,
                "Region": region,
                "User": "threatOps"
            }
            security_group_open_ports = ec2_utils.get_security_group_open_ports(security_group_id)
            if security_group_open_ports[0]:
                scan_records = [item]
                for open_port_item in security_group_open_ports[1]:
                    if not Helper().matches_given_ports(open_port_item['Port'], open_port_item['Protocol'], ec2_security_group_ingress_ignore_ports, True) and not Helper().matches_given_ports(open_port_item['Port'], open_port_item['Protocol'], loadbalancer_security_group_ingress_ignore_ports, True):
                        all_open_ports.append(str(open_port_item['Port']))
                        port_userip = Helper().extract_ports_with_userip(open_port_item, scan_records)
                        is_rule_deleted = False

                        if is_attached:
                            group_rule_id = open_port_item['RuleId']
                            user_ip_address = port_userip['UserIpAddress'] if 'UserIpAddress' in port_userip else ''
                            if Helper().is_all_traffic_port(open_port_item['Port']):
                                if public_instances or internet_facing_lb:
                                    if auto_delete_all_traffic_sg_rule:
                                        if not ec2_utils.delete_security_group_rule(security_group_id, group_rule_id):
                                            LOGGER.error("Could not delete security group rule with all traffic open to public for Security Group %s in Account=%s and Region=%s", security_group_id, helper.account_id, helper.region)
                                        else:
                                            is_rule_deleted = True
                                    else:
                                        is_critical_finding = True
                                else:
                                    is_medium_finding = True
                            elif Helper().matches_given_ports(open_port_item['Port'], open_port_item['Protocol'], ec2_security_group_ingress_remote_access_ports, False) or Helper().matches_given_ports(open_port_item['Port'], open_port_item['Protocol'], loadbalancer_security_group_ingress_remote_access_ports, False):
                                if public_instances or internet_facing_lb:
                                    if not user_ip_address and auto_remediate_remote_access_ports:
                                        if not ec2_utils.delete_security_group_rule(security_group_id, group_rule_id):
                                            LOGGER.error("Could not delete security group rule with remote access port open to public for Security Group %s in Account=%s and Region=%s", security_group_id, helper.account_id, helper.region)
                                        else:
                                            is_rule_deleted = True
                                    else:
                                        is_critical_finding = True
                                else:
                                    is_medium_finding = True
                            elif Helper().matches_given_ports(open_port_item['Port'], open_port_item['Protocol'], ec2_security_group_ingress_traffic_ports, False) or Helper().matches_given_ports(open_port_item['Port'], open_port_item['Protocol'], loadbalancer_security_group_ingress_traffic_ports, False):
                                if public_instances or internet_facing_lb:
                                    if not user_ip_address and auto_remediate_traffic_ports:
                                        if not ec2_utils.delete_security_group_rule(security_group_id, group_rule_id):
                                            LOGGER.error("Could not delete security group rule with traffic port %s open to public for Security Group %s in Account=%s and Region=%s", str(open_port_item['Port']), security_group_id, helper.account_id, helper.region)
                                        else:
                                            is_rule_deleted = True
                                    else:
                                        is_high_finding = True

                        if not is_rule_deleted:
                            open_ports.append(str(open_port_item['Port']))
                            if port_userip:
                                ports_userip.append(Helper().format_ports_entry(port_userip['Port'], port_userip['Protocol'], port_userip['UserIpAddress']))
                            else:
                                ports_userip.append(Helper().format_ports_entry(open_port_item['Port'], open_port_item['Protocol'], ''))

            if ports_userip:
                pagerduty_incidents = []
                updated_incident_ids = []
                if create_incidents_on_pagerduty:
                    pagerduty_helper = PagerDuty(
                        account_id,
                        messenger.account_name,
                        region,
                        is_pd_integration_type_restapi=is_pd_integration_type_restapi,
                        routing_key=None if is_pd_integration_type_restapi else pagerduty_routing_key,
                        api_token=pagerduty_api_token if is_pd_integration_type_restapi else None,
                        service_id=pagerduty_service_id if is_pd_integration_type_restapi else None,
                        from_user_email=pagerduty_user_email_address if is_pd_integration_type_restapi else None)
                    if 'pagerduty_incident_id' in item:
                        for incident_id in item['pagerduty_incident_id']['SS']:
                            incident_status, incident_number, incident_url = pagerduty_helper.get_incident_details(incident_id)
                            if incident_status not in ['resolved']:
                                updated_incident_ids.append(incident_id)
                                pagerduty_incidents.append({
                                    "IncidentNumber": incident_number,
                                    "IncidentUrl": incident_url,
                                })
                    elif 'pagerduty_dedup_keys' in item:
                        for dedup_key in item['pagerduty_dedup_keys']['SS']:
                            updated_incident_ids.append(dedup_key)

                if not SecurityGroupsData(security_groups_table).store(account_id, region, security_group_id, ports_userip, is_attached, item['notifications_suppressed']['S'], pagerduty_incident_id=updated_incident_ids if is_pd_integration_type_restapi else None, pagerduty_dedup_keys=None if is_pd_integration_type_restapi else updated_incident_ids):
                    LOGGER.error("Could not add metadata for Security Group %s in Account ID=%s and Region=%s", security_group_id, account_id, region)
                severity = 'Critical' if is_critical_finding else 'High' if is_high_finding else 'Medium' if is_medium_finding else 'Low'
                alert_args = {
                    "severity": severity,
                    "port": open_ports,
                    "security_group_id": security_group_id,
                    "is_attached": is_attached,
                    "attached_instances": attached_ec2_instances,
                    "attached_lb": attached_loadbalancers,
                    "pagerduty_incidents": pagerduty_incidents
                }
                if severity in hourly_alerts_severity_types or 'ALL' in hourly_alerts_severity_types:
                    alerts_handler = Alert(None, [], is_pd_integration_type_restapi, True, messenger, False, {}, None, None, None)
                    alerts_handler.handler('security_group_ingress_open_to_all_attachment_cron_message', alert_args, None, None)
            else:
                if create_incidents_on_pagerduty:
                    pagerduty_helper = PagerDuty(
                        account_id,
                        messenger.account_name,
                        region,
                        is_pd_integration_type_restapi=is_pd_integration_type_restapi,
                        routing_key=None if is_pd_integration_type_restapi else pagerduty_routing_key,
                        api_token=pagerduty_api_token if is_pd_integration_type_restapi else None,
                        service_id=pagerduty_service_id if is_pd_integration_type_restapi else None,
                        from_user_email=pagerduty_user_email_address if is_pd_integration_type_restapi else None)
                    if 'pagerduty_incident_id' in item:
                        for incident_id in item['pagerduty_incident_id']['SS']:
                            pagerduty_helper.resolve_incident(incident_id)
                    elif 'pagerduty_dedup_keys' in item:
                        for dedup_key in item['pagerduty_dedup_keys']['SS']:
                            pagerduty_helper.resolve_incident(dedup_key)
                if not DeleteData(security_groups_table).delete('account_id', account_id, 'security_group_id', security_group_id):
                    LOGGER.error("Could not delete metadata for Security Group %s from DynamoDB Table", security_group_id)
                if not remediated_table_ops.store(account_id, region, security_group_id, 'Security Group with Open Ports'):
                    LOGGER.error("Could not add metadata for Security Group %s to remediated DynamoDB Table", security_group_id)
                severity = 'Informational'
                alert_args = {
                    "severity": severity,
                    "port": all_open_ports,
                    "security_group_id": security_group_id,
                    "is_attached": is_attached,
                    "attached_instances": attached_ec2_instances,
                    "attached_lb": attached_loadbalancers,
                    "is_deleted": False
                }
                azure_data['Event'] = f"Security Group {security_group_id} with ports open to everyone has been remediated"
                alerts_handler = Alert(None, [], is_pd_integration_type_restapi, True, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                alerts_handler.handler('security_group_ingress_open_to_all_attachment_remediation_message', alert_args, None, None)
        except Exception as error:
            raise error

    scan_response = GetData(iam_table).get()
    for item in scan_response:
        account_id = item['account_id']['S']
        region = item['region']['S']
        iam_user = item['iam_user']['S']
        detail = { 'account': account_id, 'region': region }
        helper = AWSHelper(detail)
        active_session = helper.get_active_session()
        iam_utils = IAM(active_session)
        messenger = EventAlert(engineer_facing_notification_app, account_id, region, engineer_facing_webhook_urls)
        try:
            pagerduty_incidents = []
            updated_incident_ids = []
            if create_incidents_on_pagerduty:
                pagerduty_helper = PagerDuty(
                    account_id,
                    messenger.account_name,
                    region,
                    is_pd_integration_type_restapi=is_pd_integration_type_restapi,
                    routing_key=None if is_pd_integration_type_restapi else pagerduty_routing_key,
                    api_token=pagerduty_api_token if is_pd_integration_type_restapi else None,
                    service_id=pagerduty_service_id if is_pd_integration_type_restapi else None,
                    from_user_email=pagerduty_user_email_address if is_pd_integration_type_restapi else None)
                if 'pagerduty_incident_id' in item:
                    for incident_id in item['pagerduty_incident_id']['SS']:
                        incident_status, incident_number, incident_url = pagerduty_helper.get_incident_details(incident_id)
                        if incident_status not in ['resolved']:
                            updated_incident_ids.append(incident_id)
                            pagerduty_incidents.append({
                                "IncidentNumber": incident_number,
                                "IncidentUrl": incident_url,
                            })
                elif 'pagerduty_dedup_keys' in item:
                    for dedup_key in item['pagerduty_dedup_keys']['SS']:
                        updated_incident_ids.append(dedup_key)
            if iam_utils.check_iam_user_exists(iam_user):
                is_programmatic_access_enabled = iam_utils.found_user_access_keys(iam_user)
                is_console_access_enabled = iam_utils.found_iam_user_login_profile(iam_user)
                alert_args = {
                    "iam_user": iam_user,
                    "pagerduty_incidents": pagerduty_incidents
                }
                severity = ''
                alert_id = ''
                if is_programmatic_access_enabled:
                    severity = 'High'
                    alert_args['access_key_ids'] = iam_utils.get_active_iam_user_access_key_ids(iam_user)
                    alert_id = 'secret_access_key_exist_message'
                elif is_console_access_enabled:
                    severity = 'High'
                    alert_id = 'console_access_enabled_message'
                elif not is_console_access_enabled and not is_programmatic_access_enabled:
                    severity = 'Medium'
                    alert_id = 'iam_user_exist_message'

                if alert_id:
                    alert_args['severity'] = severity
                    if severity in hourly_alerts_severity_types or 'ALL' in hourly_alerts_severity_types:
                        alerts_handler = Alert(None, [], is_pd_integration_type_restapi, True, messenger, False, {}, None, None, None)
                        alerts_handler.handler(alert_id, alert_args, None, None)
                    if not iam_users_table_ops.store(account_id, region, iam_user, is_programmatic_access_enabled, is_console_access_enabled, item['notifications_suppressed']['S'], pagerduty_incident_id=updated_incident_ids if is_pd_integration_type_restapi else None, pagerduty_dedup_keys=None if is_pd_integration_type_restapi else updated_incident_ids):
                        LOGGER.error("Could not add metadata to DynamoDB table for User %s in Account=%s", iam_user, account_id)
            else:
                if create_incidents_on_pagerduty:
                    pagerduty_helper = PagerDuty(
                        account_id,
                        messenger.account_name,
                        region,
                        is_pd_integration_type_restapi=is_pd_integration_type_restapi,
                        routing_key=None if is_pd_integration_type_restapi else pagerduty_routing_key,
                        api_token=pagerduty_api_token if is_pd_integration_type_restapi else None,
                        service_id=pagerduty_service_id if is_pd_integration_type_restapi else None,
                        from_user_email=pagerduty_user_email_address if is_pd_integration_type_restapi else None)
                    if 'pagerduty_incident_id' in item:
                        for incident_id in item['pagerduty_incident_id']['SS']:
                            pagerduty_helper.resolve_incident(incident_id)
                    elif 'pagerduty_dedup_keys' in item:
                        for dedup_key in item['pagerduty_dedup_keys']['SS']:
                            pagerduty_helper.resolve_incident(dedup_key)
                if not DeleteData(iam_table).delete('account_id', account_id, 'iam_user', iam_user):
                    LOGGER.error("Could not delete metadata for IAM User %s from DynamoDB Table", iam_user)
                if not RemediatedResourcesData(remediated_table_name).store(helper.account_id, helper.region, iam_user, 'IAM User'):
                    LOGGER.error("Could not add metadata for IAM User %s to remediated DynamoDB Table", iam_user)
                severity = 'Informational'
                alert_args = {
                    "severity": severity,
                    "iam_user": iam_user
                }
                azure_data = {
                    "Severity": severity,
                    "AccountID": helper.account_id,
                    "AccountName": messenger.account_name,
                    "Region": helper.region,
                    "User": helper.iam_user,
                    "Event": f"IAM User named {iam_user} has been deleted and the finding is marked remediated"
                }
                alerts_handler = Alert(None, [], is_pd_integration_type_restapi, True, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                alerts_handler.handler('iam_user_remediation_message', alert_args, None, None)
        except Exception as error:
            raise error

    scan_response = GetData(s3_buckets_table).get()
    for item in scan_response:
        account_id = item['account_id']['S']
        region = item['region']['S']
        bucket_name = item['s3_bucket_name']['S']
        detail = { 'account': account_id, 'region': region }
        helper = AWSHelper(detail)
        active_session = helper.get_active_session()
        s3_utils = S3(active_session, helper.region)
        messenger = EventAlert(engineer_facing_notification_app, account_id, region, engineer_facing_webhook_urls)
        try:
            found_public_objects = s3_utils.found_s3_public_objects(bucket_name)
            is_bucket_policy_public = s3_utils.is_bucket_policy_public(bucket_name)
            is_bucket_acls_public = s3_utils.is_bucket_acls_public(bucket_name)
            is_bucket_encrypted = s3_utils.is_bucket_encryption_enabled(bucket_name)

            is_public_bucket = is_bucket_policy_public or is_bucket_acls_public
            pagerduty_incidents = []
            updated_incident_ids = []
            if create_incidents_on_pagerduty:
                pagerduty_helper = PagerDuty(
                    account_id,
                    messenger.account_name,
                    region,
                    is_pd_integration_type_restapi=is_pd_integration_type_restapi,
                    routing_key=None if is_pd_integration_type_restapi else pagerduty_routing_key,
                    api_token=pagerduty_api_token if is_pd_integration_type_restapi else None,
                    service_id=pagerduty_service_id if is_pd_integration_type_restapi else None,
                    from_user_email=pagerduty_user_email_address if is_pd_integration_type_restapi else None)
                if 'pagerduty_incident_id' in item:
                    for incident_id in item['pagerduty_incident_id']['SS']:
                        incident_status, incident_number, incident_url = pagerduty_helper.get_incident_details(incident_id)
                        if incident_status not in ['resolved']:
                            updated_incident_ids.append(incident_id)
                            pagerduty_incidents.append({
                                "IncidentNumber": incident_number,
                                "IncidentUrl": incident_url,
                            })
                elif 'pagerduty_dedup_keys' in item:
                    for dedup_key in item['pagerduty_dedup_keys']['SS']:
                        updated_incident_ids.append(dedup_key)

            if not found_public_objects and not is_public_bucket:
                if create_incidents_on_pagerduty:
                    pagerduty_helper = PagerDuty(
                        account_id,
                        messenger.account_name,
                        region,
                        is_pd_integration_type_restapi=is_pd_integration_type_restapi,
                        routing_key=None if is_pd_integration_type_restapi else pagerduty_routing_key,
                        api_token=pagerduty_api_token if is_pd_integration_type_restapi else None,
                        service_id=pagerduty_service_id if is_pd_integration_type_restapi else None,
                        from_user_email=pagerduty_user_email_address if is_pd_integration_type_restapi else None)
                    if 'pagerduty_incident_id' in item:
                        for incident_id in item['pagerduty_incident_id']['SS']:
                            pagerduty_helper.resolve_incident(incident_id)
                    elif 'pagerduty_dedup_keys' in item:
                        for dedup_key in item['pagerduty_dedup_keys']['SS']:
                            pagerduty_helper.resolve_incident(dedup_key)
                if not DeleteData(s3_buckets_table).delete('account_id', account_id, 's3_bucket_name', bucket_name):
                    LOGGER.error("Could not delete metadata for S3 Bucket %s from DynamoDB Table", bucket_name)
                if not remediated_table_ops.store(account_id, region, bucket_name, 'Public S3 Bucket'):
                    LOGGER.error("Could not add metadata for S3 Bucket %s to remediated DynamoDB Table", bucket_name)
                severity = 'Informational'
                alert_args = {
                    "severity": severity,
                    "s3_bucket_name": bucket_name
                }
                azure_data = {
                    "Severity": severity,
                    "AccountID": account_id,
                    "AccountName": messenger.account_name,
                    "Region": region,
                    "User": "threatOps",
                    "Event": f"Public S3 Bucket {bucket_name} has been remediated since it does not have Public Access anymore at Bucket/Object level"
                }
                alerts_handler = Alert(None, [], is_pd_integration_type_restapi, True, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                alerts_handler.handler('s3_public_bucket_object_remediation_message', alert_args, None, None)
            elif is_public_bucket or found_public_objects:
                severity = 'Critical'
                alert_args = {
                    "severity": severity,
                    "s3_bucket_name": bucket_name,
                    "is_encryption_enabled": is_bucket_encrypted,
                    "pagerduty_incidents": pagerduty_incidents
                }
                if severity in hourly_alerts_severity_types or 'ALL' in hourly_alerts_severity_types:
                    alerts_handler = Alert(None, [], is_pd_integration_type_restapi, True, messenger, False, {}, None, None, None)
                    alerts_handler.handler('s3_public_bucket_object_message', alert_args, None, None)
                if not s3_buckets_table_ops.store(account_id, region, bucket_name, is_bucket_encrypted, is_public_bucket, found_public_objects, item['notifications_suppressed']['S'], pagerduty_incident_id=updated_incident_ids if is_pd_integration_type_restapi else None, pagerduty_dedup_keys=None if is_pd_integration_type_restapi else updated_incident_ids):
                    LOGGER.error("Could not add metadata to DynamoDB table for S3 Bucket %s in Account=%s", bucket_name, account_id)
        except Exception as error:
            raise error

    if deploy_cmdb_project:
        records = GetData(active_resources_table).get()
        for record in records:
            account_id, account_name, region = record['account_id']['S'], record['account_name']['S'], record['region']['S']
            deploy_method, team, created_by, resource_id, resource_type, created_at, instance_type = record['deploy_method']['S'], record['team']['S'], record['created_by']['S'], record['resource_id']['S'], record['resource_type']['S'], record['created_at']['S'], record['instance_type']['S']
            cloudtrail_delete_event_name = ''
            all_tags, launch_time, current_state, public_ip, cost_type, platform = [], '', '', '', '', ''
            hourly_cost, daily_cost, monthly_cost = record['hourly_cost']['S'], record['daily_cost']['S'], record['monthly_cost']['S']
            is_instance_ssm_managed, is_imdsv2_enabled = '', ''
            detail = { 'account': account_id, 'region': region }
            helper = AWSHelper(detail)
            active_session = helper.get_active_session()
            ec2_utils = EC2(active_session, helper.region)
            ssm_utils = SSM(active_session, helper.region)
            eks_utils = EKS(active_session, helper.region)
            rds_utils = RDS(active_session, helper.region)
            efs_utils = EFS(active_session, helper.region)
            cloudtrail_utils = CloudTrail(active_session, helper.region)
            pricing_utils = Pricing(active_session, helper.region)

            if resource_type == 'EC2Instance':
                current_state = ec2_utils.get_instance_status(resource_id)
                cloudtrail_delete_event_name = 'TerminateInstances'
                all_tags, launch_time, public_ip, ec2_instance_exists = ec2_utils.get_cmdb_instance_details(resource_id)
                if ec2_instance_exists:
                    cost_type, tenancy, usage_operation, platform_detail, platform = ec2_utils.get_instance_cost_details(resource_id)
                    is_instance_ssm_managed = 'Yes' if ssm_utils.is_instance_ssm_managed(resource_id) else 'No'
                    is_imdsv2_enabled = 'Yes' if ec2_utils.is_instance_imdsv2_enabled(resource_id) else 'No'
                    spot_request_id = ''
                    for tag in all_tags:
                        if tag.split(' ')[0].rstrip(':').startswith('aws:ec2spot:'):
                            spot_request_id = tag.split(' ')[1]
                    if cost_type == 'spot':
                        hourly_cost, daily_cost, monthly_cost = ec2_utils.get_spot_price(instance_type, platform_detail, spot_request_id)
                    else:
                        hourly_cost, daily_cost, monthly_cost = pricing_utils.get_instance_cost(instance_type, cost_type, usage_operation, tenancy)
                else:
                    current_state = 'terminated'

            elif resource_type == 'EKSCluster':
                current_state = (eks_utils.get_eks_cluster_status(resource_id)).lower()
                if current_state not in ['deleted']:
                    launch_time = eks_utils.get_eks_cluster_launch_time(resource_id)
                cloudtrail_delete_event_name = 'DeleteCluster'
                all_tags = eks_utils.get_eks_cluster_tags(resource_id)

                hourly_cost, daily_cost, monthly_cost = pricing_utils.get_cluster_cost()

            elif resource_type == 'RDSDBInstance':
                current_state = rds_utils.get_rds_instance_status(resource_id)
                if current_state not in ['deleted']:
                    launch_time = rds_utils.get_rds_instance_launch_time(resource_id)
                cloudtrail_delete_event_name = 'DeleteDBInstance'
                all_tags = rds_utils.get_rds_tags(helper.account_id, resource_type, resource_id)

                instance_class, rds_engine, storage_type = rds_utils.get_rds_cost_details(resource_type, resource_id)
                instance_type = instance_class
                hourly_cost = 0.0
                instance_classes = instance_class.split(',')
                for instance in instance_classes:
                    hourly_cost += pricing_utils.get_rds_hourly_cost(instance, rds_engine, storage_type)
                if hourly_cost:
                    daily_cost = hourly_cost * 24
                    monthly_cost = daily_cost * 30
                    hourly_cost = f"USD {hourly_cost:.2f}"
                    daily_cost = f"USD {daily_cost:.2f}"
                    monthly_cost = f"USD {monthly_cost:.2f}"

            elif resource_type == 'RDSDBCluster':
                current_state = rds_utils.get_rds_cluster_status(resource_id)
                if current_state not in ['deleted']:
                    launch_time = rds_utils.get_rds_cluster_launch_time(resource_id)
                cloudtrail_delete_event_name = 'DeleteDBCluster'
                all_tags = rds_utils.get_rds_tags(helper.account_id, resource_type, resource_id)

                instance_class, rds_engine, storage_type = rds_utils.get_rds_cost_details(resource_type, resource_id)
                instance_type = instance_class
                hourly_cost = 0.0
                instance_classes = instance_class.split(',')
                for instance in instance_classes:
                    hourly_cost += pricing_utils.get_rds_hourly_cost(instance, rds_engine, storage_type)
                if hourly_cost:
                    daily_cost = hourly_cost * 24
                    monthly_cost = daily_cost * 30
                    hourly_cost = f"USD {hourly_cost:.2f}"
                    daily_cost = f"USD {daily_cost:.2f}"
                    monthly_cost = f"USD {monthly_cost:.2f}"

            elif resource_type == 'EFSFileSystem':
                current_state = efs_utils.get_efs_filesystem_status(resource_id)
                cloudtrail_delete_event_name = 'DeleteFileSystem'
                all_tags, launch_time = efs_utils.get_efs_details(resource_id)
                is_multi_az, standard_gb_hours, infa_gb_hours = efs_utils.get_efs_cost_details(resource_id)
                hourly_cost, daily_cost, monthly_cost = pricing_utils.get_efs_cost(is_multi_az, standard_gb_hours, infa_gb_hours)

            if current_state in ['terminated', 'deleted']:
                deleted_by, deleted_at = cloudtrail_utils.get_resource_details(cloudtrail_delete_event_name, resource_id)
                if not deleted_resources_table_ops.store(account_id, account_name, region, deleted_by, resource_id, resource_type, deleted_at, record['all_tags']['SS']):
                    LOGGER.error("Could not store data for deleted resource %s", resource_id)
                else:
                    LOGGER.info("Added resource details to Deleted Resource Table. Removing from Active Resource Table...")
                    unique_id = f"{account_id}_{region}_{resource_type}_{resource_id}"
                    if not active_resources_table_ops.delete(unique_id):
                        LOGGER.error("Could not delete record for %s from active resources table", resource_id)
                    else:
                        LOGGER.info("Deleted record for %s from active resource table", resource_id)
            else:
                if not active_resources_table_ops.store(account_id, account_name, region, deploy_method, team, created_by, resource_id, instance_type, resource_type, current_state, public_ip, created_at, launch_time, f"USD {hourly_cost:.2f}" if not isinstance(hourly_cost, str) else hourly_cost, daily_cost, monthly_cost, cost_type, platform, is_instance_ssm_managed, is_imdsv2_enabled, all_tags if all_tags else [""]):
                    LOGGER.error("Could not store data for Resource %s in Account=%s and Region=%s", resource_id, account_id, region)
                else:
                    LOGGER.info("Updated record")

    if deploy_ip_tracker_project and track_tailscale_ips:
        tailscale_config = Tailscale(tailnet_name, tailscale_client_id, tailscale_client_secret)
        tailscale_user_ips = tailscale_config.get_tailscale_user_ips()
        records = GetData(ip_correlation_table).get()
        for record in records:
            if not UsersIPData(ip_correlation_table, track_tailscale_ips).store_ip_data(record['user']['S'], record['sso_user_id']['S'], record['last_login_date']['S'], record['known_aws_ip']['S'], tailscale_user_ips[record['user']['S']] if tailscale_user_ips[record['user']['S']] else [""]):
                LOGGER.error("Could not update data for SSO User %s", record['user']['S'])

    if track_ssm_doc_assoc_failures:
        records = GetData(ssm_document_association_failure_tracker_table).get()
        association_failed_instances = {}
        for record in records:
            account_id, account_name, region = record['account_id']['S'], record['account_name']['S'], record['region']['S']
            instance_id, ssm_document_name, association_id = record['instance_id']['S'], record['ssm_document_name']['S'], record['association_id']['S']
            detail = { 'account': account_id, 'region': region }
            helper = AWSHelper(detail)
            active_session = helper.get_active_session()
            ssm_utils = SSM(active_session, helper.region)
            ec2_utils = EC2(active_session, helper.region)
            messenger = EventAlert(security_admin_facing_notification_app, account_id, region, security_admin_facing_webhook_urls)

            failed_instance_succeeded = False
            instance_status = ec2_utils.get_instance_status(instance_id)
            if instance_status not in ['terminated']:
                LOGGER.info("EC2 Instance %s is in %s state. Checking status of instance's SSM association...", instance_id, instance_status)
                if ssm_utils.is_instance_ssm_managed(instance_id):
                    LOGGER.info("EC2 Instance %s is SSM managed", instance_id)
                    ssm_association_status = ssm_utils.get_instance_association_status(instance_id, association_id)
                    if ssm_association_status in ['Failed']:
                        if association_id not in association_failed_instances:
                            association_failed_instances[association_id] = { 'AccountName': account_name, 'AccountId': account_id, 'Region': region, 'DocumentName': ssm_document_name, 'Instances': [] }
                        association_failed_instances[association_id]['Instances'].append(instance_id)
                        LOGGER.info("SSM Association %s for EC2 Instance %s is still in Failed state", association_id, instance_id)
                    elif ssm_association_status in ['Success']:
                        failed_instance_succeeded = True
            if instance_status in ['terminated'] or failed_instance_succeeded:
                LOGGER.info("EC2 Instance %s is in %s state", instance_id, instance_status)
                if create_incidents_on_pagerduty and create_pagerduty_incidents_for_ssm_failures:
                    pagerduty_helper = PagerDuty(
                        account_id,
                        messenger.account_name,
                        region,
                        is_pd_integration_type_restapi=is_pd_integration_type_restapi,
                        routing_key=None if is_pd_integration_type_restapi else pagerduty_routing_key,
                        api_token=pagerduty_api_token if is_pd_integration_type_restapi else None,
                        service_id=pagerduty_service_id if is_pd_integration_type_restapi else None,
                        from_user_email=pagerduty_user_email_address if is_pd_integration_type_restapi else None)
                    if 'pagerduty_incident_id' in record:
                        for incident_id in record['pagerduty_incident_id']['SS']:
                            pagerduty_helper.resolve_incident(incident_id)
                    elif 'pagerduty_dedup_keys' in record:
                        for dedup_key in record['pagerduty_dedup_keys']['SS']:
                            pagerduty_helper.resolve_incident(dedup_key)
                if not DeleteData(ssm_document_association_failure_tracker_table).delete('ssm_document_name', ssm_document_name, 'instance_id', instance_id):
                    LOGGER.error("Could not delete metadata for SSM Document Association failure for document %s from DynamoDB Table", ssm_document_name)
                is_terminated = True if instance_status in ['terminated'] else False
                severity = 'Informational'
                azure_data = {
                    "Severity": severity,
                    "AccountID": account_id,
                    "AccountName": messenger.account_name,
                    "Region": region,
                    "User": "SSM Association"
                }
                alert_args = {
                    "severity": severity,
                    "account_name": account_name,
                    "account_id": account_id,
                    "region": region,
                    "instance_id": instance_id,
                    "association_id": association_id,
                    "document_name": ssm_document_name,
                    "is_terminated": is_terminated
                }
                if failed_instance_succeeded or enable_hourly_ssm_failure_reminders:
                    azure_data['Event'] = f"EC2 Instance {instance_id} which was previously in a failed state in the SSM Document Association for document {ssm_document_name} has {'been terminated' if is_terminated else 'now successfully associated'}."
                    alerts_handler = Alert(None, [], is_pd_integration_type_restapi, True, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                    alerts_handler.handler('ssm_associated_ec2_instance_update_message', alert_args, None, None)
        if enable_hourly_ssm_failure_reminders:
            for assoc_id, assoc_details in association_failed_instances.items():
                severity = 'High'
                alert_args = {
                    "severity": severity,
                    "account_name": assoc_details['AccountName'],
                    "account_id": assoc_details['AccountId'],
                    "region": assoc_details['Region'],
                    "instances": assoc_details['Instances'],
                    "association_id": assoc_id,
                    "document_name": assoc_details['DocumentName']
                }
                messenger = EventAlert(security_admin_facing_notification_app, account_id, region, security_admin_facing_webhook_urls)
                alerts_handler = Alert(None, [], is_pd_integration_type_restapi, True, messenger, False, {}, None, None, None)
                alerts_handler.handler('ssm_document_association_failure_cron_message', alert_args, None, None)
