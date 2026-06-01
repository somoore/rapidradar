import json
from utils.cloudtrail import CloudTrail
from utils.ec2 import EC2
from utils.dynamodb import (
    SecurityGroupsData,
    ActiveResourcesData,
    DeletedResourcesData,
    GetData
)
from utils.ssm import SSM
from utils.pricing import Pricing
from utils.sso_helper import SSOHelper
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, slack_oauth_token, sender_email, alert_suppression_resource_tag_key_value, alert_suppression_permission_set_tag_key_value, send_logs_to_azure, customer_id, shared_key, log_type, security_groups_table, active_resources_table, deleted_resources_table, deploy_cmdb_project, pagerduty_helper, is_pd_integration_type_restapi):
    if 'errorCode' not in event and 'requestParameters' in event:
        messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
        email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
        slack_bot = None
        if slack_oauth_token:
            slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)
        active_session = helper.get_active_session()
        cloudtrail_utils = CloudTrail(active_session, helper.region)
        ec2_utils = EC2(active_session, helper.region)
        ssm_utils = SSM(active_session, helper.region)
        pricing_utils = Pricing(active_session, helper.region)
        alert_suppression_tag_key, alert_suppression_tag_value = alert_suppression_resource_tag_key_value.split('=')
        admin_alert_suppression_tag_key, admin_alert_suppression_tag_value = alert_suppression_permission_set_tag_key_value.split('=')

        request_params = event['requestParameters']
        resource_type = ''
        resource_id = ''
        try:
            if 'resourcesSet' in request_params and 'tagSet' in request_params and 'items' in request_params['resourcesSet'] and 'items' in request_params['tagSet']:
                found_admin_suppression_tag = SSOHelper().found_admin_suppression_tag(helper.user_arn, admin_alert_suppression_tag_key, admin_alert_suppression_tag_value)
                for item in request_params['resourcesSet']['items']:
                    active_resources_table_ops = ActiveResourcesData(active_resources_table)
                    deleted_resources_table_ops = DeletedResourcesData(deleted_resources_table)
                    if item['resourceId'].startswith("sg-"):
                        scan_records = GetData(security_groups_table).get_by_id('account_id', helper.account_id, 'security_group_id', item['resourceId'])
                        previously_notifications_compressed = json.loads(scan_records[0]['notifications_suppressed']['S']) if scan_records else False

                        for tag in request_params['tagSet']['items']:
                            if tag['key'] == alert_suppression_tag_key and tag['value'] == alert_suppression_tag_value:
                                found_suppression_tag = ec2_utils.found_suppression_tag_sg(item['resourceId'], alert_suppression_tag_key, alert_suppression_tag_value)
                                resource_type = 'Security Group'
                                resource_id = item['resourceId']
                                severity = 'Informational'
                                alert_args = {
                                    "severity": severity,
                                    "iam_user": helper.iam_user,
                                    "resource_type": resource_type,
                                    "resource_id": resource_id,
                                    "alert_suppression_tag_key": alert_suppression_tag_key,
                                    "alert_suppression_tag_value": alert_suppression_tag_value
                                }
                                azure_data = {
                                    "Severity": severity,
                                    "AccountID": helper.account_id,
                                    "AccountName": messenger.account_name,
                                    "Region": helper.region,
                                    "User": helper.iam_user
                                }

                                if not found_suppression_tag and previously_notifications_compressed and found_admin_suppression_tag:
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
                                    if not SecurityGroupsData(security_groups_table).store(helper.account_id, helper.region, item['resourceId'], scan_records[0]['port']['SS'], scan_records[0]['attached']['S'], found_suppression_tag, pagerduty_incident_id=updated_incident_ids if is_pd_integration_type_restapi else None, pagerduty_dedup_keys=None if is_pd_integration_type_restapi else updated_incident_ids):
                                        LOGGER.error("Could not add metadata for Security Group %s in Account=%s and Region=%s", item['resourceId'], helper.account_id, helper.region)
                                    azure_data['Event'] = f"User {helper.iam_user} has removed {alert_suppression_tag_key}={alert_suppression_tag_value} tag from {resource_type} {resource_id}. Notifications for this specific {resource_type} will now continue until remediated or silenced once again"
                                    alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                                    alerts_handler.handler('notifications_suppression_removal_message', alert_args, email_messenger, slack_bot)

                                if not found_suppression_tag and previously_notifications_compressed and not found_admin_suppression_tag:
                                    azure_data['Event'] = f"User {helper.iam_user} removed {alert_suppression_tag_key}={alert_suppression_tag_value} tag from {resource_type} {resource_id} but they do not have permission to enable or disable notifications, that's why alerts for this resource will remain disabled"
                                    alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                                    alerts_handler.handler('notifications_suppression_removal_failure_message', alert_args, email_messenger, slack_bot)

                    if deploy_cmdb_project and item['resourceId'].startswith("i-"):
                        resource_type = 'EC2Instance'
                        instance_id = item['resourceId']
                        current_state = ec2_utils.get_instance_status(instance_id)
                        account_name, deploy_method, team, created_by, created_at, all_tags, instance_type, platform, hourly_cost, daily_cost, monthly_cost = active_resources_table_ops.record_exists(helper.account_id, helper.region, resource_type, instance_id)
                        if all_tags is not None:
                            LOGGER.info("Record exists. Updating it...")
                            all_tags, launch_time, public_ip, ec2_instance_exists = ec2_utils.get_cmdb_instance_details(instance_id)
                            if ec2_instance_exists:
                                cost_type, tenancy, usage_operation, platform_detail, platform = ec2_utils.get_instance_cost_details(instance_id)
                                is_instance_ssm_managed = 'Yes' if ssm_utils.is_instance_ssm_managed(instance_id) else 'No'
                                is_imdsv2_enabled = 'Yes' if ec2_utils.is_instance_imdsv2_enabled(instance_id) else 'No'
                                spot_request_id = ''
                                for tag in all_tags:
                                    if tag.split(' ')[0].rstrip(':') in ['DeployedBy', 'deployedby', 'Deployedby', 'deployedBy']:
                                        created_by = tag.split(': ')[1]
                                    if tag.split(' ')[0].rstrip(':') in ['DeployMethod', 'deployMethod', 'Deploymethod', 'deployMethod']:
                                        deploy_method = tag.split(': ')[1]
                                    if tag.split(' ')[0].rstrip(':') in ['Team', 'team']:
                                        team = tag.split(': ')[1]
                                    if tag.split(' ')[0].rstrip(':').startswith('aws:ec2spot:'):
                                        spot_request_id = tag.split(' ')[1]
                                if not created_at:
                                    created_at = launch_time
                                if cost_type == 'spot':
                                    hourly_cost, daily_cost, monthly_cost = ec2_utils.get_spot_price(instance_type, platform_detail, spot_request_id)
                                else:
                                    hourly_cost, daily_cost, monthly_cost = pricing_utils.get_instance_cost(instance_type, cost_type, usage_operation, tenancy)
                                if not active_resources_table_ops.store(helper.account_id, account_name, helper.region, deploy_method, team, created_by, instance_id, instance_type, resource_type, current_state, public_ip, created_at, launch_time, hourly_cost, daily_cost, monthly_cost, cost_type, platform, is_instance_ssm_managed, is_imdsv2_enabled, all_tags if all_tags else [""]):
                                    LOGGER.error("Could not store data for Instance %s in Account=%s and Region=%s", instance_id, helper.account_id, helper.region)
                                else:
                                    LOGGER.info("Updated record")
                            else:
                                deleted_by, deleted_at = cloudtrail_utils.get_resource_details('TerminateInstances', instance_id)
                                if not deleted_resources_table_ops.store(helper.account_id, account_name, helper.region, deleted_by, instance_id, resource_type, deleted_at, all_tags if all_tags else [""]):
                                    LOGGER.error("Could not store data for deleted resource %s", instance_id)
                                else:
                                    LOGGER.info("Added resource details to Deleted Resource Table. Removing from Active Resource Table...")
                                    unique_id = f"{helper.account_id}_{helper.region}_{resource_type}_{instance_id}"
                                    if not active_resources_table_ops.delete(unique_id):
                                        LOGGER.error("Could not delete record for %s from active resources table", instance_id)
                                    else:
                                        LOGGER.info("Deleted record for %s from active resource table", instance_id)

            else:
                LOGGER.info("Not notifying")
        except Exception as error:
            LOGGER.error(str(error))
    else:
        LOGGER.info("Tags were not deleted from resource for some reason")
