import json
from utils.dynamodb import ActiveResourcesData
from utils.events import Events
from utils.efs import EFS
from utils.ssm import SSM
from utils.pricing import Pricing
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, event_time, sender_email, notification_app, webhook_urls, slack_oauth_token, send_logs_to_azure, customer_id, shared_key, log_type, active_resources_table, deploy_cmdb_project, project_name, tag_efs, tag_efs_using_tag_template_for_tf_deployment, efs_tags_key_value, send_missing_tags_notification_efs, target_arn, efs_filesystem_creation_blocked_wo_certain_tags, efs_filesystem_creation_scp_tag_keys, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
    email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
    slack_bot = None
    if slack_oauth_token:
        slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)
    event_by, account_name = helper.get_cmdb_event_details()
    azure_data = {
        "AccountID": helper.account_id,
        "AccountName": account_name,
        "Region": helper.region,
        "User": helper.iam_user
    }
    if 'errorCode' in event and event['errorCode'] == 'AccessDenied':
        if efs_filesystem_creation_blocked_wo_certain_tags:
            severity = 'Informational'
            alert_args = {
                "severity": severity,
                "resource_type": "EFS FileSystem",
                "iam_user": helper.iam_user,
                "tags": efs_filesystem_creation_scp_tag_keys
            }
            azure_data['Event'] = f"User {helper.iam_user} tried to create an EFS FileSystem with missing tags {efs_filesystem_creation_scp_tag_keys} which failed due to an SCP policy"
            alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
            alerts_handler.handler('resource_creation_wo_required_tags_scp_block_error_message', alert_args, email_messenger, slack_bot)
        else:
            LOGGER.info("FileSystem was not created for some reason")
    elif 'errorCode' not in event:
        if 'responseElements' in event:
            active_session = helper.get_active_session()
            efs_utils = EFS(active_session, helper.region)
            ssm_utils = SSM(active_session, helper.region)
            events_utils = Events(helper.account_id, helper.region)
            pricing_utils = Pricing(active_session, helper.region)

            response_elements = event['responseElements']
            efs_id = response_elements['fileSystemId']
            current_state = response_elements['lifeCycleState']
            resource_type = 'EFSFileSystem'
            cost_type, platform, is_instance_ssm_managed = '', '', ''
            deploy_method, deploy_method_key_exists = '', False
            team, team_key_exists = '', False
            deployed_by_key_exists = False
            found_tf_deploy_method = False
            is_tf_deployment = False

            all_tags = []
            efs_tag_keys = []
            try:
                if 'tags' in response_elements:
                    all_tags = [ f"{tag['key']}: {tag['value']}" for tag in response_elements['tags'] ]
                    efs_tag_keys = [ tag['key'] for tag in response_elements['tags'] ]

                for tag in all_tags:
                    if tag.split(' ')[0].rstrip(':') in ['DeployMethod', 'deployMethod', 'Deploymethod', 'deploymethod']:
                        deploy_method = tag.split(': ')[1]
                        deploy_method_key_exists = True
                        if deploy_method in ['Terraform','terraform']:
                            found_tf_deploy_method = True
                    if tag.split(' ')[0].rstrip(':') in ['Team', 'team']:
                        team = tag.split(': ')[1]
                        team_key_exists = True
                    if tag.split(' ')[0].rstrip(':') in ['DeployedBy', 'deployedBy', 'Deployedby', 'deployedby']:
                        event_by = tag.split(': ')[1]
                        deployed_by_key_exists = True

                if 'Terraform' in helper.user_agent or found_tf_deploy_method:
                    is_tf_deployment = True

                if deploy_cmdb_project:
                    is_multi_az, standard_gb_hours, infa_gb_hours = efs_utils.get_efs_cost_details(efs_id)
                    hourly_cost, daily_cost, monthly_cost = pricing_utils.get_efs_cost(is_multi_az, standard_gb_hours, infa_gb_hours)

                    if not deploy_method_key_exists:
                        deploy_method='aws-console'
                        efs_utils.add_tags_to_efs(efs_id, [{'Key': 'DeployMethod', 'Value': deploy_method}])
                    if not deployed_by_key_exists:
                        efs_utils.add_tags_to_efs(efs_id, [{'Key': 'DeployedBy', 'Value': event_by}])
                    if not team_key_exists:
                        team='unknown'
                        efs_utils.add_tags_to_efs(efs_id, [{'Key': 'Team', 'Value': team}])
                    if not ActiveResourcesData(active_resources_table).store(helper.account_id, account_name, helper.region, deploy_method, team, event_by, efs_id, '', resource_type, current_state, '', event_time, event_time, hourly_cost, daily_cost, monthly_cost, cost_type, platform, is_instance_ssm_managed, '', all_tags if all_tags else [""]):
                        LOGGER.error("Could not store data for EFS FileSystem %s in Account=%s and Region=%s", efs_id, helper.account_id, helper.region)
                    if current_state in ['creating', 'updating']:
                        if not events_utils.create_5_min_status_update_rule(resource_type, efs_id, target_arn):
                            LOGGER.error("Could not create 5 min cron for EFSFileSystem %s", efs_id)
                        else:
                            LOGGER.info("Created 5 min cron for EFSFileSystem %s", efs_id)

                if tag_efs:
                    use_params_tags = True
                    if tag_efs_using_tag_template_for_tf_deployment and is_tf_deployment:
                        decrypted_value = json.loads(ssm_utils.get_decrypted_value(f'/{project_name}/EFS_TAG_TEMPLATE'))
                        for key, value in decrypted_value.items():
                            if value != f"< {key.upper()} >":
                                use_params_tags = False
                                if not efs_utils.add_tags_to_efs(efs_id, [{'Key': key, 'Value': value}]):
                                    LOGGER.error("Could not add tag %s to EFS FileSystem %s", key, efs_id)
                    if use_params_tags:
                        for efs_tag in efs_tags_key_value:
                            key_value = efs_tag.split('=')
                            if deploy_method_key_exists and key_value[0] in ['DeployMethod', 'deployMethod', 'Deploymethod', 'deploymethod']:
                                continue
                            if deployed_by_key_exists and key_value[0] in ['DeployedBy', 'deployedBy', 'Deployedby', 'deployedby']:
                                continue
                            if not efs_utils.add_tags_to_efs(efs_id, [{'Key': key_value[0], 'Value': key_value[1]}]):
                                LOGGER.error("Could not add tag %s to EFS FileSystem %s", key_value[0], efs_id)

                if send_missing_tags_notification_efs and not tag_efs:
                    efs_tags_key_value_missing = []
                    for tag in efs_tags_key_value:
                        tag_key = tag.split('=')[0]
                        if tag_key not in efs_tag_keys:
                            efs_tags_key_value_missing.append(tag)
                    if efs_tags_key_value_missing:
                        severity = 'Low'
                        alert_args = {
                            "severity": severity,
                            "iam_user": helper.iam_user,
                            "resource_type": "EFS FileSystem",
                            "resource_id": efs_id,
                            "tags": efs_tags_key_value_missing
                        }
                        azure_data['Severity'] = severity
                        azure_data['Event'] = f"User {helper.iam_user} created an EFS FileSystem with ID {efs_id} without proper tags"
                        alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                        alerts_handler.handler('resource_creation_without_tags_message', alert_args, email_messenger, slack_bot)
                    else:
                        LOGGER.info("EFS was created with proper tags")
            except Exception as error:
                LOGGER.error(str(error))
        else:
            LOGGER.info("No responseElements in event")
