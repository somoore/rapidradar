import json
from utils.rds import RDS
from utils.ssm import SSM
from utils.dynamodb import ActiveResourcesData
from utils.pricing import Pricing
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, event_time, sender_email, notification_app, webhook_urls, slack_oauth_token, active_resources_table, send_logs_to_azure, customer_id, shared_key, log_type, project_name, tag_rds, tag_rds_using_tag_template_for_tf_deployment, rds_tags_key_value, send_missing_tags_notification_rds_clusters, deploy_cmdb_project, unencrypted_rds_creation_blocked, unencrypted_rds_creation_blocked_bypass_tag_key, alert_on_unencrypted_rds_creation_bypass, rds_cluster_instance_creation_blocked_wo_certain_tags, rds_cluster_instance_creation_scp_tag_keys, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
    email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
    slack_bot = None
    if slack_oauth_token:
        slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)
    active_session = helper.get_active_session()
    rds_utils = RDS(active_session, helper.region)
    ssm_utils = SSM(active_session, helper.region)
    pricing_utils = Pricing(active_session, helper.region)
    event_by, account_name = helper.get_cmdb_event_details()
    azure_data = {
        "AccountID": helper.account_id,
        "AccountName": messenger.account_name,
        "Region": helper.region,
        "User": helper.iam_user
    }

    if 'errorCode' in event and event['errorCode'] == 'AccessDenied' and 'errorMessage' in event and 'explicit deny in a service control policy' in event['errorMessage']:
        if unencrypted_rds_creation_blocked or rds_cluster_instance_creation_blocked_wo_certain_tags:
            severity = 'Informational'
            alert_args = {
                "severity": severity,
                "iam_user": helper.iam_user,
                "resource_type": 'RDS DB Cluster',
                "is_unencrypted": unencrypted_rds_creation_blocked,
                "bypass_tag_key": unencrypted_rds_creation_blocked_bypass_tag_key,
                "is_missing_tags": rds_cluster_instance_creation_blocked_wo_certain_tags,
                "scp_tags": rds_cluster_instance_creation_scp_tag_keys
            }
            azure_message = ''
            if unencrypted_rds_creation_blocked and rds_cluster_instance_creation_blocked_wo_certain_tags:
                azure_message = 'without encryption enabled and certain tags'
            elif unencrypted_rds_creation_blocked or rds_cluster_instance_creation_blocked_wo_certain_tags:
                azure_message = 'without encryption enabled' if unencrypted_rds_creation_blocked else 'without certain tags'
            azure_data['Severity'] = severity
            azure_data['Event'] = f"User {helper.iam_user} tried to created an RDS DB Cluster {azure_message} which was blocked by a service control policy."
            alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
            alerts_handler.handler('ebs_vol_rds_creation_without_encryption_missing_tags_scp_block_error_message', alert_args, email_messenger, slack_bot)

    elif 'errorCode' not in event and 'responseElements' in event:
        response_elements = event['responseElements']
        db_cluster_identifier = response_elements['dBClusterIdentifier']
        current_state = response_elements['status']
        found_encrypted_rds_bypass_tag = False
        is_rds_encrypted = False
        resource_type = 'RDSDBCluster'
        cost_type, platform, is_instance_ssm_managed, is_imdsv2_enabled = '', '', '', ''
        deploy_method, deploy_method_key_exists = '', False
        team, team_key_exists = '', ''
        deployed_by_key_exists = False
        found_tf_deploy_method = False
        is_tf_deployment = False

        all_tags = [ f"{tag['key']}: {tag['value']}" for tag in response_elements['tagList'] ]
        rds_cluster_tag_keys = [ tag['key'] for tag in response_elements['tagList'] ]

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
            if tag.split(' ')[0].rstrip(':') == unencrypted_rds_creation_blocked_bypass_tag_key:
                found_encrypted_rds_bypass_tag = True

        if 'Terraform' in helper.user_agent or found_tf_deploy_method:
            is_tf_deployment = True

        if deploy_cmdb_project:
            instance_class, rds_engine, storage_type = rds_utils.get_rds_cost_details(resource_type, db_cluster_identifier)
            hourly_cost = 0.0
            instance_classes = instance_class.split(',')
            for instance in instance_classes:
                hourly_cost += pricing_utils.get_rds_hourly_cost(instance, rds_engine, storage_type)
            daily_cost, monthly_cost = '', ''
            if hourly_cost:
                daily_cost = hourly_cost * 24
                monthly_cost = daily_cost * 30
                hourly_cost = f"USD {hourly_cost:.2f}"
                daily_cost = f"USD {daily_cost:.2f}"
                monthly_cost = f"USD {monthly_cost:.2f}"
            if not isinstance(hourly_cost, str):
                hourly_cost = f"USD {hourly_cost:.2f}"
            if not deploy_method_key_exists:
                deploy_method='aws-console'
                rds_utils.add_tags_to_rds(helper.account_id, f"cluster:{db_cluster_identifier}", [{'Key': 'DeployMethod', 'Value': deploy_method}])
            if not deployed_by_key_exists:
                rds_utils.add_tags_to_rds(helper.account_id, f"cluster:{db_cluster_identifier}", [{'Key': 'DeployedBy', 'Value': event_by}])
            if not team_key_exists:
                team='unknown'
                rds_utils.add_tags_to_rds(helper.account_id, f"cluster:{db_cluster_identifier}", [{'Key': 'Team', 'Value': team}])
            if not ActiveResourcesData(active_resources_table).store(helper.account_id, account_name, helper.region, deploy_method, team, event_by, db_cluster_identifier, instance_class, resource_type, current_state, '', event_time, event_time, hourly_cost, daily_cost, monthly_cost, cost_type, platform, is_instance_ssm_managed, is_imdsv2_enabled, all_tags if all_tags else [""]):
                LOGGER.error("Could not store data for RDS DB Cluster %s in Account=%s and Region=%s", db_cluster_identifier, helper.account_id, helper.region)

        if tag_rds:
            use_params_tags = True
            if tag_rds_using_tag_template_for_tf_deployment and is_tf_deployment:
                decrypted_value = json.loads(ssm_utils.get_decrypted_value(f'/{project_name}/RDS_CLUSTER_INSTANCES_TAG_TEMPLATE'))
                for key, value in decrypted_value.items():
                    if value != f"< {key.upper()} >":
                        use_params_tags = False
                        if not rds_utils.add_tags_to_rds(helper.account_id, f"cluster:{db_cluster_identifier}", [{'Key': key, 'Value': value}]):
                            LOGGER.error("Could not add tag %s to RDS DB Cluster %s", key, db_cluster_identifier)
            if use_params_tags:
                for rds_tag in rds_tags_key_value:
                    key_value = rds_tag.split('=')
                    if deploy_method_key_exists and key_value[0] in ['DeployMethod', 'deployMethod', 'Deploymethod', 'deploymethod']:
                        continue
                    if deployed_by_key_exists and key_value[0] in ['DeployedBy', 'deployedBy', 'Deployedby', 'deployedby']:
                        continue
                    if not rds_utils.add_tags_to_rds(helper.account_id, f"cluster:{db_cluster_identifier}", [{'Key': key_value[0], 'Value': key_value[1]}]):
                        LOGGER.error("Could not add tag %s to RDS DB Cluster %s", key_value[0], db_cluster_identifier)

        if send_missing_tags_notification_rds_clusters and not tag_rds:
            rds_tags_key_value_missing = []
            for tag in rds_tags_key_value:
                tag_key = tag.split('=')[0]
                if tag_key not in rds_cluster_tag_keys:
                    rds_tags_key_value_missing.append(tag)
            if rds_tags_key_value_missing:
                severity = 'Low'
                alert_args = {
                    "severity": severity,
                    "iam_user": helper.iam_user,
                    "resource_type": "RDS Cluster",
                    "resource_id": db_cluster_identifier,
                    "tags": rds_tags_key_value_missing
                }
                azure_data['Severity'] = severity
                azure_data['Event'] = f"User {helper.iam_user} created an RDS Cluster with ID {db_cluster_identifier} without proper tags"
                alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                alerts_handler.handler('resource_creation_without_tags_message', alert_args, email_messenger, slack_bot)
            else:
                LOGGER.info("RDS Cluster was created with proper tags")

        if 'storageEncrypted' in response_elements:
            is_rds_encrypted = response_elements['storageEncrypted']
        if not is_rds_encrypted:
            severity = 'Informational' if found_encrypted_rds_bypass_tag else 'High'
            alert_args = {
                "severity": severity,
                "iam_user": helper.iam_user,
                "db_identifier": db_cluster_identifier,
                "resource_type": 'RDS DB Cluster',
                "found_bypass_tag": found_encrypted_rds_bypass_tag
            }
            azure_data['Severity'] = severity
            azure_data['Event'] = f"User {helper.iam_user} created an RDS DB Cluster {db_cluster_identifier} without encryption enabled{' against SCP applied on your Organization using bypass tag.' if found_encrypted_rds_bypass_tag else '. Please add encryption to this RDS DB Cluster by creating a snapshot of it, and then creating an encrypted copy of that snapshot and then restore a DB Cluster from the encrypted snapshot.'}"
            alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
            alert_id = None
            if unencrypted_rds_creation_blocked and found_encrypted_rds_bypass_tag and alert_on_unencrypted_rds_creation_bypass:
                alert_id = 'unencrypted_rds_creation_bypass_tag_message'
            elif not unencrypted_rds_creation_blocked:
                alert_id = 'unencrypted_rds_creation_bypass_tag_message'
            alerts_handler.handler(alert_id, alert_args, email_messenger, slack_bot)
        if deploy_cmdb_project:
            instance_class, rds_engine, storage_type = rds_utils.get_rds_cost_details(resource_type, db_cluster_identifier)
            hourly_cost = 0.0
            instance_classes = instance_class.split(',')
            for instance in instance_classes:
                hourly_cost += pricing_utils.get_rds_hourly_cost(instance, rds_engine, storage_type)
            daily_cost, monthly_cost = '', ''
            if hourly_cost:
                daily_cost = hourly_cost * 24
                monthly_cost = daily_cost * 30
                hourly_cost = f"USD {hourly_cost:.2f}"
                daily_cost = f"USD {daily_cost:.2f}"
                monthly_cost = f"USD {monthly_cost:.2f}"
            if not isinstance(hourly_cost, str):
                hourly_cost = f"USD {hourly_cost:.2f}"
            if not ActiveResourcesData(active_resources_table).store(helper.account_id, account_name, helper.region, deploy_method, team, event_by, db_cluster_identifier, instance_class, resource_type, current_state, '', event_time, event_time, hourly_cost, daily_cost, monthly_cost, cost_type, platform, is_instance_ssm_managed, is_imdsv2_enabled, all_tags if all_tags else [""]):
                LOGGER.error("Could not store data for RDS DB Cluster %s in Account=%s and Region=%s", db_cluster_identifier, helper.account_id, helper.region)
    else:
        LOGGER.info("Not notifying")
