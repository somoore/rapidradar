import json
from utils.eks import EKS
from utils.ssm import SSM
from utils.dynamodb import ActiveResourcesData
from utils.events import Events
from utils.pricing import Pricing
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, event_time, sender_email, notification_app, webhook_urls, slack_oauth_token, send_logs_to_azure, customer_id, shared_key, log_type, active_resources_table, project_name, tag_eks_clusters, tag_eks_clusters_using_tag_template_for_tf_deployment, eks_tags_key_value, send_missing_tags_notification_eks_clusters, deploy_cmdb_project, target_arn, eks_cluster_creation_blocked_wo_certain_tags, eks_cluster_creation_scp_tag_keys, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    if 'responseElements' in event and 'requestParameters' in event:
        response_elements = event['responseElements']
        request_params = event['requestParameters']
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
            if eks_cluster_creation_blocked_wo_certain_tags and 'message' in response_elements and 'explicit deny' in response_elements['message']:
                eks_cluster_tag_keys = []
                missing_tags = []
                if 'tags' in request_params:
                    for key in request_params['tags'].keys():
                        eks_cluster_tag_keys.append(key)
                for key in eks_cluster_creation_scp_tag_keys:
                    if key not in eks_cluster_tag_keys:
                        missing_tags.append(key)
                if missing_tags:
                    severity = 'Informational'
                    alert_args = {
                        "severity": severity,
                        "resource_type": "EKS Cluster",
                        "iam_user": helper.iam_user,
                        "tags": missing_tags
                    }
                    alerts_handler = Alert(None, [], is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                    alerts_handler.handler('resource_creation_wo_required_tags_scp_block_error_message', alert_args, email_messenger, slack_bot)
        elif 'errorCode' not in event:
            active_session = helper.get_active_session()
            eks_utils = EKS(active_session, helper.region)
            ssm_utils = SSM(active_session, helper.region)
            events_utils = Events(helper.account_id, helper.region)
            pricing_utils = Pricing(active_session, helper.region)
            response_elements = event['responseElements']
            cluster_name = response_elements['cluster']['name']
            current_state = response_elements['cluster']['status'].lower()
            resource_type = 'EKSCluster'
            cost_type = ''
            deploy_method, deploy_method_key_exists = '', False
            team, team_key_exists = '', False
            deployed_by_key_exists = False
            found_tf_deploy_method = False
            is_tf_deployment = False
            all_tags = [ f"{k}: {v}" for k, v in response_elements['cluster']['tags'].items() ]
            eks_tag_keys = list(response_elements['cluster']['tags'].keys())

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
                hourly_cost, daily_cost, monthly_cost = pricing_utils.get_cluster_cost()
                platform, is_instance_ssm_managed, is_imdsv2_enabled = '', '', ''

                if not deploy_method_key_exists:
                    deploy_method='aws-console'
                    eks_utils.add_tags_to_eks_cluster(helper.account_id, cluster_name, {'DeployMethod': deploy_method})
                if not deployed_by_key_exists:
                    eks_utils.add_tags_to_eks_cluster(helper.account_id, cluster_name, {'DeployedBy': event_by})
                if not team_key_exists:
                    team='unknown'
                    eks_utils.add_tags_to_eks_cluster(helper.account_id, cluster_name, {'Team': team})
                if not ActiveResourcesData(active_resources_table).store(helper.account_id, account_name, helper.region, deploy_method, team, event_by, cluster_name, '', resource_type, current_state, '', event_time, event_time, hourly_cost, daily_cost, monthly_cost, cost_type, platform, is_instance_ssm_managed, is_imdsv2_enabled, all_tags if all_tags else [""]):
                    LOGGER.error("Could not store data for EKS Cluster %s in Account=%s and Region=%s", cluster_name, helper.account_id, helper.region)
                if current_state in ['pending', 'creating']:
                    if not events_utils.create_5_min_status_update_rule(resource_type, cluster_name, target_arn):
                        LOGGER.error("Could not create 5 min cron for EKSCluster %s", cluster_name)
                    else:
                        LOGGER.info("Created 5 min cron for EKSCluster %s", cluster_name)

            if tag_eks_clusters:
                use_params_tags = True
                if tag_eks_clusters_using_tag_template_for_tf_deployment and is_tf_deployment:
                    decrypted_value = json.loads(ssm_utils.get_decrypted_value(f'/{project_name}/EKS_CLUSTER_TAG_TEMPLATE'))
                    for key, value in decrypted_value.items():
                        if value != f"< {key.upper()} >":
                            use_params_tags = False
                            if not eks_utils.add_tags_to_eks_cluster(helper.account_id, cluster_name, {key: value}):
                                LOGGER.error("Could not add tag %s to EKS Cluster %s", key, cluster_name)
                if use_params_tags:
                    for eks_tag in eks_tags_key_value:
                        key_value = eks_tag.split('=')
                        if deploy_method_key_exists and key_value[0] in ['DeployMethod', 'deployMethod', 'Deploymethod', 'deploymethod']:
                            continue
                        if deployed_by_key_exists and key_value[0] in ['DeployedBy', 'deployedBy', 'Deployedby', 'deployedby']:
                            continue
                        if not eks_utils.add_tags_to_eks_cluster(helper.account_id, cluster_name, {key_value[0]: key_value[1]}):
                            LOGGER.error("Could not add tag %s to EKS Cluster %s", key_value[0], cluster_name)

            if send_missing_tags_notification_eks_clusters and not tag_eks_clusters:
                eks_tags_key_value_missing = []
                for tag in eks_tags_key_value:
                    tag_key = tag.split('=')[0]
                    if tag_key not in eks_tag_keys:
                        eks_tags_key_value_missing.append(tag)
                if eks_tags_key_value_missing:
                    severity = 'Low'
                    alert_args = {
                        "severity": severity,
                        "iam_user": helper.iam_user,
                        "resource_type": "EKS Cluster",
                        "resource_id": cluster_name,
                        "tags": eks_tags_key_value_missing
                    }
                    azure_data['Severity'] = severity
                    azure_data['Event'] = f"User {helper.iam_user} created an EKS Cluster named {cluster_name} without proper tags"
                    alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                    alerts_handler.handler('resource_creation_without_tags_message', alert_args, email_messenger, slack_bot)
                else:
                    LOGGER.info("EKS Cluster was created with proper tags")
    else:
        LOGGER.info("responseElements or requestParameters prop not found in event")
