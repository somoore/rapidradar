from collections import defaultdict
import datetime
from utils.dynamodb import (
    UserCostReportsData,
    GetData,
    DeleteData
)
from utils.utility import AWSHelper, Helper
from utils.logger import LOGGER
from utils.cost_optimizer import CostOptimizer
from utils.ec2 import EC2
from utils.ssm import SSM
from messenger.email_alerts import EmailAlert
from pagerduty.main import PagerDuty

def handle_event(aws_org_name, deploy_cmdb_project, active_resources_table, weekly_user_cost_reports_table, enable_cost_optimizer_recommendations, track_ssm_doc_assoc_failures, create_pagerduty_incidents_for_ssm_failures, ssm_document_association_failure_tracker_table, create_incidents_on_pagerduty, is_pd_integration_type_restapi, pagerduty_routing_key, pagerduty_api_token, pagerduty_service_id, pagerduty_user_email_address, sender_email_address, receiver_email_addresses):
    if deploy_cmdb_project:
        users_active_resources = defaultdict(list)
        records = GetData(active_resources_table).get()
        for record in records:
            if record['deploy_method']['S'] not in ['Terraform', 'terraform'] and record['current_status']['S'] not in ['stopping', 'stopped']:
                helper = AWSHelper({'account': record['account_id']['S'], 'region': record['region']['S']})

                created_by = record['created_by']['S']
                users_active_resources_data = {
                    'AccountName': record['account_name']['S'],
                    'AccountId': record['account_id']['S'],
                    'Region': record['region']['S'],
                    'CreatedAt': record['created_at']['S'],
                    'ResourceType': record['resource_type']['S'],
                    'ResourceId': record['resource_id']['S'],
                    'CurrentStatus': record['current_status']['S'],
                    'InstanceType': record['instance_type']['S'],
                    'HourlyCost': record['hourly_cost']['S'],
                    'DailyCost': record['daily_cost']['S'],
                    'MonthlyCost': record['monthly_cost']['S']
                }
                if enable_cost_optimizer_recommendations:
                    optimizer_status = None
                    if record['resource_type']['S'] == 'EC2Instance':
                        active_session = helper.get_active_session()
                        cost_optimizer_utils = CostOptimizer(active_session, helper.region)
                        optimizer_status = cost_optimizer_utils.get_compute_optimizer_recommendations(record['resource_id']['S'], helper.account_id)
                    users_active_resources_data['OptimizerStatus'] = optimizer_status if optimizer_status is not None else ''
                users_active_resources[created_by].append(users_active_resources_data)
        for created_by, resources in users_active_resources.items():
            current_date = datetime.datetime.now(datetime.UTC).date()
            one_day_prior_date = current_date - datetime.timedelta(days=1)
            last_week_start_date = current_date - datetime.timedelta(days=7)
            two_weeks_before_start_date = last_week_start_date - datetime.timedelta(days=7)

            user_resources_table = []
            resources_total_weekly_cost = 0.0

            if len(resources) > 0:
                user_resources_table.append('<div style="background-color:#ffffff; padding:5px 20px 5px 20px;border-radius: 10px">')
                user_resources_table.append('<p style="font-size: 19px;"><b>Resources Still Active</b></p><br>')
                user_resources_headers = ['', 'Account Name', 'Account ID', 'Region', 'Resource Type', 'Resource ID', 'Created At', 'Instance Type', 'Cost Optimizer Status', 'Weekly Cost']
                user_resources_table.append('<table border="1">')
                user_resources_table.append('<tr>')
                for label in user_resources_headers:
                    if label == 'Cost Optimizer Status' and not enable_cost_optimizer_recommendations:
                        continue
                    user_resources_table.append(f'<th style="padding:5px">{label}</th>')
                user_resources_table.append('</tr>')
                for resource in resources:
                    daily_cost = float(resource['DailyCost'].replace("USD ", "")) if resource['DailyCost'] else 0.0
                    weekly_cost = daily_cost * 7
                    resources_total_weekly_cost += weekly_cost

                    user_resources_table.append('<tr>')
                    user_resources_table.append("<td style='padding:5px'> </td>")
                    user_resources_table.append(f"<td style='padding:5px'>{resource['AccountName']}</td>")
                    user_resources_table.append(f"<td style='padding:5px'>{resource['AccountId']}</td>")
                    user_resources_table.append(f"<td style='padding:5px'>{resource['Region']}</td>")
                    user_resources_table.append(f"<td style='padding:5px'>{resource['ResourceType']}</td>")
                    user_resources_table.append(f"<td style='padding:5px'>{resource['ResourceId']}</td>")
                    user_resources_table.append(f"<td style='padding:5px'>{resource['CreatedAt']}</td>")
                    user_resources_table.append(f"<td style='padding:5px'>{resource['InstanceType']}</td>")
                    if enable_cost_optimizer_recommendations:
                        user_resources_table.append(f"<td style='padding:5px'>{resource['OptimizerStatus']}</td>")
                    user_resources_table.append(f"<td style='padding:5px'>USD {weekly_cost:.2f}</td>")
                    user_resources_table.append('</tr>')

                user_resources_table.append('<tr>')
                user_resources_table.append("<td style='padding:5px'><b>Total</b></td>")
                range_index = 7
                if enable_cost_optimizer_recommendations:
                    range_index+=1
                for _ in range(range_index):
                    user_resources_table.append("<td style='padding:5px'></td>")
                user_resources_table.append(f"<td style='padding:5px'>USD {resources_total_weekly_cost:.2f}</td>")
                user_resources_table.append('</tr>')

                user_resources_table.append('</table>')
                user_resources_table.append('</div><br>')
                user_resources_table = '\n'.join([str(elem) for elem in user_resources_table])

                last_user_report_metadata = {}
                if created_by:
                    last_user_report_metadata = UserCostReportsData(weekly_user_cost_reports_table).get_latest_data_by_user(created_by, last_week_start_date, two_weeks_before_start_date)
                percentage_change = 100
                if last_user_report_metadata:
                    last_weekly_cost = float(last_user_report_metadata['total_weekly_cost']['S'].replace("USD ", "")) if last_user_report_metadata['total_weekly_cost']['S'] else 0.0
                    percentage_change = round(((resources_total_weekly_cost - last_weekly_cost) / last_weekly_cost) * 100, 2)
                percentage_status = f"down by {abs(percentage_change)}%" if percentage_change < 0 else f"up by {abs(percentage_change)}%" if percentage_change > 0 else "unchanged"

                if not isinstance(resources_total_weekly_cost, str):
                    resources_total_weekly_cost = f"USD {resources_total_weekly_cost:.2f}"
                if Helper().is_user_email(created_by):
                    if not UserCostReportsData(weekly_user_cost_reports_table).store_weekly_data(created_by, Helper().get_cst_cdt_date(), resources_total_weekly_cost, percentage_status):
                        LOGGER.error("Could not add metadata for cost report metadata for user %s", created_by)
                    else:
                        LOGGER.info("Successfully stored cost report metadata for user %s", created_by)
                    messenger = EmailAlert(sender_email_address, "", "")
                    status, response = messenger.send_weekly_cost_report(created_by, one_day_prior_date.strftime('%b %d, %Y'), last_week_start_date.strftime('%b %d, %Y'), user_resources_table, percentage_status)
                    if status:
                        LOGGER.info(response)
                    else:
                        LOGGER.error("%s", response)
                else:
                    LOGGER.info("User %s is not a valid email address, hence could not save cost report metadata to %s table or send email", created_by, weekly_user_cost_reports_table)

    if track_ssm_doc_assoc_failures:
        association_failed_instances = {}
        failed_ssm_doc_associations = []
        records = GetData(ssm_document_association_failure_tracker_table).get()
        for record in records:
            account_id, account_name, region = record['account_id']['S'], record['account_name']['S'], record['region']['S']
            instance_id, ssm_document_name, association_id = record['instance_id']['S'], record['ssm_document_name']['S'], record['association_id']['S']
            detail = { 'account': account_id, 'region': region }
            helper = AWSHelper(detail)
            active_session = helper.get_active_session()
            ssm_utils = SSM(active_session, helper.region)
            ec2_utils = EC2(active_session, helper.region)
            failed_ssm_doc_associations = []

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
            else:
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

        if association_failed_instances:
            failed_ssm_doc_associations.append('<table border="1">')
            failed_ssm_doc_associations.append('<tr>')
            header = ['State Manager Association ID', 'SSM Document Name', 'Account', 'Region', 'Failed Instances']
            for label in header:
                failed_ssm_doc_associations.append(f'<th style="padding:5px">{label}</th>')
            failed_ssm_doc_associations.append('</tr>')
            for assoc_id, assoc_details in association_failed_instances.items():
                failed_ssm_doc_associations.append('<tr>')
                failed_ssm_doc_associations.append(f"<td style='padding:5px'>{assoc_id}</td>")
                failed_ssm_doc_associations.append(f"<td style='padding:5px'>{assoc_details['DocumentName']}</td>")
                failed_ssm_doc_associations.append(f"<td style='padding:5px'>{assoc_details['AccountName']} ({assoc_details['AccountId']})</td>")
                failed_ssm_doc_associations.append(f"<td style='padding:5px'>{assoc_details['Region']}</td>")
                failed_ssm_doc_associations.append(f"<td style='padding:5px'>{', '.join(assoc_details['Instances'])}</td>")
                failed_ssm_doc_associations.append('</tr>')
            failed_ssm_doc_associations.append('</table>')
        failed_ssm_doc_associations = '\n'.join([str(elem) for elem in failed_ssm_doc_associations])
        if failed_ssm_doc_associations:
            email_messenger = EmailAlert(sender_email=sender_email_address)
            body_html = f"""
            <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
                <p style="font-size: 22px;"><b>SSM Document Association Failure Details{f" (AWS Organization-{aws_org_name})" if aws_org_name else ""}</b></p>
                <div style="background-color:#ffffff; padding:5px 20px 5px 20px;border-radius: 10px">
                    {failed_ssm_doc_associations}
                </div>
            </body>"""
            for recipient in receiver_email_addresses:
                email_messenger.send_email("SSM Document Association Failures", body_html, recipient)
