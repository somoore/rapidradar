from collections import defaultdict
import datetime
from dateutil.relativedelta import relativedelta
from messenger.email_alerts import EmailAlert
from utils.dynamodb import (
    UserCostReportsData,
    GetData
)
from utils.cost_optimizer import CostOptimizer
from utils.utility import AWSHelper, Helper
from utils.logger import LOGGER

def handle_event(sender_email, active_resources_table, monthly_user_cost_reports_table, enable_cost_optimizer_recommendations):
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
        last_month_start_date = current_date - relativedelta(months=1)
        one_day_prior_date = current_date - datetime.timedelta(days=1)
        two_months_before_start_date = last_month_start_date - relativedelta(months=1)

        user_resources_table = []
        resources_total_monthly_cost = 0.0

        if len(resources) > 0:
            user_resources_table.append('<div style="background-color:#ffffff; padding:5px 20px 5px 20px;border-radius: 10px">')
            user_resources_table.append('<p style="font-size: 19px;"><b>Resources Still Active</b></p><br>')
            user_resources_headers = ['', 'Account Name', 'Account ID', 'Region', 'Resource Type', 'Resource ID', 'Created At', 'Instance Type', 'Cost Optimizer Status', 'Monthly Cost']
            user_resources_table.append('<table border="1">')
            user_resources_table.append('<tr>')
            for label in user_resources_headers:
                if label == 'Cost Optimizer Status' and not enable_cost_optimizer_recommendations:
                    continue
                user_resources_table.append(f'<th style="padding:5px">{label}</th>')
            user_resources_table.append('</tr>')
            for resource in resources:
                monthly_cost = float(resource['MonthlyCost'].replace("USD ", "")) if resource['MonthlyCost'] else 0.0
                resources_total_monthly_cost += monthly_cost

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
                user_resources_table.append(f"<td style='padding:5px'>USD {monthly_cost:.2f}</td>")
                user_resources_table.append('</tr>')

            user_resources_table.append('<tr>')
            user_resources_table.append("<td style='padding:5px'><b>Total</b></td>")
            range_index = 7
            if enable_cost_optimizer_recommendations:
                range_index+=1
            for _ in range(range_index):
                user_resources_table.append("<td style='padding:5px'></td>")
            user_resources_table.append(f"<td style='padding:5px'>USD {resources_total_monthly_cost:.2f}</td>")
            user_resources_table.append('</tr>')

            user_resources_table.append('</table>')
            user_resources_table.append('</div><br>')
            user_resources_table = '\n'.join([str(elem) for elem in user_resources_table])

            last_user_report_metadata = {}
            if created_by:
                last_user_report_metadata = UserCostReportsData(monthly_user_cost_reports_table).get_latest_data_by_user(created_by, last_month_start_date, two_months_before_start_date)
            percentage_change = 100
            if last_user_report_metadata:
                last_monthly_cost = float(last_user_report_metadata['total_monthly_cost']['S'].replace("USD ", "")) if last_user_report_metadata['total_monthly_cost']['S'] else 0.0
                percentage_change = round(((resources_total_monthly_cost - last_monthly_cost) / last_monthly_cost) * 100, 2)
            percentage_status = f"down by {abs(percentage_change)}%" if percentage_change < 0 else f"up by {abs(percentage_change)}%" if percentage_change > 0 else "unchanged"

            if not isinstance(resources_total_monthly_cost, str):
                resources_total_monthly_cost = f"USD {resources_total_monthly_cost:.2f}"
            if Helper().is_user_email(created_by):
                if not UserCostReportsData(monthly_user_cost_reports_table).store_monthly_data(created_by, Helper().get_cst_cdt_date(), resources_total_monthly_cost, percentage_status):
                    LOGGER.error("Could not add metadata for cost report metadata for user %s", created_by)
                else:
                    LOGGER.info("Successfully stored cost report metadata for user %s", created_by)
                messenger = EmailAlert(sender_email, "", "")
                status, response = messenger.send_monthly_cost_report(created_by, one_day_prior_date, last_month_start_date, user_resources_table, percentage_status)
                if status:
                    LOGGER.info(response)
                else:
                    LOGGER.error("%s", response)
            else:
                LOGGER.info("User %s is not a valid email address, hence could not save cost report metadata to %s table or send email", created_by, monthly_user_cost_reports_table)
