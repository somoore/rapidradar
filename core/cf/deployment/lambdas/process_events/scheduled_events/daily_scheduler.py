import json
from collections import defaultdict
import datetime
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from utils.iam import IAM
from utils.dynamodb import (
    IAMKeyPairAccessTrackerData,
    UserCostReportsData,
    GetData
)
from utils.cost_optimizer import CostOptimizer
from utils.utility import AWSHelper, Alert, Helper
from utils.logger import LOGGER

def handle_event(home_region, notification_app, webhook_urls, sender_email, auto_remediate_unused_secret_access_keypair, inactive_criteria_days, active_resources_table, daily_user_cost_reports_table, enable_cost_optimizer_recommendations, deploy_iam_keypair_access_tracker_project, iam_keypair_access_tracker_table, disable_reminders_for_secret_access_key_expiry, iam_secret_access_key_expiry, deploy_cmdb_project):
    if deploy_iam_keypair_access_tracker_project:
        iam_keypair_access_tracker_table_ops = IAMKeyPairAccessTrackerData(iam_keypair_access_tracker_table)
        records = GetData(iam_keypair_access_tracker_table).get()
        for record in records:
            account_id, account_name, iam_user, access_key_id, status, create_date, key_activity, expiry_reminders = record['account_id']['S'], record['account_name']['S'], record['iam_user']['S'], record['access_key_id']['S'], record['status']['S'], datetime.datetime.strptime(record['create_date']['S'], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.UTC), record['key_activity']['SS'], record['expiry_reminders']['SS']
            helper = AWSHelper({'account': account_id, 'region': home_region})
            messenger = EventAlert(notification_app, account_id, home_region, webhook_urls)
            active_session = helper.get_active_session()
            iam_utils = IAM(active_session)
            last_used, current_status = '', ''
            make_key_inactive = False
            current_datetime = datetime.datetime.now(datetime.UTC)

            last_used = iam_utils.get_access_key_last_used(access_key_id)
            current_status = iam_utils.get_access_key_status(iam_user, access_key_id)
            iam_user_tags, created_by = iam_utils.get_iam_user_tags_created_by(iam_user)

            if last_used:
                date_difference = current_datetime - datetime.datetime.strptime(last_used, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.UTC)
                if date_difference > datetime.timedelta(days=inactive_criteria_days):
                    make_key_inactive = True
            else:
                date_difference = current_datetime - create_date
                if date_difference > datetime.timedelta(days=inactive_criteria_days):
                    make_key_inactive = True

            if last_used or current_status != status:
                if not iam_keypair_access_tracker_table_ops.store(account_id, account_name, iam_user, access_key_id, current_status, created_by, record['create_date']['S'], last_used, key_activity, expiry_reminders, iam_user_tags if iam_user_tags else [""]):
                    LOGGER.error("Could not update data for Access Key ID %s of IAM User %s into IAM KeyPair Access Tracker DynamoDB Table", access_key_id, iam_user)

            if auto_remediate_unused_secret_access_keypair:
                if status == 'Active' and make_key_inactive:
                    LOGGER.info("Access Key ID %s has been inactive for more than %s days. Deactivating it...", access_key_id, str(inactive_criteria_days))
                    if not iam_utils.make_access_key_inactive(iam_user, access_key_id):
                        LOGGER.error("Could not deactivate Access Key ID %s of IAM User %s in Account %s", access_key_id, iam_user, account_id)
                    else:
                        if not iam_keypair_access_tracker_table_ops.store(account_id, account_name, iam_user, access_key_id, 'Inactive', created_by, record['create_date']['S'], last_used, key_activity, expiry_reminders, iam_user_tags if iam_user_tags else [""]):
                            LOGGER.error("Could not update data for Access Key ID %s of IAM User %s of Account %s", access_key_id, iam_user, account_id)
                        severity = 'Informational'
                        status, reason = messenger.send_notification('secret_access_key_deactivated_remediation_message', {
                            "severity": severity,
                            "iam_user": iam_user,
                            "access_key_id": access_key_id
                        })
                        if not status:
                            LOGGER.error(str(reason))

            if not disable_reminders_for_secret_access_key_expiry:
                reminder_dates_details = []
                reminder_dates = []
                for day in expiry_reminders:
                    day = json.loads(day)
                    reminder_dates_details.append(day)
                    reminder_dates.append(day['date'])
                if iam_utils.check_iam_user_exists(iam_user) and status == 'Active':
                    expiry_datetime = create_date + datetime.timedelta(days=iam_secret_access_key_expiry)
                    days_remaining = (expiry_datetime.date() - current_datetime.date()).days
                    if current_datetime <= expiry_datetime and current_datetime.strftime('%Y-%m-%d') in reminder_dates:
                        email_messenger = None
                        if created_by:
                            email_messenger = EmailAlert(sender_email, account_id, home_region)
                        severity = 'Informational'
                        alert_args = {
                            "severity": severity,
                            "iam_user": iam_user,
                            "access_key_id": access_key_id,
                            "created_by": created_by,
                            "creation_date": create_date.strftime('%Y-%m-%d %H:%M:%S %Z'),
                            "expiry_date": expiry_datetime.strftime('%Y-%m-%d %H:%M:%S %Z'),
                            "days_remaining": days_remaining
                        }
                        alerts_handler = Alert(None, [], False, True, messenger, False, None, None, None, None)
                        alerts_handler.handler('secret_access_key_expiry_reminder_message', alert_args, email_messenger, None)
                        reminder_dates_details_str = []
                        for day in reminder_dates_details:
                            if day['date'] == current_datetime.strftime('%Y-%m-%d'):
                                day['sent'] = True
                            reminder_dates_details_str.append(json.dumps(day))
                        if not iam_keypair_access_tracker_table_ops.store(account_id, account_name, iam_user, access_key_id, current_status, created_by, record['create_date']['S'], last_used, key_activity, reminder_dates_details_str, iam_user_tags if iam_user_tags else [""]):
                            LOGGER.error("Could not update data for Access Key ID %s of IAM User %s of Account %s", access_key_id, iam_user, account_id)

    if deploy_cmdb_project:
        users_active_resources = defaultdict(list)
        records = GetData(active_resources_table).get()
        messenger = EmailAlert(sender_email, "", "")
        for record in records:
            if record['deploy_method']['S'] not in ['Terraform', 'terraform']:
                helper = AWSHelper({'account': record['account_id']['S'], 'region': record['region']['S']})
                active_session = helper.get_active_session()

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
                        cost_optimizer_utils = CostOptimizer(active_session, helper.region)
                        optimizer_status = cost_optimizer_utils.get_compute_optimizer_recommendations(record['resource_id']['S'], helper.account_id)
                    users_active_resources_data['OptimizerStatus'] = optimizer_status if optimizer_status is not None else ''
                users_active_resources[created_by].append(users_active_resources_data)

        for created_by, resources in users_active_resources.items():
            findings_found = False
            hr24_resources = []
            hr24_resources_table = []
            hr24_resources_total_hourly_cost = 0.0
            hr24_resources_total_daily_cost = 0.0
            hr24_resources_total_weekly_cost = 0.0
            hr24_resources_total_monthly_cost = 0.0
            hr24_old_resources = []
            hr24_old_resources_table = []
            hr24_old_resources_total_hourly_cost = 0.0
            hr24_old_resources_total_daily_cost = 0.0
            hr24_old_resources_total_weekly_cost = 0.0
            hr24_old_resources_total_monthly_cost = 0.0
            stopped_resources = []
            stopped_resources_table = []
            for resource in resources:
                if resource['CurrentStatus'] not in ['stopping', 'stopped']:
                    current_datetime = datetime.datetime.now(datetime.UTC)
                    difference = datetime.timedelta(days=1)
                    if resource['CreatedAt']:
                        difference = current_datetime - datetime.datetime.strptime(resource['CreatedAt'],"%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.UTC)
                    if difference.days == 0:
                        hr24_resources_data = {
                            'AccountName': resource['AccountName'],
                            'AccountId': resource['AccountId'],
                            'Region': resource['Region'],
                            'ResourceType': resource['ResourceType'],
                            'ResourceId': resource['ResourceId'],
                            'CreatedAt': resource['CreatedAt'],
                            'InstanceType': resource['InstanceType'],
                            'HourlyCost': resource['HourlyCost'],
                            'DailyCost': resource['DailyCost'],
                            'MonthlyCost': resource['MonthlyCost']
                        }
                        if enable_cost_optimizer_recommendations:
                            hr24_resources_data['OptimizerStatus'] = resource['OptimizerStatus']
                        hr24_resources.append(hr24_resources_data)
                    else:
                        hr24_old_resources_data = {
                            'AccountName': resource['AccountName'],
                            'AccountId': resource['AccountId'],
                            'Region': resource['Region'],
                            'ResourceType': resource['ResourceType'],
                            'ResourceId': resource['ResourceId'],
                            'CreatedAt': resource['CreatedAt'],
                            'InstanceType': resource['InstanceType'],
                            'HourlyCost': resource['HourlyCost'],
                            'DailyCost': resource['DailyCost'],
                            'MonthlyCost': resource['MonthlyCost']
                        }
                        if enable_cost_optimizer_recommendations:
                            hr24_old_resources_data['OptimizerStatus'] = resource['OptimizerStatus']
                        hr24_old_resources.append(hr24_old_resources_data)
                elif resource['CurrentStatus'] in ['stopping', 'stopped']:
                    stopped_resources_data = {
                        'AccountName': resource['AccountName'],
                        'AccountId': resource['AccountId'],
                        'Region': resource['Region'],
                        'ResourceType': resource['ResourceType'],
                        'ResourceId': resource['ResourceId'],
                        'CreatedAt': resource['CreatedAt'],
                        'InstanceType': resource['InstanceType'],
                        'HourlyCost': resource['HourlyCost'],
                        'DailyCost': resource['DailyCost'],
                        'MonthlyCost': resource['MonthlyCost']
                    }
                    if enable_cost_optimizer_recommendations:
                        stopped_resources_data['OptimizerStatus'] = resource['OptimizerStatus']
                    stopped_resources.append(stopped_resources_data)
            if len(hr24_resources) > 0 or len(hr24_old_resources) > 0 or len(stopped_resources) > 0:
                findings_found = True
            if len(hr24_resources) > 0:
                hr24_resources_table.append('<div style="background-color:#ffffff; padding:5px 20px 5px 20px;border-radius: 10px">')
                hr24_resources_table.append('<p style="font-size: 19px;"><b>Deploys in the last 24 hours (from report generation)</b></p><br>')
                hr24_resources_headers = ['', 'Account Name', 'Account ID', 'Region', 'Resource Type', 'Resource ID', 'Created At', 'Instance Type', 'Cost Optimizer Status', 'Hourly Cost', 'Daily Cost', 'Weekly Cost', 'Monthly Cost']
                hr24_resources_table.append('<table border="1">')
                hr24_resources_table.append('<tr>')
                for label in hr24_resources_headers:
                    if label == 'Cost Optimizer Status' and not enable_cost_optimizer_recommendations:
                        continue
                    hr24_resources_table.append(f'<th style="padding:5px">{label}</th>')
                hr24_resources_table.append('</tr>')

                for resource in hr24_resources:
                    hourly_cost = float(resource['HourlyCost'].replace("USD ", "")) if resource['HourlyCost'] else 0.0
                    hr24_resources_total_hourly_cost += hourly_cost

                    daily_cost = float(resource['DailyCost'].replace("USD ", "")) if resource['DailyCost'] else 0.0
                    hr24_resources_total_daily_cost += daily_cost

                    weekly_cost = daily_cost * 7
                    hr24_resources_total_weekly_cost += weekly_cost

                    monthly_cost = float(resource['MonthlyCost'].replace("USD ", "")) if resource['MonthlyCost'] else 0.0
                    hr24_resources_total_monthly_cost += monthly_cost

                    hr24_resources_table.append('<tr>')
                    hr24_resources_table.append("<td style='padding:5px'> </td>")
                    hr24_resources_table.append(f"<td style='padding:5px'>{resource['AccountName']}</td>")
                    hr24_resources_table.append(f"<td style='padding:5px'>{resource['AccountId']}</td>")
                    hr24_resources_table.append(f"<td style='padding:5px'>{resource['Region']}</td>")
                    hr24_resources_table.append(f"<td style='padding:5px'>{resource['ResourceType']}</td>")
                    hr24_resources_table.append(f"<td style='padding:5px'>{resource['ResourceId']}</td>")
                    hr24_resources_table.append(f"<td style='padding:5px'>{resource['CreatedAt']}</td>")
                    hr24_resources_table.append(f"<td style='padding:5px'>{resource['InstanceType']}</td>")
                    if enable_cost_optimizer_recommendations:
                        hr24_resources_table.append(f"<td style='padding:5px'>{resource['OptimizerStatus']}</td>")
                    hr24_resources_table.append(f"<td style='padding:5px'>{resource['HourlyCost']}</td>")
                    hr24_resources_table.append(f"<td style='padding:5px'>{resource['DailyCost']}</td>")
                    hr24_resources_table.append(f"<td style='padding:5px'>USD {weekly_cost:.2f}</td>")
                    hr24_resources_table.append(f"<td style='padding:5px'>{resource['MonthlyCost']}</td>")
                    hr24_resources_table.append('</tr>')

                hr24_resources_table.append('<tr>')
                hr24_resources_table.append("<td style='padding:5px'><b>Total</b></td>")
                range_index = 7
                if enable_cost_optimizer_recommendations:
                    range_index+=1
                for _ in range(range_index):
                    hr24_resources_table.append("<td style='padding:5px'></td>")
                hr24_resources_table.append(f"<td style='padding:5px'>USD {hr24_resources_total_hourly_cost:.2f}</td>")
                hr24_resources_table.append(f"<td style='padding:5px'>USD {hr24_resources_total_daily_cost:.2f}</td>")
                hr24_resources_table.append(f"<td style='padding:5px'>USD {hr24_resources_total_weekly_cost:.2f}</td>")
                hr24_resources_table.append(f"<td style='padding:5px'>USD {hr24_resources_total_monthly_cost:.2f}</td>")
                hr24_resources_table.append('</tr>')

                hr24_resources_table.append('</table>')
                hr24_resources_table.append('</div><br>')
                hr24_resources_table = '\n'.join([str(elem) for elem in hr24_resources_table])

            if len(hr24_old_resources) > 0:
                hr24_old_resources_table.append('<div style="background-color:#ffffff; padding:5px 20px 5px 20px;border-radius: 10px">')
                hr24_old_resources_table.append('<p style="font-size: 19px;"><b>Deploys Older than 24 hours (from report generation)</b></p><br>')
                hr24_old_resources_headers = ['', 'Account Name', 'Account ID', 'Region', 'Resource Type', 'Resource ID', 'Created At', 'Instance Type', 'Cost Optimizer Status', 'Hourly Cost', 'Daily Cost', 'Weekly Cost', 'Monthly Cost']
                hr24_old_resources_table.append('<table border="1">')
                hr24_old_resources_table.append('<tr>')
                for label in hr24_old_resources_headers:
                    if label == 'Cost Optimizer Status' and not enable_cost_optimizer_recommendations:
                        continue
                    hr24_old_resources_table.append(f'<th style="padding:5px">{label}</th>')
                hr24_old_resources_table.append('</tr>')

                for resource in hr24_old_resources:
                    hourly_cost = float(resource['HourlyCost'].replace("USD ", "")) if resource['HourlyCost'] else 0.0
                    hr24_old_resources_total_hourly_cost += hourly_cost

                    daily_cost = float(resource['DailyCost'].replace("USD ", "")) if resource['DailyCost'] else 0.0
                    hr24_old_resources_total_daily_cost += daily_cost

                    weekly_cost = daily_cost * 7
                    hr24_old_resources_total_weekly_cost += weekly_cost

                    monthly_cost = float(resource['MonthlyCost'].replace("USD ", "")) if resource['MonthlyCost'] else 0.0
                    hr24_old_resources_total_monthly_cost += monthly_cost

                    hr24_old_resources_table.append('<tr>')
                    hr24_old_resources_table.append("<td style='padding:5px'> </td>")
                    hr24_old_resources_table.append(f"<td style='padding:5px'>{resource['AccountName']}</td>")
                    hr24_old_resources_table.append(f"<td style='padding:5px'>{resource['AccountId']}</td>")
                    hr24_old_resources_table.append(f"<td style='padding:5px'>{resource['Region']}</td>")
                    hr24_old_resources_table.append(f"<td style='padding:5px'>{resource['ResourceType']}</td>")
                    hr24_old_resources_table.append(f"<td style='padding:5px'>{resource['ResourceId']}</td>")
                    hr24_old_resources_table.append(f"<td style='padding:5px'>{resource['CreatedAt']}</td>")
                    hr24_old_resources_table.append(f"<td style='padding:5px'>{resource['InstanceType']}</td>")
                    if enable_cost_optimizer_recommendations:
                        hr24_old_resources_table.append(f"<td style='padding:5px'>{resource['OptimizerStatus']}</td>")
                    hr24_old_resources_table.append(f"<td style='padding:5px'>{resource['HourlyCost']}</td>")
                    hr24_old_resources_table.append(f"<td style='padding:5px'>{resource['DailyCost']}</td>")
                    hr24_old_resources_table.append(f"<td style='padding:5px'>USD {weekly_cost:.2f}</td>")
                    hr24_old_resources_table.append(f"<td style='padding:5px'>{resource['MonthlyCost']}</td>")
                    hr24_old_resources_table.append('</tr>')

                hr24_old_resources_table.append('<tr>')
                hr24_old_resources_table.append("<td style='padding:5px'><b>Total</b></td>")
                range_index = 7
                if enable_cost_optimizer_recommendations:
                    range_index+=1
                for _ in range(range_index):
                    hr24_old_resources_table.append("<td style='padding:5px'></td>")
                hr24_old_resources_table.append(f"<td style='padding:5px'>USD {hr24_old_resources_total_hourly_cost:.2f}</td>")
                hr24_old_resources_table.append(f"<td style='padding:5px'>USD {hr24_old_resources_total_daily_cost:.2f}</td>")
                hr24_old_resources_table.append(f"<td style='padding:5px'>USD {hr24_old_resources_total_weekly_cost:.2f}</td>")
                hr24_old_resources_table.append(f"<td style='padding:5px'>USD {hr24_old_resources_total_monthly_cost:.2f}</td>")
                hr24_old_resources_table.append('</tr>')

                hr24_old_resources_table.append('</table>')
                hr24_old_resources_table.append('</div><br>')
                hr24_old_resources_table = '\n'.join([str(elem) for elem in hr24_old_resources_table])

            if len(stopped_resources) > 0:
                stopped_resources_table.append('<div style="background-color:#ffffff; padding:5px 20px 5px 20px;border-radius: 10px">')
                stopped_resources_table.append('<p style="font-size: 19px;"><b>Stopped Resources</b></p><br>')
                stopped_resources_headers = ['Account Name', 'Account ID', 'Region', 'Resource Type', 'Resource ID', 'Created At', 'Instance Type', 'Cost Optimizer Status']
                stopped_resources_table.append('<table border="1">')
                stopped_resources_table.append('<tr>')
                for label in stopped_resources_headers:
                    if label == 'Cost Optimizer Status' and not enable_cost_optimizer_recommendations:
                        continue
                    stopped_resources_table.append(f'<th style="padding:5px">{label}</th>')
                stopped_resources_table.append('</tr>')

                for resource in stopped_resources:
                    stopped_resources_table.append('<tr>')
                    stopped_resources_table.append(f"<td style='padding:5px'>{resource['AccountName']}</td>")
                    stopped_resources_table.append(f"<td style='padding:5px'>{resource['AccountId']}</td>")
                    stopped_resources_table.append(f"<td style='padding:5px'>{resource['Region']}</td>")
                    stopped_resources_table.append(f"<td style='padding:5px'>{resource['ResourceType']}</td>")
                    stopped_resources_table.append(f"<td style='padding:5px'>{resource['ResourceId']}</td>")
                    stopped_resources_table.append(f"<td style='padding:5px'>{resource['CreatedAt']}</td>")
                    stopped_resources_table.append(f"<td style='padding:5px'>{resource['InstanceType']}</td>")
                    if enable_cost_optimizer_recommendations:
                        stopped_resources_table.append(f"<td style='padding:5px'>{resource['OptimizerStatus']}</td>")
                    stopped_resources_table.append('</tr>')

                stopped_resources_table.append('</table>')
                stopped_resources_table.append('</div><br>')
                stopped_resources_table = '\n'.join([str(elem) for elem in stopped_resources_table])

            if findings_found:
                total_hourly_cost = hr24_resources_total_hourly_cost + hr24_old_resources_total_hourly_cost
                total_daily_cost = hr24_resources_total_daily_cost + hr24_old_resources_total_daily_cost
                total_weekly_cost = hr24_resources_total_weekly_cost + hr24_old_resources_total_weekly_cost
                total_monthly_cost = hr24_resources_total_monthly_cost + hr24_old_resources_total_monthly_cost
                if not isinstance(total_hourly_cost, str):
                    total_hourly_cost = f"USD {total_hourly_cost:.2f}"
                    total_daily_cost = f"USD {total_daily_cost:.2f}"
                    total_weekly_cost = f"USD {total_weekly_cost:.2f}"
                    total_monthly_cost = f"USD {total_monthly_cost:.2f}"

                if Helper().is_user_email(created_by):
                    if not UserCostReportsData(daily_user_cost_reports_table).store_daily_data(created_by, Helper().get_cst_cdt_date(), total_hourly_cost, total_daily_cost, total_weekly_cost, total_monthly_cost):
                        LOGGER.error("Could not add metadata for cost report metadata for user %s", created_by)
                    else:
                        LOGGER.info("Successfully stored cost report metadata for user %s", created_by)
                    messenger = EmailAlert(sender_email, "", "")
                    status, response = messenger.send_daily_cost_report(created_by, Helper().get_cst_cdt_date(), hr24_resources_table, hr24_old_resources_table, stopped_resources_table)
                    if status:
                        LOGGER.info(response)
                    else:
                        LOGGER.error("%s", response)
                else:
                    LOGGER.info("User %s is not a valid email address, hence could not save cost report metadata to %s table or send email", created_by, daily_user_cost_reports_table)
