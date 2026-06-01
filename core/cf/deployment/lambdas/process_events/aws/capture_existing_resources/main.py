import json
import datetime
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from utils.ec2 import EC2
from utils.rds import RDS
from utils.efs import EFS
from utils.pricing import Pricing
from utils.events import Events
from utils.dynamodb import (
    ActiveResourcesData,
    IAMKeyPairAccessTrackerData,
    GetData
)
from utils.utility import AWSHelper, Alert, Helper
from utils.logger import LOGGER

def handle_event(helper: AWSHelper, event, project_name, event_bus_arn, sender_email, engineer_facing_notification_app, engineer_facing_webhook_urls, security_admin_facing_notification_app, security_admin_facing_webhook_urls, active_resources_table, iam_keypair_access_tracker_table, disable_reminders_for_secret_access_key_expiry, iam_secret_access_key_expiry, deploy_cmdb_project, deploy_iam_keypair_access_tracker_project):
    active_session = helper.get_active_session()
    ec2_utils = EC2(active_session, helper.region)
    rds_utils = RDS(active_session, helper.region)
    efs_utils = EFS(active_session, helper.region)
    events_utils = Events(helper.account_id, helper.region)
    pricing_utils = Pricing(active_session, helper.region)
    account_name = helper.get_account_name()

    if event['ResourceType'] == 'IAMAccessKey' and deploy_iam_keypair_access_tracker_project:
        records = GetData(iam_keypair_access_tracker_table).get_by_id('iam_user', event['UserName'], 'access_key_id', event['AccessKeyId'])
        if not records:
            is_user_email = Helper().is_user_email(event['CreatedBy'])
            create_date = datetime.datetime.strptime(event['CreateDate'], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.UTC)
            reminder_dates = []
            if not disable_reminders_for_secret_access_key_expiry:
                reminder_after_days = [int(round(iam_secret_access_key_expiry/3, 0)), int(round(iam_secret_access_key_expiry/2, 0)), int(round(iam_secret_access_key_expiry/1.5, 0)), iam_secret_access_key_expiry-5, iam_secret_access_key_expiry-2, iam_secret_access_key_expiry-1, iam_secret_access_key_expiry]
                for day in reminder_after_days:
                    reminder_dates.append(json.dumps({"date": (create_date + datetime.timedelta(days=day)).strftime('%Y-%m-%d'), "sent": False}))

            if not IAMKeyPairAccessTrackerData(iam_keypair_access_tracker_table).store(helper.account_id, account_name, event['UserName'], event['AccessKeyId'], event['Status'], event['CreatedBy'] if is_user_email else '', event['CreateDate'], event['LastUsedDate'], [""], reminder_dates if reminder_dates else [""], event['Tags'] if event['Tags'] else [""]):
                LOGGER.error("Could not store data for Access Key ID %s of IAM User %s into IAM KeyPair Access Tracker DynamoDB Table", event['AccessKeyId'], event['UserName'])
            if event['Status'] == 'Active':
                if not events_utils.create_rules_to_capture_iam_user_events(active_session, event['UserName'], event['AccessKeyId'], project_name, event_bus_arn):
                    LOGGER.error("Could not create CloudWatch Event Rule for AccessKeyId %s of IAM User %s", event['AccessKeyId'], event['UserName'])
            messenger = None
            email_messenger = None
            if is_user_email:
                messenger = EventAlert(engineer_facing_notification_app, helper.account_id, helper.region, engineer_facing_webhook_urls)
                email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
            else:
                messenger = EventAlert(security_admin_facing_notification_app, helper.account_id, helper.region, security_admin_facing_webhook_urls)
            alerts_handler = Alert(None, [], False, False, messenger, False, {}, None, None, None)
            severity = 'High'
            alert_args = {
                "severity": severity,
                "is_new": False,
                "iam_user": helper.iam_user,
                "secret_access_key_user": event['UserName'],
                "access_key_id": event['AccessKeyId'],
                "created_by": event['CreatedBy'] if is_user_email else '',
                "created_at": event['CreateDate'],
                "deploy_iam_keypair_access_tracker_project": deploy_iam_keypair_access_tracker_project
            }
            alerts_handler.handler('secret_access_key_creation_message', alert_args, email_messenger, None)

    elif deploy_cmdb_project:
        instance_type, public_ip, cost_type, platform, is_instance_ssm_managed, is_imdsv2_enabled = '', '', '', '', '', ''
        hourly_cost, daily_cost, monthly_cost = '', '', ''

        if 'InstanceType' in event:
            instance_type = event['InstanceType']
        if 'PublicIp' in event:
            public_ip = event['PublicIp']
        if 'CostType' in event:
            cost_type = event['CostType']
        if 'Platform' in event:
            platform = event['Platform']
        if 'IsSSMManged' in event:
            is_instance_ssm_managed = event['IsSSMManged']
        if event['ResourceType'] == 'EC2Instance':
            is_imdsv2_enabled = 'Yes' if ec2_utils.is_instance_imdsv2_enabled(event['ResourceId']) else 'No'
            spot_request_id = ''
            for tag in event['Tags']:
                if tag.split(' ')[0].rstrip(':').startswith('aws:ec2spot:'):
                    spot_request_id = tag.split(' ')[1]
            cost_type, tenancy, usage_operation, platform_detail, platform = ec2_utils.get_instance_cost_details(event['ResourceId'])
            if cost_type == 'spot':
                hourly_cost, daily_cost, monthly_cost = ec2_utils.get_spot_price(instance_type, platform_detail, spot_request_id)
            else:
                hourly_cost, daily_cost, monthly_cost = pricing_utils.get_instance_cost(instance_type, cost_type, usage_operation, tenancy)
        elif event['ResourceType'].startswith('RDSDB'):
            instance_class, rds_engine, storage_type = rds_utils.get_rds_cost_details(event['ResourceType'], event['ResourceId'])
            instance_type = instance_class
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
        elif event['ResourceType'] == 'EKSCluster':
            hourly_cost, daily_cost, monthly_cost = pricing_utils.get_cluster_cost()
        elif event['ResourceType'] == 'EFSFileSystem':
            is_multi_az, standard_gb_hours, infa_gb_hours = efs_utils.get_efs_cost_details(event['ResourceId'])
            hourly_cost, daily_cost, monthly_cost = pricing_utils.get_efs_cost(is_multi_az, standard_gb_hours, infa_gb_hours)
        if not isinstance(hourly_cost, str):
            hourly_cost = f"USD {hourly_cost:.2f}"
        if not ActiveResourcesData(active_resources_table).store(helper.account_id, account_name, helper.region, event['DeployMethod'], event['Team'], event['CreatedBy'], event['ResourceId'], instance_type, event['ResourceType'], event['State'], public_ip, event['CreatedAt'], event['LaunchedAt'], hourly_cost, daily_cost, monthly_cost, cost_type, platform, is_instance_ssm_managed, is_imdsv2_enabled, event['Tags'] if event['Tags'] else [""]):
            LOGGER.error("Could not store data for %s %s", event['ResourceType'], event['ResourceId'])
        else:
            LOGGER.info("Data stored for %s %s", event['ResourceType'], event['ResourceId'])
