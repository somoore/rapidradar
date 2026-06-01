from os import getenv
from collections import defaultdict
import datetime
import json
import logging
import pytz
import utils
from messenger import Messenger

logger = logging.getLogger()
logger.setLevel(logging.INFO)

CROSS_ACCOUNT_ROLE = getenv('CROSS_ACCOUNT_ROLE')
UNUSED_EC2_INSTANCES_DYNAMO_DB_TABLE = getenv('UNUSED_EC2_INSTANCES_TABLE')
UNUSED_SECURITY_GROUPS_DYNAMODB_TABLE = getenv('UNUSED_SECURITY_GROUPS_TABLE')
UNUSED_EBS_VOLUMES_DYNAMODB_TABLE = getenv('UNUSED_EBS_VOLUMES_TABLE')
SENDER_EMAIL_ADDRESS = getenv('SENDER_EMAIL_ADDRESS')
NOTIFICATION_CONFIGS_SECRET_NAME = getenv('NOTIFICATION_CONFIGS_SECRET_NAME')
NOTIFICATION_CONFIGS = utils.get_secret_value(NOTIFICATION_CONFIGS_SECRET_NAME)
NOTIFICATION_APP = NOTIFICATION_CONFIGS.get('NOTIFICATION_APP', '')
WEBHOOK_URLS = ""
if "APP_CONFIG" in NOTIFICATION_CONFIGS:
    WEBHOOK_URLS = NOTIFICATION_CONFIGS.get("APP_CONFIG")
else:
    WEBHOOK_URLS = NOTIFICATION_CONFIGS.get("WEBHOOK_URL")
WEBHOOK_URLS = WEBHOOK_URLS.replace(' ', '').split(',')

def lambda_handler(event, context):
    logger.info("Processing Event: %s", event)
    if UNUSED_EC2_INSTANCES_DYNAMO_DB_TABLE:
        unused_instances = defaultdict(lambda: defaultdict(list))
        scan_response = utils.scan_dynamodb(UNUSED_EC2_INSTANCES_DYNAMO_DB_TABLE)
        if scan_response['Count'] > 0:
            for item in scan_response['Items']:
                notified_at = item['notified_at']['S'] if item['notified_at']['S'] != 'None' else None
                alert_step = int(item['step']['S'])

                is_instance_older, status_code = utils.is_instance_older_than_5_days(item['account_id']['S'], item['region']['S'], item['instance_id']['S'])
                if not is_instance_older:
                    email_resources_block = []
                    alert_resources_block = []
                    messenger = Messenger(NOTIFICATION_APP, WEBHOOK_URLS, item['instance_id']['S'], item['region']['S'], 'EC2Instance', True if status_code == 'InvalidInstanceID.NotFound' else False)
                    if not utils.remove_deletion_tag(item['account_id']['S'], item['region']['S'], item['instance_id']['S']):
                        logger.error("Could not remove [Pending Deletion] Tag from EC2 Instance %s", item['instance_id']['S'])
                    if not utils.cleanup_dynamodb(UNUSED_EC2_INSTANCES_DYNAMO_DB_TABLE, item['account_id']['S'], 'instance_id', item['instance_id']['S']):
                        logger.error("Could not cleanup metadata for instance %s", item['instance_id']['S'])

                    if status_code == 'SKIP':
                        break
                    email_resources_block.append(f"<b>Instance ID:</b> {item['instance_id']['S']}")
                    email_resources_block.append(f"<b>Account ID:</b> {item['account_id']['S']}")
                    email_resources_block.append(f"<b>Region:</b> {item['region']['S']}")

                    if NOTIFICATION_APP == 'slack':
                        alert_resources_block = [str(item).replace("<b>", "*").replace("</b>", "*").replace("<br>","") for item in email_resources_block]
                    elif NOTIFICATION_APP == 'msteams':
                        alert_resources_block = [str(item).replace("<b>", "**").replace("</b>", "**") for item in email_resources_block]
                    elif NOTIFICATION_APP == 'googlechat':
                        alert_resources_block = email_resources_block

                    status, response = messenger.send_email(SENDER_EMAIL_ADDRESS, item['created_by']['S'], email_resources_block, None, '', False, None)
                    if status:
                        logger.info(response)
                    else:
                        logger.error("%s", response)
                    status, response = messenger.send_alert(item['created_by']['S'], alert_resources_block, None, '', False, None)
                    if status:
                        logger.info(response)
                    else:
                        logger.error("%s", response)
                else:
                    alert_step = alert_step + 1
                    created_by = item['created_by']['S']

                    unused_instances[created_by][alert_step].append({
                        'InstanceId': item['instance_id']['S'],
                        'AccountId': item['account_id']['S'],
                        'Region': item['region']['S'],
                        'CreatedAt': item['created_at']['S'],
                        'StoppedAt': item['stopped_at']['S'],
                        'NotifiedAt': notified_at,
                    })

            for created_by, alert_step in unused_instances.items():
                for step, instances in alert_step.items():
                    email_resources_block = []
                    alert_resources_block = []
                    old_notified_at = ''
                    current_datetime = utils.get_cst_cdt_datetime(datetime.datetime.now(datetime.timezone.utc))

                    for instance in instances:
                        old_notified_at = instance['NotifiedAt']
                        messenger = Messenger(NOTIFICATION_APP, WEBHOOK_URLS, instance['AccountId'], instance['Region'], 'EC2Instance', False)

                        email_resources_block.append(f"<b>Instance ID:</b> {instance['InstanceId']}")
                        email_resources_block.append(f"<b>Account ID:</b> {instance['AccountId']}")
                        email_resources_block.append(f"<b>Region:</b> {instance['Region']}")
                        email_resources_block.append(f"<b>Launched At:</b> {instance['CreatedAt']}")

                        hour_diff = 0
                        if old_notified_at is not None:
                            timezone_abbrev = utils.extract_timezone_abbreviation(old_notified_at)
                            difference = datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.strptime(old_notified_at, f'%b %d, %Y %I:%M %p {timezone_abbrev}').replace(tzinfo=pytz.timezone('CST6CDT')).astimezone(pytz.utc)
                            hour_diff = int(difference.total_seconds() / 3600)

                        if step == 1 and not hour_diff:
                            if not utils.update_instance_metadata(
                                UNUSED_EC2_INSTANCES_DYNAMO_DB_TABLE,
                                instance['AccountId'],
                                instance['Region'],
                                instance['InstanceId'],
                                created_by,
                                instance['CreatedAt'],
                                instance['StoppedAt'],
                                str(step),
                                current_datetime):
                                logger.error("Could not update metadata for instance %s", instance['InstanceId'])
                        if step == 2 and hour_diff >= 120:
                            if not utils.add_deletion_tag(instance['AccountId'], instance['Region'], instance['InstanceId']):
                                logger.error("Could not add [PENDING DELETION] tag to EC2 Instance %s", instance['InstanceId'])
                            if not utils.update_instance_metadata(
                                UNUSED_EC2_INSTANCES_DYNAMO_DB_TABLE,
                                instance['AccountId'],
                                instance['Region'],
                                instance['InstanceId'],
                                created_by,
                                instance['CreatedAt'],
                                instance['StoppedAt'],
                                str(step),
                                current_datetime):
                                logger.error("Could not update metadata for instance %s", instance['InstanceId'])
                        if step == 3 and hour_diff >= 312:
                            if not utils.update_instance_metadata(
                                UNUSED_EC2_INSTANCES_DYNAMO_DB_TABLE,
                                instance['AccountId'],
                                instance['Region'],
                                instance['InstanceId'],
                                created_by,
                                instance['CreatedAt'],
                                instance['StoppedAt'],
                                str(step),
                                current_datetime):
                                logger.error("Could not update metadata for instance %s", instance['InstanceId'])
                        if step == 4 and hour_diff >= 24:
                            ami_id = utils.create_instance_image(instance['AccountId'], instance['Region'], instance['InstanceId'], created_by)
                            if not ami_id:
                                raise Exception(f"Could not create AMI for EC2 Instance {instance['InstanceId']}")
                            if not utils.terminate_instance(instance['AccountId'], instance['Region'], instance['InstanceId']):
                                logger.error("Could not terminate EC2 Instance %s", instance['InstanceId'])
                            if not utils.cleanup_dynamodb(UNUSED_EC2_INSTANCES_DYNAMO_DB_TABLE, instance['AccountId'], 'instance_id', instance['InstanceId']):
                                logger.error("Could cleanup metadata for instance %s", instance['InstanceId'])
                            email_resources_block = [item for item in email_resources_block if not item.startswith(('<b>Instance ID','<b>Launched At'))]
                            email_resources_block.append(f"<b>AMI ID:</b> {ami_id}")
                        email_resources_block.append("<br>")

                        if NOTIFICATION_APP == 'slack':
                            alert_resources_block = [str(item).replace("<b>", "*").replace("</b>", "*").replace("<br>","") for item in email_resources_block]
                        elif NOTIFICATION_APP == 'msteams':
                            alert_resources_block = [str(item).replace("<b>", "**").replace("</b>", "**") for item in email_resources_block]
                        elif NOTIFICATION_APP == 'googlechat':
                            alert_resources_block = email_resources_block

                    if len(email_resources_block) > 0:
                        del email_resources_block[-1]

                        status, response = messenger.send_email(SENDER_EMAIL_ADDRESS, created_by, email_resources_block, old_notified_at, current_datetime, False, step)
                        if status:
                            logger.info(response)
                        else:
                            logger.error("%s: %s", response, json.dumps(instances))

                        status, response = messenger.send_alert(created_by, alert_resources_block, old_notified_at, current_datetime, False, step)
                        if status:
                            logger.info(response)
                        else:
                            logger.error("%s: %s", response, json.dumps(instances))

    if UNUSED_SECURITY_GROUPS_DYNAMODB_TABLE:
        unused_security_groups = defaultdict(lambda: defaultdict(list))
        scan_response = utils.scan_dynamodb(UNUSED_SECURITY_GROUPS_DYNAMODB_TABLE)
        if scan_response['Count'] > 0:
            for item in scan_response['Items']:
                if not utils.is_unused_security_group(item['account_id']['S'], item['region']['S'], item['security_group_id']['S']):
                    if not utils.cleanup_dynamodb(UNUSED_SECURITY_GROUPS_DYNAMODB_TABLE, item['account_id']['S'], 'security_group_id', item['security_group_id']['S']):
                        logger.error("Could not cleanup metadata for security group %s", item['security_group_id']['S'])
                else:
                    created_by = item['created_by']['S']
                    is_launch_wizard_group = json.loads(item['is_launch_wizard']['S'])

                    unused_security_groups[created_by][is_launch_wizard_group].append({
                        'SecurityGroupId': item['security_group_id']['S'],
                        'SecurityGroupName': item['security_group_name']['S'],
                        'AccountId': item['account_id']['S'],
                        'Region': item['region']['S'],
                        'CreatedAt': item['created_at']['S']
                    })
            for created_by, is_launch_wizard_group in unused_security_groups.items():
                for is_launch_wizard, security_groups in is_launch_wizard_group.items():
                    email_resources_block = []
                    alert_resources_block = []
                    old_notified_at = ''
                    current_datetime = utils.get_cst_cdt_datetime(datetime.datetime.now(datetime.timezone.utc))

                    for sg in security_groups:
                        messenger = Messenger(NOTIFICATION_APP, WEBHOOK_URLS, sg['AccountId'], sg['Region'], 'SecurityGroups', False)

                        is_deleted, reason = utils.delete_security_group(sg['AccountId'], sg['Region'], sg['SecurityGroupId'])
                        if not is_deleted:
                            logger.error("Could not delete Security Group=%s in AccountId=%s and Region=%s", sg['SecurityGroupId'], sg['AccountId'], sg['Region'])
                            if reason == 'DependencyViolation':
                                if not utils.cleanup_dynamodb(UNUSED_SECURITY_GROUPS_DYNAMODB_TABLE, sg['AccountId'], 'security_group_id', sg['SecurityGroupId']):
                                    logger.error("Could cleanup metadata for Security Group=%s", sg['SecurityGroupId'])
                        else:
                            if not utils.cleanup_dynamodb(UNUSED_SECURITY_GROUPS_DYNAMODB_TABLE, sg['AccountId'], 'security_group_id', sg['SecurityGroupId']):
                                logger.error("Could cleanup metadata for Security Group=%s", sg['SecurityGroupId'])
                            email_resources_block.append(f"<b>Security Group ID:</b> {sg['SecurityGroupId']}")
                            email_resources_block.append(f"<b>Security Group Name:</b> {sg['SecurityGroupName']}")
                            email_resources_block.append(f"<b>Account ID:</b> {sg['AccountId']}")
                            email_resources_block.append(f"<b>Region:</b> {sg['Region']}")
                            email_resources_block.append(f"<b>Created on:</b> {sg['CreatedAt']}")

                            email_resources_block.append("<br>")

                            if NOTIFICATION_APP == 'slack':
                                alert_resources_block = [str(item).replace("<b>", "*").replace("</b>", "*").replace("<br>","") for item in email_resources_block]
                            elif NOTIFICATION_APP == 'msteams':
                                alert_resources_block = [str(item).replace("<b>", "**").replace("</b>", "**") for item in email_resources_block]
                            elif NOTIFICATION_APP == 'googlechat':
                                alert_resources_block = email_resources_block

                    if len(email_resources_block) > 0:
                        del email_resources_block[-1]

                        status, response = messenger.send_email(SENDER_EMAIL_ADDRESS, created_by, email_resources_block, old_notified_at, current_datetime, is_launch_wizard, None)
                        if status:
                            logger.info(response)
                        else:
                            logger.error("%s: %s", response, json.dumps(security_groups))
                        status, response = messenger.send_alert(created_by, alert_resources_block, old_notified_at, current_datetime, is_launch_wizard, None)
                        if status:
                            logger.info(response)
                        else:
                            logger.error("%s: %s", response, json.dumps(security_groups))

    if UNUSED_EBS_VOLUMES_DYNAMODB_TABLE:
        unused_ebs_volumes = defaultdict(list)
        scan_response = utils.scan_dynamodb(UNUSED_EBS_VOLUMES_DYNAMODB_TABLE)
        if scan_response['Count'] > 0:
            for item in scan_response['Items']:
                if not utils.is_unused_ebs_volume(item['account_id']['S'], item['region']['S'], item['volume_id']['S']):
                    if not utils.cleanup_dynamodb(UNUSED_EBS_VOLUMES_DYNAMODB_TABLE, item['account_id']['S'], 'volume_id', item['volume_id']['S']):
                        logger.error("Could not cleanup metadata for EBS Volume %s", item['volume_id']['S'])
                else:
                    created_by = item['created_by']['S']

                    unused_ebs_volumes[created_by].append({
                        'VolumeId': item['volume_id']['S'],
                        'AccountId': item['account_id']['S'],
                        'Region': item['region']['S'],
                        'CreatedAt': item['created_at']['S']
                    })
            for created_by, volumes in unused_ebs_volumes.items():
                email_resources_block = []
                alert_resources_block = []
                old_notified_at = ''
                current_datetime = utils.get_cst_cdt_datetime(datetime.datetime.now(datetime.timezone.utc))

                for vol in volumes:
                    messenger = Messenger(NOTIFICATION_APP, WEBHOOK_URLS, vol['AccountId'], vol['Region'], 'EBSVolumes', False)

                    email_resources_block.append(f"<b>Volume ID:</b> {vol['VolumeId']}")
                    email_resources_block.append(f"<b>Account ID:</b> {vol['AccountId']}")
                    email_resources_block.append(f"<b>Region:</b> {vol['Region']}")
                    email_resources_block.append(f"<b>Created on:</b> {vol['CreatedAt']}")

                    email_resources_block.append("<br>")

                    if NOTIFICATION_APP == 'slack':
                        alert_resources_block = [str(item).replace("<b>", "*").replace("</b>", "*").replace("<br>","") for item in email_resources_block]
                    elif NOTIFICATION_APP == 'msteams':
                        alert_resources_block = [str(item).replace("<b>", "**").replace("</b>", "**").replace("<br>","\n\n") for item in email_resources_block]
                    elif NOTIFICATION_APP == 'googlechat':
                        alert_resources_block = email_resources_block

                if len(email_resources_block) > 0:
                    del email_resources_block[-1]
                    status, response = messenger.send_email(SENDER_EMAIL_ADDRESS, created_by, email_resources_block, old_notified_at, current_datetime, None, None)
                    if status:
                        logger.info(response)
                    else:
                        logger.error("%s: %s", response, json.dumps(volumes))
                    status, response = messenger.send_alert(created_by, alert_resources_block, old_notified_at, current_datetime, None, None)
                    if status:
                        logger.info(response)
                    else:
                        logger.error("%s: %s", response, json.dumps(volumes))
