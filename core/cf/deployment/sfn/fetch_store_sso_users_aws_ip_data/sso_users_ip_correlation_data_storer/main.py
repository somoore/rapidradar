from os import getenv
import json
import logging
import datetime
import boto3
logger = logging.getLogger()
logger.setLevel(logging.INFO)

TRACK_TAILSCALE_IPS = json.loads(getenv('TRACK_TAILSCALE_IPS'))
IP_CORRELATION_TABLE = getenv('IP_CORRELATION_TABLE')

def lambda_handler(event, context):
    logger.info("Storing data for SSO User %s", event['EmailAddress'])
    records = get_ip_data_by_user(IP_CORRELATION_TABLE, event['EmailAddress'])
    if len(records) > 0:
        if event['SourceIpAddress']:
            if not add_ip_correlation_data(IP_CORRELATION_TABLE, TRACK_TAILSCALE_IPS, event['EmailAddress'], event['UserId'], event['LastActivity'], event['SourceIpAddress'], records[0]['tailscale_user_ips']['SS'] if 'tailscale_user_ips' in records[0] and records[0]['tailscale_user_ips']['SS'] else []):
                logger.error("Could not update data for SSO User %s", event['EmailAddress'])
    else:
        if not add_ip_correlation_data(IP_CORRELATION_TABLE, TRACK_TAILSCALE_IPS, event['EmailAddress'], event['UserId'], event['LastActivity'], event['SourceIpAddress'], [""]):
            logger.error("Could not store data for SSO User %s", event['EmailAddress'])

def get_ip_data_by_user(table_name: str, user: str):
    dynamodb = boto3.client('dynamodb')
    try:
        response = dynamodb.query(
            TableName=table_name,
            IndexName='UserIndex',
            ExpressionAttributeNames={
                '#user': 'user'
            },
            ExpressionAttributeValues={
                ':user': {
                    'S': user,
                }
            },
            KeyConditionExpression='#user = :user',
        )
        if response['Count'] > 0:
            return response['Items']
    except Exception as error:
        logger.error(str(error))
    return []

def add_ip_correlation_data(table_name: str, track_tailscale_ips: bool, user: str, sso_user_id: str, login_date: str, ip_address: str, tailscale_user_ips: list) -> bool:
    dynamodb = boto3.client('dynamodb')
    try:
        db_items = {
            'user': {'S': user},
            'sso_user_id': {'S': sso_user_id},
            'updated_at': {'S': f'{datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}'},
            'last_login_date': {'S': login_date},
            'known_aws_ip': {'S': ip_address}
        }
        if track_tailscale_ips:
            db_items['tailscale_user_ips'] = {}
            db_items['tailscale_user_ips']['SS'] = tailscale_user_ips
        dynamodb.put_item(
            TableName=table_name,
            Item=db_items
        )
    except Exception as error:
        logger.error(str(error))
        return False
    return True
