from os import getenv
import logging
import datetime
import json
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

USERS_IP_HISTORY_TABLE = getenv('USERS_IP_HISTORY_TABLE')

def lambda_handler(event, context):
    logger.info("Storing data for SSO User %s", event['EmailAddress'])
    records = get_ip_data_by_user(USERS_IP_HISTORY_TABLE, event['EmailAddress'])
    if len(records) > 0:
        for record in records:
            ip_addresses = []
            for ip in record['ip_addresses']['SS']:
                if ip:
                    ip_data = json.loads(ip)
                    ip_addresses.append(ip_data['IpAddress'])
            if event['SourceIpAddress'] not in ip_addresses and event['SourceIpAddress']:
                record['ip_addresses']['SS'].append(json.dumps({'IpAddress': event['SourceIpAddress'], 'Timestamp': event['LastActivity']}))
                while("" in record['ip_addresses']['SS']):
                    record['ip_addresses']['SS'].remove("")
                if not add_user_ip_history_data(USERS_IP_HISTORY_TABLE, event['EmailAddress'], event['UserId'], record['ip_addresses']['SS']):
                    logger.error("Could not update data for SSO User %s", event['EmailAddress'])
    else:
        if not add_user_ip_history_data(USERS_IP_HISTORY_TABLE, event['EmailAddress'], event['UserId'], [""] if not event['SourceIpAddress'] else [ json.dumps({'IpAddress': event['SourceIpAddress'], 'Timestamp': event['LastActivity']}) ]):
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

def add_user_ip_history_data(table_name: str, user: str, sso_user_id: str, ip_addresses: list) -> bool:
    dynamodb = boto3.client('dynamodb')
    try:
        dynamodb.put_item(
            TableName=table_name,
            Item={
                'user': {'S': user},
                'sso_user_id': {'S': sso_user_id},
                'updated_at': {'S': f'{datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}'},
                'ip_addresses': {'SS': ip_addresses}
            }
        )
    except Exception as error:
        logger.error(str(error))
        return False
    return True
