from os import getenv
import logging
import json
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

PROJECT_NAME = getenv('PROJECT_NAME')
SSO_CROSS_ACCOUNT_ROLE_ARN = getenv('SSO_CROSS_ACCOUNT_ROLE_ARN')
DATA_BUCKET = getenv('DATA_BUCKET')

def lambda_handler(event, context):
    logger.info('PROCESSING NEW EVENT: %s', event)
    sso_users = []
    file_name = "sso_users_data.json"
    if 'TriggerType' in event and event['TriggerType'] in ['Custom']:
        trigger_type = event['TriggerType']
        active_session = __assume_role(SSO_CROSS_ACCOUNT_ROLE_ARN)
        identity_store_id = __get_identity_store_id(active_session)
        identity_store = active_session.client(service_name='identitystore',region_name='us-east-1')
        next_token = ''
        base_kwargs = {
            'IdentityStoreId': identity_store_id
        }
        try:
            while next_token is not None:
                kwargs = base_kwargs.copy()
                if next_token != '':
                    kwargs.update({'NextToken': next_token})
                response = identity_store.list_users(**kwargs)
                for user in response['Users']:
                    username = user['UserName']
                    user_id = user['UserId']
                    email_address = ''
                    if 'Emails' in user:
                        if len(user['Emails']) > 1:
                            for email in user['Emails']:
                                if 'Primary' in email and email['Primary']:
                                    email_address = email['Value']
                        else:
                            email_address = user['Emails'][0]['Value']
                    if email_address:
                        sso_users.append({'TriggerType': trigger_type, 'UserName': username, 'UserId': user_id, 'EmailAddress': email_address})
                next_token = response['NextToken'] if 'NextToken' in response else None
            file_path = f"/tmp/{file_name}"
            with open(file_path, "w") as file:
                file.write(json.dumps(sso_users, indent=4))
            s3_res = boto3.resource('s3')
            s3_res.meta.client.upload_file(file_path, DATA_BUCKET, f'{file_name}')
        except Exception as error:
            raise error
    return {
        'BucketName': DATA_BUCKET,
        'BucketKey': file_name
    }

def __assume_role(arn):
    sts = boto3.client('sts', region_name='us-east-1')
    response = sts.assume_role(RoleArn=arn, RoleSessionName=PROJECT_NAME)
    session = boto3.Session(aws_access_key_id=response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                    aws_session_token=response['Credentials']['SessionToken'])
    return session

def __get_identity_store_id(active_session: boto3.Session):
    sso_admin = active_session.client(service_name='sso-admin', region_name='us-east-1')
    identity_store_id = ''
    try:
        sso_instance = sso_admin.list_instances()['Instances'][0]
        identity_store_id = sso_instance['IdentityStoreId']
    except Exception as error:
        raise error
    return identity_store_id
