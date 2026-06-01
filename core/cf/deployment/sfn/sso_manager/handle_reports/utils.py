import os
import json
import boto3

def get_secret_value(name: str) -> str:
    client = boto3.client('secretsmanager')
    try:
        response = client.get_secret_value(SecretId=name)
        return json.loads(response["SecretString"])
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return ''

def put_object(file_path, bucket_name, object_key) -> bool:
    s3_res = boto3.resource('s3')
    try:
        s3_res.meta.client.upload_file(file_path, bucket_name, object_key)
    except Exception as error:
        print(f"[ERROR] Could not upload CSV to S3 Bucket: {str(error)}")
        return False
    return True

def get_s3_files(bucket_name, process_id, user_id) -> str:
    s3 = boto3.client('s3')
    next_token = ''
    base_kwargs = {
        'Bucket': bucket_name,
        'Prefix': f'{process_id}/{user_id}',
    }
    keys = []
    folders = []
    try:
        while next_token is not None:
            kwargs = base_kwargs.copy()
            if next_token != '':
                kwargs.update({'ContinuationToken': next_token})
            results = s3.list_objects_v2(**kwargs)
            if 'Contents' in results:
                contents = results['Contents']
                for i in contents:
                    k = i['Key']
                    if k[-1] != '/':
                        keys.append(k)
                    else:
                        folders.append(k)
                if 'NextContinuationToken' in results:
                    next_token = results['NextContinuationToken']
                else:
                    next_token = None
            else:
                next_token = None
        for folder in folders:
            dest_pathname = os.path.join('/tmp/', folder)
            if not os.path.exists(os.path.dirname(dest_pathname)):
                os.makedirs(os.path.dirname(dest_pathname))
        for obj in keys:
            dest_pathname = os.path.join('/tmp/', obj)
            if not os.path.exists(os.path.dirname(dest_pathname)):
                os.makedirs(os.path.dirname(dest_pathname))
            s3.download_file(bucket_name, obj, dest_pathname)
    except Exception as error:
        print(f"[ERROR] {str(error)}")
        return False, keys
    return True, keys

def __assume_role(project_name, region, role_arn):
    sts = boto3.client('sts', region_name=region)
    response = sts.assume_role(RoleArn=role_arn, RoleSessionName=project_name)
    session = boto3.Session(aws_access_key_id=response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                    aws_session_token=response['Credentials']['SessionToken'])
    return session

def __get_identity_store_id(active_session):
    identity_store_id = ''
    try:
        sso_admin_client = active_session.client(service_name='sso-admin',region_name='us-east-1')
        sso_instance = sso_admin_client.list_instances()['Instances'][0]
        identity_store_id = sso_instance['IdentityStoreId']
    except Exception as error:
        raise error
    return identity_store_id

def get_all_sso_users_id_names(project_name, sso_role_arn):
    active_session = __assume_role(project_name, 'us-east-1', sso_role_arn)
    identity_store_client = active_session.client(service_name='identitystore', region_name='us-east-1')
    sso_users = {}
    next_token = ''
    base_kwargs = {'IdentityStoreId': __get_identity_store_id(active_session)}
    try:
        while next_token is not None:
            kwargs = base_kwargs.copy()
            if next_token != '':
                kwargs.update({'NextToken': next_token})
            response = identity_store_client.list_users(**kwargs)
            for user in response['Users']:
                username = user['UserName']
                user_id = user['UserId']
                sso_users[user_id] = username
            next_token = response['NextToken'] if 'NextToken' in response else None
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return sso_users

def store_all_sso_users_id_names(secret_name: str, data: str):
    secretsmanager = boto3.client('secretsmanager')
    try:
        secretsmanager.put_secret_value(
            Name=secret_name,
            SecretString=json.dumps(data)
        )
        return True
    except secretsmanager.exceptions.ResourceNotFoundException:
        secretsmanager.create_secret(
            Name=secret_name,
            Description='Secret for SSO Users IDs alongwith usernames',
            SecretString=json.dumps(data)
        )
        return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
        return False
