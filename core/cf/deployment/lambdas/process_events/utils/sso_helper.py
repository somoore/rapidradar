from os import getenv
import logging
from time import sleep
from utils.sts import AssumeRole

SSO_CROSS_ACCOUNT_ROLE_ARN = getenv('SSO_CROSS_ACCOUNT_ROLE_ARN')
HOME_REGION = getenv('HOME_REGION')
MAX_RETRY_ATTEMPTS = 5
DELAY_SECONDS = 3
ORG_THROTTLE_PERIOD = 0.2
LOGGER = logging.getLogger(getenv('PROJECT_NAME'))
LOGGER.setLevel('INFO')

class SSOHelper:
    def __init__(self):
        self.active_session = AssumeRole(SSO_CROSS_ACCOUNT_ROLE_ARN).assume_role(HOME_REGION)
        self.sso_admin_client = self.active_session.client(service_name='sso-admin',region_name=HOME_REGION)
        self.identity_store_client = self.active_session.client(service_name='identitystore', region_name=HOME_REGION)

    def __get_all_permission_sets(self, instance_arn):
        permission_sets = []
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                next_token = ''
                base_kwargs = { "InstanceArn": instance_arn }
                while next_token is not None:
                    kwargs = base_kwargs.copy()
                    if next_token != '':
                        kwargs.update({'NextToken': next_token})
                    response = self.sso_admin_client.list_permission_sets(**kwargs)
                    permission_sets.extend(response['PermissionSets'])
                    next_token = response['NextToken'] if 'NextToken' in response else None
                break
            except self.sso_admin_client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return permission_sets

    def get_all_active_accounts(self):
        retry_attempts = 0
        delay = DELAY_SECONDS
        active_accounts_details = {}
        client = self.active_session.client(service_name='organizations')
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                paginator = client.get_paginator('list_accounts')
                for page in paginator.paginate():
                    for account in page['Accounts']:
                        if account['Status'] == 'ACTIVE':
                            active_accounts_details[account['Id']] = account['Name']
                    sleep(ORG_THROTTLE_PERIOD)
                break
            except client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    print(f"[INFO] {str(error)}. Retrying in {delay} seconds...")
                    sleep(delay)
                    delay *= 2
                    continue
                print(f"[ERROR {str(error)}]")
                break
        return active_accounts_details

    def get_children(self, client, child_type, ou_id, exclude_accounts):
        children = []
        retry_attempts = 0
        delay = DELAY_SECONDS
        base_kwargs, next_token = {'ParentId': ou_id, 'ChildType': child_type}, ''
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                while next_token is not None:
                    kwargs = base_kwargs.copy()
                    if next_token != '':
                        kwargs.update({'NextToken': next_token})
                    sleep(ORG_THROTTLE_PERIOD)
                    response = client.list_children(**kwargs)
                    for child in response['Children']:
                        if child_type == 'ACCOUNT':
                            if child['Id'] not in exclude_accounts:
                                children.append(child['Id'])
                        elif child_type == 'ORGANIZATIONAL_UNIT':
                            children.extend(self.get_children(client, 'ACCOUNT', child['Id'], exclude_accounts))
                            children.extend(self.get_children(client, 'ORGANIZATIONAL_UNIT', child['Id'], exclude_accounts))
                    next_token = response['NextToken'] if 'NextToken' in response else None
                break
            except client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                raise error
        return children

    def get_active_child_accounts(self, deployment_targets: list, exclude_accounts: list = None) -> list:
        active_accounts = []
        active_accounts_details = []
        retry_attempts = 0
        delay = DELAY_SECONDS
        organizations = self.active_session.client(service_name='organizations')
        describe_method=getattr(organizations, 'describe_account')
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                for target in deployment_targets:
                    active_accounts.extend(self.get_children(organizations, 'ACCOUNT', target, exclude_accounts))
                    active_accounts.extend(self.get_children(organizations, 'ORGANIZATIONAL_UNIT', target, exclude_accounts))
                for account in active_accounts:
                    response = describe_method(AccountId=account)
                    if 'Account' in response:
                        if response["Account"]["Status"] == "ACTIVE":
                            active_accounts_details.append(response["Account"]["Id"])
                    sleep(ORG_THROTTLE_PERIOD)
                break
            except organizations.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                raise error
        return active_accounts_details

    def found_admin_suppression_tag(self, user_arn, admin_alert_suppression_tag_key, admin_alert_suppression_tag_value):
        found_suppression_tag = False
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                user_permission_set = ''
                if '_' in user_arn:
                    user_permission_set = (user_arn.split('/')[-2]).split("_")[-2]
                if user_permission_set:
                    instance_arn = self.sso_admin_client.list_instances()['Instances'][0]['InstanceArn']
                    permission_sets_list = self.__get_all_permission_sets(instance_arn)
                    user_permission_set_arn = ''
                    for permission_set in permission_sets_list:
                        response = self.sso_admin_client.describe_permission_set(
                            InstanceArn=instance_arn,
                            PermissionSetArn=permission_set
                        )['PermissionSet']['Name']
                        if response == user_permission_set:
                            user_permission_set_arn = permission_set
                            break
                    tags_list = self.sso_admin_client.list_tags_for_resource(
                        InstanceArn=instance_arn,
                        ResourceArn=user_permission_set_arn
                    )['Tags']
                    for tag in tags_list:
                        if tag['Key'] == admin_alert_suppression_tag_key and tag['Value'] == admin_alert_suppression_tag_value:
                            found_suppression_tag = True
                break
            except self.sso_admin_client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                raise error
        return found_suppression_tag

    def get_identity_store_id(self):
        identity_store_id = ''
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                sso_instance = self.sso_admin_client.list_instances()['Instances'][0]
                identity_store_id = sso_instance['IdentityStoreId']
                return identity_store_id
            except self.sso_admin_client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                raise error

    def get_sso_user_email(self, iam_user=None, user_id=None, identity_store_id=None):
        sso_user_email = ''
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                if not identity_store_id or identity_store_id is None:
                    identity_store_id = self.get_identity_store_id()
                response = {}
                if user_id:
                    response = self.identity_store_client.describe_user(
                        IdentityStoreId=identity_store_id,
                        UserId=user_id
                    )
                if iam_user:
                    response = self.identity_store_client.list_users(
                        IdentityStoreId=identity_store_id,
                        Filters=[{
                            'AttributePath': 'UserName',
                            'AttributeValue': f'{iam_user}'
                        }]
                    )
                    response = response['Users'][0] if 'Users' in response and len(response['Users']) > 0 else {}
                if 'Emails' in response:
                    if len(response['Emails']) > 1:
                        for email in response['Emails']:
                            if 'Primary' in email and email['Primary']:
                                sso_user_email = email['Value']
                    else:
                        sso_user_email = response['Emails'][0]['Value']
                break
            except self.identity_store_client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return sso_user_email

    def get_all_sso_users_id_names(self, identity_store_id: str):
        sso_users = {}
        next_token = ''
        base_kwargs = {'IdentityStoreId': identity_store_id}
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                while next_token is not None:
                    kwargs = base_kwargs.copy()
                    if next_token != '':
                        kwargs.update({'NextToken': next_token})
                    response = self.identity_store_client.list_users(**kwargs)
                    for user in response['Users']:
                        username = user['UserName']
                        user_id = user['UserId']
                        sso_users[user_id] = username
                    next_token = response['NextToken'] if 'NextToken' in response else None
                return sso_users
            except self.identity_store_client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                return {}
