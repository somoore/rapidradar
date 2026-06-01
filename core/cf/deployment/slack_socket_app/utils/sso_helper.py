"""Module for getting SSO-level details of AWS accounts"""
from os import getenv
from time import sleep
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.sts import AssumeRole
from utils.logger import LOGGER

SSO_CROSS_ACCOUNT_ROLE_ARN = getenv('SSO_CROSS_ACCOUNT_ROLE_ARN')
HOME_REGION = getenv('HOME_REGION')
MAX_RETRY_ATTEMPTS = 5
DELAY_SECONDS = 3
ORG_THROTTLE_PERIOD = 0.2

class SSOHelper:
    """SSOHelper Class used to get account details from management account"""
    def __init__(self):
        self.active_session = AssumeRole(SSO_CROSS_ACCOUNT_ROLE_ARN).assume_role(HOME_REGION)
        self.sso_admin_client = self.active_session.client(service_name='sso-admin', region_name=HOME_REGION)
        self.identity_store_client = self.active_session.client(service_name='identitystore', region_name=HOME_REGION)

    def get_children(self, client, child_type, ou_id, exclude_accounts):
        """Get all children of specified Organization Unit ID"""
        children = []
        retry_attempts = 0
        delay = DELAY_SECONDS
        base_kwargs, next_token = {'ParentId': ou_id, 'ChildType': child_type}, ''
        with ThreadPoolExecutor() as executor:
            futures = []
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
                                futures.append(executor.submit(self.get_children, client, 'ACCOUNT', child['Id'], exclude_accounts))
                                futures.append(executor.submit(self.get_children, client, 'ORGANIZATIONAL_UNIT', child['Id'], exclude_accounts))
                        next_token = response.get('NextToken')
                    break
                except client.exceptions.ClientError as error:
                    if retry_attempts < MAX_RETRY_ATTEMPTS:
                        retry_attempts += 1
                        LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                        sleep(delay)
                        delay *= 2
                        continue
                    raise error
            for future in as_completed(futures):
                children.extend(future.result())
        return children
    def get_active_child_accounts(self, deployment_targets: list, exclude_accounts: list = None) -> list:
        """Get all active child accounts in given Deployment Targets"""
        active_accounts = []
        active_accounts_details = []
        organizations = self.active_session.client(service_name='organizations')
        describe_method = getattr(organizations, 'describe_account')
        with ThreadPoolExecutor() as executor:
            future_to_target = {executor.submit(self.get_children, organizations, 'ACCOUNT', target, exclude_accounts): target for target in deployment_targets}
            future_to_target.update({executor.submit(self.get_children, organizations, 'ORGANIZATIONAL_UNIT', target, exclude_accounts): target for target in deployment_targets})
            for future in as_completed(future_to_target):
                active_accounts.extend(future.result())
        with ThreadPoolExecutor() as executor:
            future_to_account = {executor.submit(self.process_account_status, describe_method, account): account for account in active_accounts}
            for future in as_completed(future_to_account):
                result = future.result()
                if result:
                    active_accounts_details.append(result)
        return active_accounts_details
    def process_account_status(self, describe_method, account):
        """Only return Id of AWS account if its in ACTIVE state"""
        try:
            response = describe_method(AccountId=account)
            if 'Account' in response and response["Account"]["Status"] == "ACTIVE":
                return response["Account"]["Id"]
        except Exception as e:
            LOGGER.error("Error describing account %s: %s", account, str(e))
        return None
