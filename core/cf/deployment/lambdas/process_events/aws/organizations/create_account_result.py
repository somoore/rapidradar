from os import getenv
from utils.secretsmanager import Store
from utils.ssm import SSM
from utils.sso_helper import SSOHelper
from utils.utility import AWSHelper
from utils.logger import LOGGER

DEPLOYMENT_TARGET_ACCOUNTS_SECRET = getenv('DEPLOYMENT_TARGET_ACCOUNTS')

def handle_event(event, helper: AWSHelper, active_regions, enable_ec2_instance_configurator, deployment_targets, exclude_accounts, ssm_document_name):
    if 'errorCode' not in event and 'errorMessage' not in event:
        if 'serviceEventDetails' in event and 'createAccountStatus' in event['serviceEventDetails']:
            account_status_details = event['serviceEventDetails']['createAccountStatus']
            if account_status_details['state'] == 'SUCCEEDED':
                new_account_id = account_status_details['accountId']
                LOGGER.info("Account Creation Succeeded. New Account ID is %s", new_account_id)
                sso_helper = SSOHelper()
                active_accounts = sso_helper.get_active_child_accounts(deployment_targets, exclude_accounts)
                if new_account_id not in active_accounts:
                    active_accounts.append(new_account_id)

                    all_active_accounts = sso_helper.get_all_active_accounts()
                    if not Store(DEPLOYMENT_TARGET_ACCOUNTS_SECRET, 'Secret to store Account Names against active AWS Account IDs in Deployment Targets', all_active_accounts).store_value():
                        LOGGER.error("Could not store updated list of accounts with their names to SecretsManager: %s", all_active_accounts)

                if enable_ec2_instance_configurator:
                    for aws_region in active_regions:
                        active_session = helper.get_active_session()
                        ssm_utils = SSM(active_session, aws_region)
                        if not ssm_utils.share_ssm_document_w_all_accounts(aws_region, ssm_document_name, active_accounts):
                            LOGGER.error("Could not share SSM Document named %s with active AWS accounts", ssm_document_name)
            else:
                LOGGER.info("Account Creation State: %s", account_status_details['state'])
    else:
        LOGGER.info("Account Creation failed for some reason")
