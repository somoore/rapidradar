import copy
from utils.dynamodb import UsersIPData
from utils.sso_helper import SSOHelper
from utils.secretsmanager import GetConfig, Store
from utils.logger import LOGGER

def handle_event(event, deploy_ip_tracker_project, ip_correlation_table, ip_history_table, track_tailscale_ips, sso_user_id_names_secret):
    if 'errorCode' not in event:
        if 'requestParameters' in event and 'principalId' in event['userIdentity'] and 'accountId' in event['userIdentity']:
            sso_user_id = event['requestParameters']['userId']
            identity_store_id = event['requestParameters']['identityStoreId']
            sso_helper = SSOHelper()
            all_sso_users = sso_helper.get_all_sso_users_id_names(identity_store_id)
            if all_sso_users:
                update_sso_secret = False
                secret_sso_users = GetConfig(sso_user_id_names_secret).values
                secret_sso_user_ids = list(secret_sso_users.keys())
                current_sso_users = copy.copy(all_sso_users)
                current_sso_user_ids = list(current_sso_users.keys())
                if any(item not in current_sso_user_ids for item in secret_sso_user_ids) or any(item not in secret_sso_user_ids for item in current_sso_user_ids):
                    update_sso_secret = True
                if update_sso_secret:
                    if not Store(sso_user_id_names_secret, 'Secret for SSO Users IDs alongwith usernames', all_sso_users).store_value():
                        LOGGER.error("Could not store SSO Users' IDs alongwith their usernames to SecretsManager Secret")
            if deploy_ip_tracker_project:
                for table in [ip_correlation_table, ip_history_table]:
                    if not UsersIPData(table, track_tailscale_ips).delete(sso_user_id):
                        LOGGER.error("Could not delete data for SSO User %s from %s DynamoDB Table", sso_user_id, table)
