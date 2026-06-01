import copy
from utils.dynamodb import UsersIPData
from utils.secretsmanager import GetConfig, Store
from utils.sso_helper import SSOHelper
from utils.utility import Tailscale
from utils.logger import LOGGER

def handle_event(event, event_source, track_tailscale_ips, tailnet_name, tailscale_client_id, tailscale_client_secret, ip_correlation_table, ip_history_table, deploy_ip_tracker_project, sso_user_id_names_secret):
    if 'errorCode' not in event:
        if 'responseElements' in event and 'requestParameters' in event and 'principalId' in event['userIdentity'] and 'accountId' in event['userIdentity']:
            response_elements = event['responseElements']
            identity_store_id = event['requestParameters']['identityStoreId']
            sso_user_id = response_elements['user']['userId'] if event_source=='sso-directory.amazonaws.com' else response_elements['userId']
            sso_helper = SSOHelper()
            sso_user_email = sso_helper.get_sso_user_email(user_id=sso_user_id, identity_store_id=identity_store_id)
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
                if sso_user_email:
                    tailscale_user_ips = {}
                    if track_tailscale_ips:
                        tailscale_config = Tailscale(tailnet_name, tailscale_client_id, tailscale_client_secret)
                        tailscale_user_ips = tailscale_config.get_tailscale_user_ips()
                    tailscale_ip_addresses = tailscale_user_ips[sso_user_email] if tailscale_user_ips else []
                    if not UsersIPData(ip_correlation_table, track_tailscale_ips).store_ip_data(sso_user_email, sso_user_id, '', '', tailscale_ip_addresses if tailscale_ip_addresses else [""]):
                        LOGGER.error("Could not store data for SSO User %s with ID %s", sso_user_email, sso_user_id)
                    if not UsersIPData(ip_history_table, track_tailscale_ips).store_ip_history(sso_user_email, sso_user_id, [""]):
                        LOGGER.error("Could not store data for SSO User %s with ID %s", sso_user_email, sso_user_id)
                else:
                    LOGGER.info("Not storing data for SSO User %s to DynamoDB table because no email address is attached with it", sso_user_id)
