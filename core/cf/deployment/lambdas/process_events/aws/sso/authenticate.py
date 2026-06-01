import datetime
import json
from utils.dynamodb import UsersIPData
from utils.sso_helper import SSOHelper
from utils.utility import Tailscale
from utils.logger import LOGGER

def handle_event(event, track_tailscale_ips, tailnet_name, tailscale_client_id, tailscale_client_secret, ip_correlation_table, users_ip_history_table):
    if 'errorCode' not in event and 'errorMessage' not in event:
        if 'userIdentity' in event and 'principalId' in event['userIdentity'] and 'userName' in event['userIdentity']:
            sso_user_id = event['userIdentity']['principalId']
            sso_username = event['userIdentity']['userName']
            identity_store_id = SSOHelper().get_identity_store_id()
            sso_user_email = SSOHelper().get_sso_user_email(user_id=sso_user_id, identity_store_id=identity_store_id)
            source_ip_address = event['sourceIPAddress']
            event_time = event['eventTime'].strftime("%Y-%m-%dT%H:%M:%S") if isinstance(event['eventTime'], datetime.datetime) else event['eventTime']
            if sso_user_email:
                records = UsersIPData(ip_correlation_table, track_tailscale_ips).get_ip_data_by_user(sso_user_email)
                if len(records) > 0:
                    for record in records:
                        if not UsersIPData(ip_correlation_table, track_tailscale_ips).store_ip_data(record['user']['S'], record['sso_user_id']['S'], event_time, source_ip_address, record['tailscale_user_ips']['SS'] if 'tailscale_user_ips' in record and record['tailscale_user_ips']['SS'] else []):
                            LOGGER.error("Could not update data for SSO User %s", record['user']['S'])
                else:
                    tailscale_user_ips = {}
                    if track_tailscale_ips:
                        tailscale_config = Tailscale(tailnet_name, tailscale_client_id, tailscale_client_secret)
                        tailscale_user_ips = tailscale_config.get_tailscale_user_ips()
                    if not UsersIPData(ip_correlation_table, track_tailscale_ips).store_ip_data(sso_user_email, sso_user_id, event_time, source_ip_address, tailscale_user_ips[sso_user_email] if tailscale_user_ips and tailscale_user_ips[sso_user_email] else [""]):
                        LOGGER.error("Could not store data for SSO User %s", sso_username)

                ip_history_records = UsersIPData(users_ip_history_table, track_tailscale_ips).get_ip_data_by_user(sso_user_email)
                if len(ip_history_records) > 0:
                    for record in ip_history_records:
                        ip_addresses = []
                        for ip in record['ip_addresses']['SS']:
                            if ip:
                                ip_data = json.loads(ip)
                                ip_addresses.append(ip_data['IpAddress'])
                        if source_ip_address not in ip_addresses:
                            record['ip_addresses']['SS'].append(json.dumps({'IpAddress': source_ip_address, 'Timestamp': event_time}))
                            while("" in record['ip_addresses']['SS']):
                                record['ip_addresses']['SS'].remove("")
                            if not UsersIPData(users_ip_history_table, track_tailscale_ips).store_ip_history(record['user']['S'], record['sso_user_id']['S'], record['ip_addresses']['SS']):
                                LOGGER.error("Could not update data for SSO User %s", sso_username)
                else:
                    if not UsersIPData(users_ip_history_table, track_tailscale_ips).store_ip_history(sso_user_email, sso_user_id, [""] if not source_ip_address else [ json.dumps({'IpAddress': source_ip_address, 'Timestamp': event_time}) ]):
                        LOGGER.error("Could not store data for SSO User %s", sso_user_email)
