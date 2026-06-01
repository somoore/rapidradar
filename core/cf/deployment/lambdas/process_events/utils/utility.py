from os import getenv
import re
from collections import defaultdict
import json
import logging
from time import sleep
import datetime
import base64
import hashlib
import http.client
import hmac
from dateutil import tz
import requests
from parliament import analyze_policy_string
import boto3
from utils.secretsmanager import GetConfig
from utils.sts import AssumeRole
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot
from pagerduty.main import PagerDuty

MANAGEMENT_ACCOUNT_ID = getenv('MANAGEMENT_ACCOUNT_ID')
AWS_ORG_NAME = getenv('AWS_ORG_NAME')
CROSS_ACCOUNT_ROLE = getenv('CROSS_ACCOUNT_ROLE')
SSO_CROSS_ACCOUNT_ROLE_ARN = getenv('SSO_CROSS_ACCOUNT_ROLE_ARN')
DEPLOYMENT_TARGET_ACCOUNTS_SECRET = getenv('DEPLOYMENT_TARGET_ACCOUNTS')
DEPLOYMENT_TARGET_ACCOUNTS = GetConfig(DEPLOYMENT_TARGET_ACCOUNTS_SECRET).values
MAX_RETRY_ATTEMPTS = 5
DELAY_SECONDS = 3
ORG_THROTTLE_PERIOD = 0.2
LOGGER = logging.getLogger(getenv('PROJECT_NAME'))
LOGGER.setLevel('INFO')

class AWSHelper:
    def __init__(self, event):
        self.iam_user, self.user_arn, self.user_ip_address, self.account_id, self.region, self.user_agent, self.is_invoked_by_service = self.__get_account_details(event)
        self.cross_account_role_arn = SSO_CROSS_ACCOUNT_ROLE_ARN if self.account_id == MANAGEMENT_ACCOUNT_ID else f"arn:aws:iam::{self.account_id}:role/{CROSS_ACCOUNT_ROLE}-{self.region}"

    def get_active_session(self):
        return AssumeRole(self.cross_account_role_arn).assume_role(self.region)

    def __get_account_details(self, event):
        iam_user, user_arn, user_ip_address, account_id, region, user_agent, is_invoked_by_service = '', None, None, None, None, '', None
        if 'recipientAccountId' in event:
            account_id = event['recipientAccountId']
        elif 'account' in event:
            account_id = event['account']
        elif 'accountId' in event:
            account_id = event['accountId']
        if 'region' in event:
            region = event['region']
        if 'detail' in event:
            detail = event['detail']
            if 'userIdentity' in detail:
                user_identity = detail['userIdentity']
                if 'arn' in user_identity:
                    user_arn = user_identity['arn']
                if 'principalId' in user_identity:
                    iam_user = user_identity['principalId'].split(':')[-1]
                if 'type' in user_identity:
                    if user_identity['type'] == 'IAMUser' and self.__is_access_key_id(iam_user):
                        iam_user = user_identity['userName']
                if 'invokedBy' in user_identity:
                    is_invoked_by_service = user_identity['invokedBy']
            if 'sourceIPAddress' in detail:
                user_ip_address = detail['sourceIPAddress']
            if 'userAgent' in detail:
                user_agent = detail['userAgent']
        return iam_user, user_arn, user_ip_address, account_id, region, user_agent, is_invoked_by_service

    @staticmethod
    def __is_access_key_id(iam_user):
        match = re.search(r'^[A-Z0-9]{20,25}$', iam_user)
        if match is not None:
            return True
        return False

    def get_account_name(self, account_id=None) -> str:
        if account_id is None:
            account_id = self.account_id
        return DEPLOYMENT_TARGET_ACCOUNTS[account_id]

    def get_cmdb_event_details(self):
        account_name = self.get_account_name()
        event_by = ''
        if '@' in self.iam_user:
            event_by = self.iam_user
        else:
            if 'terraform.io' in self.user_agent:
                event_by = "Terraform"
            elif 'AWS Internal' in self.user_agent:
                event_by = "AWS"
        return event_by, account_name

class Helper:
    def get_cst_cdt_date(self):
        utc_now = datetime.datetime.now(datetime.timezone.utc)
        cst_offset = datetime.timedelta(hours=-6)  # CST is UTC-6
        cdt_offset = datetime.timedelta(hours=-5)  # CDT is UTC-5
        is_dst = bool(utc_now.dst())
        if is_dst:
            cst_cdt_time = utc_now + cdt_offset
        else:
            cst_cdt_time = utc_now + cst_offset
        return cst_cdt_time.strftime('%b %d, %Y')

    def get_cst_datetime(self, date_time):
        utc_now = datetime.datetime.strptime(date_time, '%b %d, %Y %H:%M:%S %p')
        return utc_now.astimezone(tz.gettz('US/Central')).strftime('%b %d, %Y %H:%M:%S %p %Z')

    def is_base64_encoded(self, value):
        try:
            # Check if value can be base64 decoded
            decoded_bytes = base64.b64decode(value, validate=True)
            # Ensure that the value when encoded back matches the original
            re_encoded = base64.b64encode(decoded_bytes).decode('utf-8').strip()
            return value.strip() == re_encoded
        except Exception:
            return False

    def is_user_email(self, iam_user):
        match = re.search(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', iam_user)
        if match is not None:
            return True
        return False

    def is_attached_role_policy_overly_permissive(self, policy_arn:str):
        policy_name = policy_arn.partition(':policy/')[-1]
        if policy_name == 'AdministratorAccess':
            return True
        return False

    def is_role_policy_overly_permissive(self, policy_document):
        found_policy_over_permissive = False
        try:
            analysis = analyze_policy_string(policy_document)
            for result in analysis.findings:
                if result.issue == 'RESOURCE_STAR':
                    found_policy_over_permissive = True
        except Exception as error:
            LOGGER.error(str(error))
        return found_policy_over_permissive

    def format_ports_entry(self, port, protocol, user_ip_address):
        return json.dumps({
            "Port": port,
            "Protocol": protocol,
            "UserIpAddress": user_ip_address
        })

    def matches_given_ports(self, port, protocol, given_ports, is_ignore) -> bool:
        try:
            if port:
                for item in given_ports:
                    given_protocol, given_port = item.split("=")
                    given_port = int(given_port)
                    if isinstance(port, int):
                        if protocol == given_protocol and port == given_port:
                            return True
                    elif isinstance(port, str) and not is_ignore:
                        from_port, to_port = port.split('-')
                        if given_port in range(int(from_port), int(to_port) + 1):
                            return True
        except Exception as error:
            LOGGER.error(str(error))
        return False

    def is_all_traffic_port(self, port):
        if port in [-1, '-1']:
            return True
        return False

    def extract_ports_with_userip(self, port_details, scan_records):
        port_userip = {}
        try:
            if scan_records:
                for scan_port in scan_records[0]['port']['SS']:
                    scan_port = json.loads(scan_port)
                    if port_details['Port'] == scan_port['Port'] and port_details['Protocol'] == scan_port['Protocol']:
                        port_userip = scan_port
        except Exception as error:
            LOGGER.error(str(error))
        return port_userip

class AzureLogs:
    def __init__(self, customer_id, shared_key, json_data):
        self.customer_id = customer_id
        json_data['OrgName'] = AWS_ORG_NAME
        self.data = json.dumps(json_data)
        self.current_datetime = datetime.datetime.now(datetime.UTC).strftime('%a, %d %b %Y %H:%M:%S GMT')
        self.content_length = len(self.data)
        self.method = 'POST'
        self.content_type = 'application/json'
        self.resource = '/api/logs'
        self.signature = self.__build_signature(customer_id, shared_key, self.current_datetime, self.content_length, self.method, self.content_type, self.resource)

    @staticmethod
    def __build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
        x_headers = 'x-ms-date:' + date
        string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
        try:
            bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
            decoded_key = base64.b64decode(shared_key)
            encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
            authorization = f"SharedKey {customer_id}:{encoded_hash}"
        except Exception as error:
            LOGGER.error(str(error))
        return authorization

    def send_data_to_log_analytics(self, log_type):
        uri = self.customer_id + '.ods.opinsights.azure.com'
        status = False
        retry_attempts = 0
        delay = DELAY_SECONDS
        try:
            conn = http.client.HTTPSConnection(uri, timeout=10)
            headers = {
                'content-type': self.content_type,
                'Authorization': self.signature,
                'Log-Type': log_type,
                'x-ms-date': self.current_datetime
            }
            while retry_attempts < MAX_RETRY_ATTEMPTS:
                try:
                    conn.request(self.method, self.resource+'?api-version=2016-04-01', self.data, headers)
                    response = conn.getresponse()
                    if response.status >= 200 and response.status <= 299:
                        LOGGER.info("Data sent successfully")
                        status = True
                    else:
                        LOGGER.error("Response code: %s", response.status)
                        status = False
                    conn.close()
                    break
                except http.client.HTTPException as http_error:
                    LOGGER.error("HTTPException occurred: %s", str(http_error))
                    status = False
                    break
                except Exception as error:
                    if retry_attempts < MAX_RETRY_ATTEMPTS:
                        retry_attempts += 1
                        LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                        sleep(delay)
                        delay *= 2
                        continue
                    LOGGER.error(str(error))
                    status = False
                    break
        except Exception as error:
            LOGGER.error(str(error))
            status = False
        return status

class Tailscale:
    def __init__(self, tailnet_name, client_id, client_secret):
        self.tailnet_name = tailnet_name
        self.client_id = client_id
        self.client_secret = client_secret

    @staticmethod
    def __generate_api_key(client_id: str, client_secret: str):
        url = "https://api.tailscale.com/api/v2/oauth/token"
        data = {
            'client_id': client_id,
            'client_secret': client_secret
        }
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                response = requests.post(url, data=data, timeout=10)
                if response.status_code == 200:
                    LOGGER.info("Token generated successfully")
                    api_key = response.json()['access_token']
                    return api_key
                LOGGER.info("Attempt %s: Failed to generate API Key. StatusCode: %s, Response: %s", attempt, response.status_code, response.text)
                if attempt < max_attempts:
                    wait_time = 2 ** attempt
                    sleep(wait_time)
                else:
                    raise CustomException(f"API Key was not generated after {max_attempts} attempts.")
            except Exception as error:
                LOGGER.info("Attempt %s: Failed to generate API Key. Error: %s", attempt, str(error))
                if attempt < max_attempts:
                    wait_time = 2 ** attempt
                    sleep(wait_time)
                else:
                    raise CustomException(f"API Key was not generated after {max_attempts} attempts.") from error

    def get_tailscale_user_ips(self):
        ipv4_addr_regex_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        api_url = f'https://api.tailscale.com/api/v2/tailnet/{self.tailnet_name}/devices?fields=all'
        headers = {
            "Authorization": f"Bearer {self.__generate_api_key(self.client_id, self.client_secret)}",
        }
        users_tailscale_ips = defaultdict(list)
        try:
            response = requests.get(api_url, headers=headers, timeout=300)

            if response.status_code == 200:
                LOGGER.info("Response received from Tailscale API")
                devices = response.json()['devices']
                LOGGER.info("No. of machines found: %s", len(devices))
                for device in devices:
                    ip_address = ''
                    for addr in device['addresses']:
                        result = re.search(ipv4_addr_regex_pattern, addr)
                        if result:
                            ip_address = result.group(0)
                    users_tailscale_ips[device['user']].append(ip_address)
                return users_tailscale_ips
            raise CustomException(f"Failed to fetch machines. StatusCode: {response.status_code}, Response: {response.text}")
        except CustomException as error:
            raise error
        except Exception as error:
            raise error

class Alert:
    def __init__(self, pagerduty_helper: PagerDuty | None, incident_finding_types, is_pd_integration_type_restapi, is_scheduler: bool, messenger: EventAlert, send_logs_to_azure: bool, azure_data: dict, customer_id: str | None, shared_key: str | None, azure_log_type: str | None):
        self.pagerduty_helper = pagerduty_helper
        self.is_scheduler = is_scheduler
        self.incident_finding_types = incident_finding_types
        self.is_pd_integration_type_restapi = is_pd_integration_type_restapi
        self.messenger = messenger
        self.send_logs_to_azure = send_logs_to_azure
        self.azure_data = azure_data
        self.customer_id = customer_id
        self.shared_key = shared_key
        self.azure_log_type = azure_log_type

    def handler(self, alert_id: str | None, alert_args: dict, email_messenger: EmailAlert | None, slack_bot: SlackBot | None):
        try:
            incident_id, incident_number, incident_url, dedup_key = '', '', '', ''
            if alert_args['severity'] not in ['Informational'] and alert_id is not None:
                if self.pagerduty_helper is not None:
                    if alert_args['severity'] in self.incident_finding_types or 'ALL' in self.incident_finding_types:
                        incident_response = self.pagerduty_helper.create_incident(alert_id, alert_args)
                        if self.is_pd_integration_type_restapi:
                            incident_id, incident_number, incident_url = incident_response[0], incident_response[1], incident_response[2]
                        else:
                            dedup_key = incident_response
                if not self.is_scheduler:
                    alert_args['incident_number'] = incident_number
                    alert_args['incident_url'] = incident_url
            if alert_id is not None:
                print(alert_id, alert_args)
                status, reason = self.messenger.send_notification(alert_id, alert_args)
                LOGGER.info("Successfully sent alert message!")
                if not status and reason is not None:
                    raise Exception(str(reason))
                if email_messenger is not None:
                    email_messenger_method = getattr(email_messenger, alert_id)
                    status, reason = email_messenger_method(**alert_args)
                    LOGGER.info("Successfully sent email alert!")
                    if not status:
                        LOGGER.error(str(reason))
                if slack_bot is not None and slack_bot.slack_user_id:
                    slack_bot_method = getattr(slack_bot, alert_id)
                    status, reason = slack_bot_method(**alert_args)
                    LOGGER.info("Successfully sent bot message!")
                    if not status:
                        LOGGER.error(str(reason))
            if self.send_logs_to_azure:
                if incident_number:
                    self.azure_data['PagerDutyIncidentNumber'] = incident_number
                azure_logs = AzureLogs(self.customer_id, self.shared_key, self.azure_data)
                LOGGER.info("Successfully sent data to Azure Log Analytics for further analysis!")
                if not azure_logs.send_data_to_log_analytics(self.azure_log_type):
                    raise Exception(f"Data {self.azure_data} could not be sent to Azure Log Analytics")
            if self.is_pd_integration_type_restapi:
                return incident_id
            return dedup_key
        except Exception as error:
            raise error

class CustomException(Exception):
    """ Custom Exception class inherited from Exception class """
