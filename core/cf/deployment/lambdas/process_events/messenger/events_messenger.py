import json
from os import getenv
from httplib2 import Http
import requests
from utils.secretsmanager import GetConfig
from messenger.channels import google_chat, slack, ms_teams

AWS_ORG_NAME = getenv('AWS_ORG_NAME')
SSO_CROSS_ACCOUNT_ROLE_ARN = getenv('SSO_CROSS_ACCOUNT_ROLE_ARN')
DEPLOYMENT_TARGET_ACCOUNTS_SECRET = getenv('DEPLOYMENT_TARGET_ACCOUNTS')
DEPLOYMENT_TARGET_ACCOUNTS = GetConfig(DEPLOYMENT_TARGET_ACCOUNTS_SECRET).values

class CustomException(Exception):
    """ Custom Exception class inherited from Exception class """

class EventAlert:
    def __init__(self, notification_app, account_id, region, webhook_urls):
        self.notification_app = notification_app
        self.account_id = account_id
        self.region = region
        self.account_name = self.__get_account_name(self.account_id)
        self.org_name = AWS_ORG_NAME
        self.webhook_urls = webhook_urls

    def send_notification(self, alert_id, message_params: dict):
        message_headers = {'Content-Type': 'application/json; charset=UTF-8'}
        http_obj = Http()
        if self.notification_app == "googlechat":
            messenger = google_chat.GoogleChatMessenger(self.account_id, self.account_name, self.org_name, self.region)
        elif self.notification_app == "slack":
            messenger = slack.SlackMessenger(self.account_id, self.account_name, self.org_name, self.region)
        elif self.notification_app == "msteams":
            messenger = ms_teams.MSTeamsMessenger(self.account_id, self.account_name, self.org_name, self.region)
        else:
            raise ValueError("Invalid format, must be ['slack', 'msteams', 'googlechat']")
        try:
            for url in self.webhook_urls:
                message_params_copy = message_params.copy()
                if self.notification_app == "slack" and url.startswith("xoxb"):
                    message_params_copy["slack_token"] = f"{url.split(':')[0]}"
                message = messenger.get_message(alert_id, message_params_copy)
                if message:
                    if self.notification_app == "slack" and url.startswith("xoxb"):
                        oauth_token, channel_id = url.split(":")
                        message["channel"] = channel_id
                        message_headers = { 'Content-Type': 'application/json; charset=UTF-8', "Authorization": f"Bearer {oauth_token}"}
                        response = requests.post("https://slack.com/api/chat.postMessage", headers=message_headers, json=message, timeout=30)
                        print(response.json())
                        if not response.json().get("ok"):
                            print("Failed to send block message:", response.json().get("error"))
                    else:
                        response = http_obj.request(uri=url, method='POST', headers=message_headers, body=json.dumps(message))
                        print(response)
                else:
                    raise CustomException("Message was not generated")
        except CustomException as error:
            return False, f"{str(error)}"
        except Exception as error:
            return False, f"Could not send alert: {str(error)}"
        return True, "Alert sent successfully"

    @staticmethod
    def __get_account_name(account_id):
        return DEPLOYMENT_TARGET_ACCOUNTS[account_id]
