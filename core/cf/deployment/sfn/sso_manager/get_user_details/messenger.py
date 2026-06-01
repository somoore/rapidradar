import json
import requests
from httplib2 import Http
class CustomException(Exception):
    """ Custom Exception class inherited from Exception class """

class Messenger():
    def __init__(self, notification_app, webhooks):
        self.notification_app = notification_app
        self.webhooks = webhooks
        self.message_headers = {'Content-Type': 'application/json; charset=UTF-8'}

        if notification_app == "slack":
            self.send_alert = self.__send_slack_message
        elif notification_app == "msteams":
            self.send_alert = self.__send_msteams_message
        elif notification_app == "googlechat":
            self.send_alert = self.__send_googlechat_message
        else:
            raise ValueError("Invalid format, must be ['slack', 'msteams', 'googlechat']")

    def __send_slack_message(self, user: str, status: str) -> bool:
        http_obj = Http()
        message = {
            "blocks": [{
                "type": "context",
                "elements": [{
                        "type": "mrkdwn",
                        "text": f"""*AWS User ({user}) {status}*
AWS User {user} has been {status} from AWS IAM Identity Centre.
We are currently conducting an investigation to determine whether this user has any leftover resources in this AWS Organization. We will update you regarding this in 10-30 mins."""
                }]
            }]
        }
        try:
            for url in self.webhooks:
                if url.startswith("xoxb"):
                    oauth_token, channel_id = url.split(":")
                    message["channel"] = channel_id
                    message_headers = { 'Content-Type': 'application/json; charset=UTF-8', "Authorization": f"Bearer {oauth_token}"}
                    response = requests.post("https://slack.com/api/chat.postMessage", headers=message_headers, json=message, timeout=30)
                    print(response.json())
                    if not response.json().get("ok"):
                        print("Failed to send block message:", response.json().get("error"))
                else:
                    response = http_obj.request(uri=url, method='POST', headers=self.message_headers, body=json.dumps(message))
                    print(response)
        except Exception as error:
            print(f"[ERROR] {str(error)}")
            return False
        return True

    def __send_msteams_message(self, user: str, status: str) -> bool:
        http_obj = Http()
        message = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "title": f"AWS User ({user}) {status}",
            "summary": f"Alert for {status} user",
            "themeColor": "0072C6",
            "sections": [{
                "text": f"""AWS User {user} has been {status} from AWS IAM Identity Centre.\n\nWe are currently conducting an investigation to determine whether this user has any leftover resources in this AWS Organization. We will update you regarding this in 10-30 mins."""
            }]
        }
        try:
            for url in self.webhooks:
                http_obj.request(uri=url, method='POST', headers=self.message_headers, body=json.dumps(message))
        except Exception as error:
            print(f"[ERROR] {str(error)}")
            return False
        return True

    def __send_googlechat_message(self, user: str, status: str) -> bool:
        http_obj = Http()
        message = {
            "cards": [{
                "sections": [{
                    "widgets": [{
                        "textParagraph": {
                            "text": f"""<b>AWS User ({user}) {status}</b>
                            AWS User {user} has been {status} from AWS IAM Identity Centre.
                            We are currently conducting an investigation to determine whether this user has any leftover resources in this AWS Organization. We will update you regarding this in 10-30 mins."""
                        }
                    }]
                }]
            }]
        }
        try:
            for url in self.webhooks:
                http_obj.request(uri=url, method='POST', headers=self.message_headers, body=json.dumps(message))
        except Exception as error:
            print(f"[ERROR] {str(error)}")
            return False
        return True
