from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
from httplib2 import Http
import requests
import boto3
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

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

    def __send_slack_message(self, user: str, status: str, email_sent: bool) -> bool:
        http_obj = Http()
        message = {
            "blocks": [{
                "type": "context",
                "elements": [{
                        "type": "mrkdwn",
                        "text": f"""*AWS User ({user}) {status} [UPDATE]*
AWS User {user} was {status} awhile ago from AWS IAM Identity Centre.
{'Leftover resources were detected. A follow up email will be sent with a list of these resources.' if email_sent else 'Since no resources were found, follow up email will not be sent.'}
"""
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
    def __send_msteams_message(self, user: str, status: str, email_sent: bool) -> bool:
        http_obj = Http()
        message = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "title": f"AWS User ({user}) {status} [UPDATE]",
            "summary": f"Alert for {status} user",
            "themeColor": "0072C6",
            "sections": [{
                "text": f"""AWS User {user} was {status} awhile ago from AWS IAM Identity Centre.<br>
                {'Leftover resources were detected. A follow up email will be sent with a list of these resources.' if email_sent else 'Since no resources were found, follow up email will not be sent.'}"""
            }]
        }
        try:
            for url in self.webhooks:
                http_obj.request(uri=url, method='POST', headers=self.message_headers, body=json.dumps(message))
        except Exception as error:
            print(f"[ERROR] {str(error)}")
            return False
        return True
    def __send_googlechat_message(self, user: str, status: str, email_sent: bool) -> bool:
        http_obj = Http()
        message = {
            "cards": [{
                "sections": [{
                    "widgets": [{
                        "textParagraph": {
                            "text": f"""<b>AWS User ({user}) {status} [UPDATE]</b>
                            AWS User {user} was {status} awhile ago from AWS IAM Identity Centre.
                            {'Leftover resources were detected. A follow up email will be sent with a list of these resources.' if email_sent else 'Since no resources were found, follow up email will not be sent.'}"""
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
    def send_email(self, sender_email: str, receiver_email: str, user: str, status: str,filepath) -> bool:
        msg = MIMEMultipart('mixed')
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg_body = MIMEMultipart('alternative')

        email_subject = f"Resources Created by {status} AWS User ({user}) Found!"
        body_html = f"""Hello,<br>
        Our telemetry has found resources created by the {status} User {user}. Please find the attached report for a detailed list of these resources.<br><br>
        Thank you!"""

        file_data = ''
        with open(filepath, 'rb') as f:
            file_data = f.read()

        attachment = MIMEBase('application', 'octet-stream')
        attachment.set_payload(file_data)
        encoders.encode_base64(attachment)
        attachment.add_header('Content-Disposition', 'attachment', filename='resources-report.xlsx')
        msg.attach(attachment)
        try:
            ses = boto3.client('ses')
            msg['Subject'] = email_subject
            htmlpart = MIMEText(body_html.encode("utf-8"), 'html', "utf-8")
            msg_body.attach(htmlpart)
            msg.attach(msg_body)

            ses.send_raw_email(
                Source=sender_email,
                Destinations=[receiver_email],
                RawMessage={'Data':msg.as_string()}
            )
        except Exception as error:
            print(f"[ERROR] {str(error)}")
            return False
        return True
