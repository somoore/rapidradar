"""
The purpose of this Lambda code is to send daily Security Summary via Email and App WebHook URL
"""
from os import getenv
import json
import datetime
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import boto3
import requests
from httplib2 import Http
from alert_notification_messages import daily_alert

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_secret_value(name: str) -> str:
    client = boto3.client('secretsmanager')
    try:
        response = client.get_secret_value(SecretId=name)
        return json.loads(response["SecretString"])
    except Exception as error:
        logger.error(str(error))
    return ''

REMEDIATED_RESOURCES_TABLE = getenv('REMEDIATED_RESOURCES_TABLE')
SECURITY_GROUPS_TABLE = getenv('SECURITY_GROUPS_TABLE')
IAM_TABLE = getenv('IAM_TABLE')
S3_BUCKETS_TABLE = getenv('S3_BUCKETS_TABLE')
ROOT_IAM_LOGINS_TABLE = getenv('ROOT_IAM_LOGINS_TABLE')
SENDER_EMAIL_ADDRESS = getenv('SENDER_EMAIL_ADDRESS')
RECEIVER_EMAIL_ADDRESSES = getenv('RECEIVER_EMAIL_ADDRESSES').replace(' ', '').split(',')
NOTIFICATION_CONFIGS_SECRET_NAME = getenv('NOTIFICATION_CONFIGS_SECRET_NAME')
NOTIFICATION_CONFIGS = get_secret_value(NOTIFICATION_CONFIGS_SECRET_NAME)
NOTIFICATION_APP = NOTIFICATION_CONFIGS.get('NOTIFICATION_APP', '')
WEBHOOK_URLS = ""
if "APP_CONFIG" in NOTIFICATION_CONFIGS:
    WEBHOOK_URLS = NOTIFICATION_CONFIGS.get("APP_CONFIG")
else:
    WEBHOOK_URLS = NOTIFICATION_CONFIGS.get("WEBHOOK_URL")
WEBHOOK_URLS = WEBHOOK_URLS.replace(' ', '').split(',')

class CustomException(Exception):
    """ Custom Exception class inherited from Exception class """

def lambda_handler(event, context):
    ses = boto3.client('ses')

    remediated_resources_data = []
    remediated_resources_table = []
    found_24hr_data = False
    scan_response = scan_dynamodb(REMEDIATED_RESOURCES_TABLE)
    if scan_response['Count'] > 0:
        remediated_resources_table.append('<p style="font-size: 22px;"><b>Remediated Resources (in last 24hrs)</b></p>')
        remediated_resources_table.append('<table border="1">')
        remediated_resources_table.append('<tr>')
        header = ['Resource Type', 'Resource ID', 'Account ID', 'Region', 'Remediated At']
        for label in header:
            remediated_resources_table.append(f'<th style="padding:5px">{label}</th>')
        remediated_resources_table.append('</tr>')
        iter = 1
        card_iter = 0
        for item in scan_response['Items']:
            difference = datetime.datetime.now(datetime.UTC) - datetime.datetime.strptime(item['remediated_at']['S'],"%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.UTC)
            if difference.days == 0:
                found_24hr_data = True
                remediated_resources_table.append('<tr>')
                remediated_resources_table.append(f"<td style='padding:5px'>{item['resource_type']['S']}</td>")
                remediated_resources_table.append(f"<td style='padding:5px'>{item['resource_id']['S']}</td>")
                remediated_resources_table.append(f"<td style='padding:5px'>{int(item['account_id']['S'])}</td>")
                remediated_resources_table.append(f"<td style='padding:5px'>{item['region']['S']}</td>")
                remediated_resources_table.append(f"<td style='padding:5px'>{item['remediated_at']['S']}</td>")
                remediated_resources_table.append('</tr>')

                if NOTIFICATION_APP == 'googlechat':
                    remediated_resources_widget = {}
                    remediated_resources_widget["textParagraph"] = {}
                    remediated_resources_widget["textParagraph"]["text"] = f"<b>{item['resource_type']['S']}</b><br>"
                    remediated_resources_widget["textParagraph"]["text"] += f"<font color=\"#868686\"><b>Resource ID:</b> {item['resource_id']['S']}</font><br>"
                    remediated_resources_widget["textParagraph"]["text"] += f"<font color=\"#868686\"><b>Account ID:</b> {int(item['account_id']['S'])}</font><br>"
                    remediated_resources_widget["textParagraph"]["text"] += f"<font color=\"#868686\"><b>Region:</b> {item['region']['S']}</font><br>"
                    remediated_resources_widget["textParagraph"]["text"] += f"<font color=\"#868686\"><b>Remediated At:</b> {item['remediated_at']['S']}</font><br>"
                    remediated_resources_data.append(remediated_resources_widget)
                    iter = iter + 1
                    card_iter = card_iter + 1
                    if card_iter != len(scan_response['Items']):
                        remediated_resources_data.append(get_divider(NOTIFICATION_APP))
                elif NOTIFICATION_APP == 'slack':
                    remediated_resources_widget = {}
                    remediated_resources_widget["type"] = "context"
                    remediated_resources_widget["elements"] = []
                    remediated_resources_widget["elements"].append({})
                    remediated_resources_widget["elements"][0]["type"] = "mrkdwn"
                    remediated_resources_widget["elements"][0]["text"] = f"*{item['resource_type']['S']}*\n"
                    remediated_resources_widget["elements"][0]["text"] += f"*Resource ID:* {item['resource_id']['S']}\n"
                    remediated_resources_widget["elements"][0]["text"] += f"*Account ID:* {item['account_id']['S']}\n"
                    remediated_resources_widget["elements"][0]["text"] += f"*Region:* {item['region']['S']}\n"
                    remediated_resources_widget["elements"][0]["text"] += f"*Remediated At:* {item['remediated_at']['S']}\n"
                    remediated_resources_data.append(remediated_resources_widget)

                    card_iter = card_iter + 1
                    if card_iter != len(scan_response['Items']):
                        remediated_resources_data.append(get_divider(NOTIFICATION_APP))
                elif NOTIFICATION_APP == 'msteams':
                    remediated_resources_data.append('<tr>')
                    remediated_resources_data.append(f"<td style='padding:5px'>{item['resource_type']['S']}</td>")
                    remediated_resources_data.append(f"<td style='padding:5px'>{item['resource_id']['S']}</td>")
                    remediated_resources_data.append(f"<td style='padding:5px'>{int(item['account_id']['S'])}</td>")
                    remediated_resources_data.append(f"<td style='padding:5px'>{item['region']['S']}</td>")
                    remediated_resources_data.append(f"<td style='padding:5px'>{item['remediated_at']['S']}</td>")
                    remediated_resources_data.append('</tr>')
        remediated_resources_table.append('</table>')
    if not found_24hr_data:
        remediated_resources_table = remediated_resources_table[:1]
    remediated_resources_table = '\n'.join([str(elem) for elem in remediated_resources_table])

    sg_resources_data = []
    sg_table = []
    scan_sg_dynamodb_response = scan_dynamodb(SECURITY_GROUPS_TABLE)
    if scan_sg_dynamodb_response['Count'] > 0:
        headers_sg = ['Security Group ID', 'Account ID', 'Region', 'Attached', 'Open To', 'Ports', 'Notifications Suppressed']
        sg_table.append('<p style="font-size: 16px;"><b>Security Groups with Open Ports</b></p>')
        sg_table.append('<table border="1">')
        sg_table.append('<tr>')
        for label in headers_sg:
            sg_table.append(f'<th style="padding:5px">{label}</th>')
        sg_table.append('</tr>')
        iter = 1
        for item in scan_sg_dynamodb_response['Items']:
            sg_table.append('<tr>')
            sg_table.append(f"<td style='padding:5px'>{item['security_group_id']['S']}</td>")
            sg_table.append(f"<td style='padding:5px'>{int(item['account_id']['S'])}</td>")
            sg_table.append(f"<td style='padding:5px'>{item['region']['S']}</td>")
            sg_table.append(f"<td style='padding:5px'>{item['attached']['S']}</td>")
            sg_table.append(f"<td style='padding:5px'>{item['open_to']['S']}</td>")
            sg_table.append(f"<td style='padding:5px'>{str(get_ints(scan_sg_dynamodb_response['Items'][0]['port']['SS']))}</td>")
            sg_table.append(f"<td style='padding:5px'>{item['notifications_suppressed']['S']}</td>")
            sg_table.append('</tr>')

            if NOTIFICATION_APP == 'googlechat':
                sg_resources_data.append(get_divider(NOTIFICATION_APP))
                sg_widget = {}
                sg_widget["textParagraph"] = {}
                sg_widget["textParagraph"]["text"] = f"<b>{item['security_group_id']['S']}</b><br>"
                sg_widget["textParagraph"]["text"] += f"<font color=\"#868686\"><b>Account ID:</b> {int(item['account_id']['S'])}</font><br>"
                sg_widget["textParagraph"]["text"] += f"<font color=\"#868686\"><b>Region:</b> {item['region']['S']}</font><br>"
                sg_widget["textParagraph"]["text"] += f"<font color=\"#868686\"><b>Attached:</b> {item['attached']['S']}</font><br>"
                sg_widget["textParagraph"]["text"] += f"<font color=\"#868686\"><b>Open To:</b> {item['open_to']['S']}</font><br>"
                sg_widget["textParagraph"]["text"] += f"<font color=\"#868686\"><b>Ports:</b> {str(get_ints(scan_sg_dynamodb_response['Items'][0]['port']['SS']))}</font><br>"
                sg_widget["textParagraph"]["text"] += f"<font color=\"#868686\"><b>Notifications Suppressed:</b> {item['notifications_suppressed']['S']}</font><br>"
                sg_resources_data.append(sg_widget)
                iter = iter + 1
            elif NOTIFICATION_APP == 'slack':
                sg_widget = {}
                sg_widget["type"] = "context"
                sg_widget["elements"] = []
                sg_widget["elements"].append({})
                sg_widget["elements"][0]["type"] = "mrkdwn"
                sg_widget["elements"][0]["text"] = f"*{item['security_group_id']['S']}*\n"
                sg_widget["elements"][0]["text"] += f"*Account ID:* {item['account_id']['S']}\n"
                sg_widget["elements"][0]["text"] += f"*Region:* {item['region']['S']}\n"
                sg_widget["elements"][0]["text"] += f"*Attached:* {item['attached']['S']}\n"
                sg_widget["elements"][0]["text"] += f"*Open To:* {item['open_to']['S']}\n"
                sg_widget["elements"][0]["text"] += f"*Ports:* {str(get_ints(scan_sg_dynamodb_response['Items'][0]['port']['SS']))}\n"
                sg_widget["elements"][0]["text"] += f"*Notifications Suppressed:* {item['notifications_suppressed']['S']}\n"
                sg_resources_data.append(sg_widget)

                card_iter = card_iter + 1
                if card_iter != len(scan_response['Items']):
                    sg_resources_data.append(get_divider(NOTIFICATION_APP))
            elif NOTIFICATION_APP == 'msteams':
                sg_resources_data.append('<tr>')
                sg_resources_data.append(f"<td style='padding:5px'>{item['security_group_id']['S']}</td>")
                sg_resources_data.append(f"<td style='padding:5px'>{int(item['account_id']['S'])}</td>")
                sg_resources_data.append(f"<td style='padding:5px'>{item['region']['S']}</td>")
                sg_resources_data.append(f"<td style='padding:5px'>{item['attached']['S']}</td>")
                sg_resources_data.append(f"<td style='padding:5px'>{item['open_to']['S']}</td>")
                sg_resources_data.append(f"<td style='padding:5px'>{str(get_ints(scan_sg_dynamodb_response['Items'][0]['port']['SS']))}</td>")
                sg_resources_data.append(f"<td style='padding:5px'>{item['notifications_suppressed']['S']}</td>")
                sg_resources_data.append('</tr>')

        sg_table.append('</table>')
    sg_table = '\n'.join([str(elem) for elem in sg_table])

    iam_resources_data = []
    iam_table = []
    scan_iam_dynamodb_response = scan_dynamodb(IAM_TABLE)
    if scan_iam_dynamodb_response['Count'] > 0:
        headers_iam = ['IAM User', 'Account ID', 'Programmatic Access', 'Console Access', 'Notifications Suppressed']
        iam_table.append('<p style="font-size: 16px;"><b>IAM Users</b></p>')
        iam_table.append('<table border="1">')
        iam_table.append('<tr>')
        for label in headers_iam:
            iam_table.append(f'<th style="padding:5px">{label}</th>')
        iam_table.append('</tr>')
        iter = 1
        for item in scan_iam_dynamodb_response['Items']:
            iam_table.append('<tr>')
            iam_table.append(f"<td style='padding:5px'>{item['iam_user']['S']}</td>")
            iam_table.append(f"<td style='padding:5px'>{int(item['account_id']['S'])}</td>")
            iam_table.append(f"<td style='padding:5px'>{item['is_programmatic_access_enabled']['S']}</td>")
            iam_table.append(f"<td style='padding:5px'>{item['is_console_access_enabled']['S']}</td>")
            iam_table.append(f"<td style='padding:5px'>{item['notifications_suppressed']['S']}</td>")
            iam_table.append('</tr>')

            if NOTIFICATION_APP == 'googlechat':
                iam_resources_data.append(get_divider(NOTIFICATION_APP))
                iam_widget = {}
                iam_widget["textParagraph"] = {}
                iam_widget["textParagraph"]["text"] = f"<b>{item['iam_user']['S']}</b><br>"
                iam_widget["textParagraph"]["text"] += f"<font color=\"#868686\"><b>Account ID:</b> {int(item['account_id']['S'])}</font><br>"
                iam_widget["textParagraph"]["text"] += f"<font color=\"#868686\"><b>Programmatic Access:</b> {item['is_programmatic_access_enabled']['S']}</font><br>"
                iam_widget["textParagraph"]["text"] += f"<font color=\"#868686\"><b>Console Access:</b> {item['is_console_access_enabled']['S']}</font><br>"
                iam_widget["textParagraph"]["text"] += f"<font color=\"#868686\"><b>Notifications Suppressed:</b> {item['notifications_suppressed']['S']}</font><br>"
                iam_resources_data.append(iam_widget)
                iter = iter + 1
            elif NOTIFICATION_APP == 'slack':
                iam_widget = {}
                iam_widget["type"] = "context"
                iam_widget["elements"] = []
                iam_widget["elements"].append({})
                iam_widget["elements"][0]["type"] = "mrkdwn"
                iam_widget["elements"][0]["text"] = f"*{item['iam_user']['S']}*\n"
                iam_widget["elements"][0]["text"] += f"*Account ID:* {item['account_id']['S']}\n"
                iam_widget["elements"][0]["text"] += f"*Programmatic Access:* {item['is_programmatic_access_enabled']['S']}\n"
                iam_widget["elements"][0]["text"] += f"*Console Access:* {item['is_console_access_enabled']['S']}\n"
                iam_widget["elements"][0]["text"] += f"*Notifications Suppressed:* {item['notifications_suppressed']['S']}\n"
                iam_resources_data.append(iam_widget)

                card_iter = card_iter + 1
                if card_iter != len(scan_response['Items']):
                    iam_resources_data.append(get_divider(NOTIFICATION_APP))
            elif NOTIFICATION_APP == 'msteams':
                iam_resources_data.append('<tr>')
                iam_resources_data.append(f"<td style='padding:5px'>{item['iam_user']['S']}</td>")
                iam_resources_data.append(f"<td style='padding:5px'>{int(item['account_id']['S'])}</td>")
                iam_resources_data.append(f"<td style='padding:5px'>{item['is_programmatic_access_enabled']['S']}</td>")
                iam_resources_data.append(f"<td style='padding:5px'>{item['is_console_access_enabled']['S']}</td>")
                iam_resources_data.append(f"<td style='padding:5px'>{item['notifications_suppressed']['S']}</td>")
                iam_resources_data.append('</tr>')
        iam_table.append('</table>')
    iam_table = '\n'.join([str(elem) for elem in iam_table])

    s3_resources_data = []
    s3_table = []
    scan_s3_dynamodb_response = scan_dynamodb(S3_BUCKETS_TABLE)
    if scan_s3_dynamodb_response['Count'] > 0:
        headers_s3 = ['S3 Bucket Name', 'Account ID', 'Region', 'Encrypted', 'Public Bucket', 'Public Objects', 'Notifications Suppressed']
        s3_table.append('<p style="font-size: 16px;"><b>Public S3 Buckets</b></p>')
        s3_table.append('<table border="1">')
        s3_table.append('<tr>')
        for label in headers_s3:
            s3_table.append(f'<th style="padding:5px">{label}</th>')
        iter = 1
        for item in scan_s3_dynamodb_response['Items']:
            s3_table.append('<tr>')
            s3_table.append(f"<td style='padding:5px'>{item['s3_bucket_name']['S']}</td>")
            s3_table.append(f"<td style='padding:5px'>{int(item['account_id']['S'])}</td>")
            s3_table.append(f"<td style='padding:5px'>{item['region']['S']}</td>")
            s3_table.append(f"<td style='padding:5px'>{item['is_encryption_enabled']['S']}</td>")
            s3_table.append(f"<td style='padding:5px'>{item['is_public_bucket']['S']}</td>")
            s3_table.append(f"<td style='padding:5px'>{item['found_public_objects']['S']}</td>")
            s3_table.append(f"<td style='padding:5px'>{item['notifications_suppressed']['S']}</td>")
            s3_table.append('</tr>')

            if NOTIFICATION_APP == 'googlechat':
                s3_resources_data.append(get_divider(NOTIFICATION_APP))
                s3_widget = {}
                s3_widget["textParagraph"] = {}
                s3_widget["textParagraph"]["text"] = f"<b>{item['s3_bucket_name']['S']}</b><br>"
                s3_widget["textParagraph"]["text"] += f"<font color=\"#868686\"><b>Account ID:</b> {int(item['account_id']['S'])}</font><br>"
                s3_widget["textParagraph"]["text"] += f"<font color=\"#868686\"><b>Region:</b> {item['region']['S']}</font><br>"
                s3_widget["textParagraph"]["text"] += f"<font color=\"#868686\"><b>Encrypted:</b> {item['is_encryption_enabled']['S']}</font><br>"
                s3_widget["textParagraph"]["text"] += f"<font color=\"#868686\"><b>Public Bucket:</b> {item['is_public_bucket']['S']}</font><br>"
                s3_widget["textParagraph"]["text"] += f"<font color=\"#868686\"><b>Public Objects:</b> {item['found_public_objects']['S']}</font><br>"
                s3_widget["textParagraph"]["text"] += f"<font color=\"#868686\"><b>Notifications Suppressed:</b> {item['notifications_suppressed']['S']}</font><br>"
                s3_resources_data.append(s3_widget)
                iter = iter + 1
            elif NOTIFICATION_APP == 'slack':
                s3_widget = {}
                s3_widget["type"] = "context"
                s3_widget["elements"] = []
                s3_widget["elements"].append({})
                s3_widget["elements"][0]["type"] = "mrkdwn"
                s3_widget["elements"][0]["text"] = f"*{item['s3_bucket_name']['S']}*\n"
                s3_widget["elements"][0]["text"] += f"*Account ID:* {item['account_id']['S']}\n"
                s3_widget["elements"][0]["text"] += f"*Region:* {item['region']['S']}\n"
                s3_widget["elements"][0]["text"] += f"*Encrypted:* {item['is_encryption_enabled']['S']}\n"
                s3_widget["elements"][0]["text"] += f"*Public Bucket:* {item['is_public_bucket']['S']}\n"
                s3_widget["elements"][0]["text"] += f"*Public Objects:* {item['found_public_objects']['S']}\n"
                s3_widget["elements"][0]["text"] += f"*Notifications Suppressed:* {item['notifications_suppressed']['S']}\n"
                s3_resources_data.append(s3_widget)

                card_iter = card_iter + 1
                if card_iter != len(scan_response['Items']):
                    s3_resources_data.append(get_divider(NOTIFICATION_APP))
            elif NOTIFICATION_APP == 'msteams':
                s3_resources_data.append('<tr>')
                s3_resources_data.append(f"<td style='padding:5px'>{item['s3_bucket_name']['S']}</td>")
                s3_resources_data.append(f"<td style='padding:5px'>{int(item['account_id']['S'])}</td>")
                s3_resources_data.append(f"<td style='padding:5px'>{item['region']['S']}</td>")
                s3_resources_data.append(f"<td style='padding:5px'>{item['is_encryption_enabled']['S']}</td>")
                s3_resources_data.append(f"<td style='padding:5px'>{item['is_public_bucket']['S']}</td>")
                s3_resources_data.append(f"<td style='padding:5px'>{item['found_public_objects']['S']}</td>")
                s3_resources_data.append(f"<td style='padding:5px'>{item['notifications_suppressed']['S']}</td>")
                s3_resources_data.append('</tr>')
        s3_table.append('</table>')
    s3_table = '\n'.join([str(elem) for elem in s3_table])

    root_logins_resources_data = []
    root_logins_table = []
    found_24hr_data = False
    scan_root_logins_dynamodb_response = scan_dynamodb_by_user_status(ROOT_IAM_LOGINS_TABLE)
    if scan_root_logins_dynamodb_response['Count'] > 0:
        headers_root_logins = ['Account ID', 'Time of Login']
        root_logins_table.append('<p style="font-size: 22px;"><b>Root User Logins (in last 24hrs)</b></p>')
        root_logins_table.append('<table border="1">')
        root_logins_table.append('<tr>')
        for label in headers_root_logins:
            root_logins_table.append(f'<th style="padding:5px">{label}</th>')
        iter = 1
        card_iter = 0
        for item in scan_root_logins_dynamodb_response['Items']:
            difference = datetime.datetime.now(datetime.UTC) - datetime.datetime.strptime(item['first_attempt_at']['S'],"%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.UTC)
            if difference.days == 0:
                found_24hr_data = True
                root_logins_table.append('<tr>')
                root_logins_table.append(f"<td style='padding:5px'>{int(item['account_id']['S'])}</td>")
                root_logins_table.append(f"<td style='padding:5px'>{item['last_attempt_at']['S']}</td>")
                root_logins_table.append('</tr>')

                if NOTIFICATION_APP == 'googlechat':
                    root_logins_widget = {}
                    root_logins_widget["textParagraph"] = {}
                    root_logins_widget["textParagraph"]["text"] = f"<font color=\"#868686\"><b>Account ID:</b> {int(item['account_id']['S'])}</font><br>"
                    root_logins_widget["textParagraph"]["text"] += f"<font color=\"#868686\"><b>Last Attempt At:</b> {item['last_attempt_at']['S']}</font><br>"
                    root_logins_resources_data.append(root_logins_widget)
                    iter = iter + 1
                    card_iter = card_iter + 1
                    if card_iter != len(scan_root_logins_dynamodb_response['Items']):
                        root_logins_resources_data.append(get_divider(NOTIFICATION_APP))
                elif NOTIFICATION_APP == 'slack':
                    root_logins_widget = {}
                    root_logins_widget["type"] = "context"
                    root_logins_widget["elements"] = []
                    root_logins_widget["elements"].append({})
                    root_logins_widget["elements"][0]["type"] = "mrkdwn"
                    root_logins_widget["elements"][0]["text"] = f"*Account ID:* {item['account_id']['S']}\n"
                    root_logins_widget["elements"][0]["text"] += f"*Last Attempt At:* {item['last_attempt_at']['S']}\n"
                    root_logins_resources_data.append(root_logins_widget)

                    card_iter = card_iter + 1
                    if card_iter != len(scan_response['Items']):
                        root_logins_resources_data.append(get_divider(NOTIFICATION_APP))
                elif NOTIFICATION_APP == 'msteams':
                    root_logins_resources_data.append('<tr>')
                    root_logins_resources_data.append(f"<td style='padding:5px'>{int(item['account_id']['S'])}</td>")
                    root_logins_resources_data.append(f"<td style='padding:5px'>{item['last_attempt_at']['S']}</td>")
                    root_logins_resources_data.append('</tr>')
        root_logins_table.append('</table>')
    root_logins_table = '\n'.join([str(elem) for elem in root_logins_table])
    if not found_24hr_data:
        root_logins_table = ''

    email_subject = "Resources Tracker Report"
    body_html = ""
    if sg_table or iam_table or s3_table or root_logins_table or remediated_resources_table:
        body_html = f"""
        <body style="background-color:#edf2f0;padding:20px 40px 20px 40px;">
            <div style="display:inline-block;width:100%">
                <h1 style="text-align:center;">AWS Security Summary for {get_cst_cdt_date()}</h1>
            </div>
        """
        if sg_table or iam_table or s3_table:
            body_html += """<div style="background-color:#ffffff; padding:5px 20px 5px 20px;border-radius: 10px">
                <p style="font-size: 22px;"><b>Outstanding Issues (not yet remediated)</b></p><br>"""
            if sg_table:
                body_html += sg_table
            if iam_table:
                body_html += iam_table
            if s3_table:
                body_html += s3_table
            body_html += "</div><br>"
        if root_logins_table:
            body_html += f"""<div style="background-color:#ffffff; padding:5px 20px 5px 20px;border-radius: 10px">
                {root_logins_table}
            </div><br>"""
        if remediated_resources_table:
            body_html += f"""<div style="background-color:#ffffff; padding:5px 20px 5px 20px;border-radius: 10px">
                {remediated_resources_table}
            </div>"""
        body_html += "</body>"

    alert_message = daily_alert(NOTIFICATION_APP, get_cst_cdt_date(), sg_resources_data, iam_resources_data, s3_resources_data, root_logins_resources_data, remediated_resources_data)
    if alert_message:
        for url in WEBHOOK_URLS:
            alert = notify_app(url, alert_message)
            logger.info(alert)
    else:
        raise CustomException("Message was not generated")

    for recipient in RECEIVER_EMAIL_ADDRESSES:
        msg = MIMEMultipart('mixed')
        msg['Subject'] = email_subject
        msg['From'] = SENDER_EMAIL_ADDRESS
        msg_body = MIMEMultipart('alternative')
        htmlpart = MIMEText(body_html.encode("utf-8"), 'html', "utf-8")
        msg_body.attach(htmlpart)
        msg['To'] = recipient
        msg.attach(msg_body)
        try:
            if body_html:
                response = ses.send_raw_email(
                    Source=SENDER_EMAIL_ADDRESS,
                    Destinations=[recipient],
                    RawMessage={
                        'Data':msg.as_string()
                    }
                )
            else:
                raise CustomException("Email Message was not generated.")
        except Exception as error:
            logger.error(str(error))
        else:
            logger.info("Email sent to %s! Message ID: %s", recipient, response['MessageId'])
def scan_dynamodb(dynamodb_table):
    dynamodb = boto3.client('dynamodb')
    response = ""
    try:
        response = dynamodb.scan(TableName=dynamodb_table)
    except dynamodb.exceptions.ClientError as error:
        logger.error(error.response['Error']['Message'])
    return response
def scan_dynamodb_by_user_status(dyanmodb_table):
    """
    Scans DynamoDB for a specific record with user and its login status
    Args:
        dyanmodb_table

    Returns:
        response
    """
    dynamodb = boto3.client('dynamodb')
    response = ''
    try:
        response = dynamodb.query(
            TableName=dyanmodb_table,
            IndexName='UserStatusIndex',
            ExpressionAttributeNames={
                '#user': 'user',
                '#status': 'status'
            },
            ExpressionAttributeValues={
                ':user': {
                    'S': 'root',
                },
                ':status': {
                    'S': 'Success'
                }
            },
            KeyConditionExpression='#user = :user AND #status = :status'
        )
    except dynamodb.exceptions.ClientError as error:
        logger.error(error.response['Error']['Message'])
    return response
def get_divider(notification_app):
    """
    Returns divider for Notification Messages
    Args:
        notification_app
    Returns:
        divider
    """
    divider = ''
    if notification_app == 'googlechat':
        divider = {
            "divider": {

        }
    }
    elif notification_app == 'slack':
        divider = {
			"type": "divider"
		}
    return divider
def get_ints(ports):
    """
    Returns Integers List
    Args:
        ports
    Returns:
        int list
    """
    integers = []
    if type(ports) is list:
        for port in ports:
            integers.append(int(port))
    return integers
def get_cst_cdt_date():
    """
    Returns Date in CST/CDT Zone
    Returns:
        date
    """
    utc_now = datetime.datetime.now(datetime.timezone.utc)
    cst_offset = datetime.timedelta(hours=-6)  # CST is UTC-6
    cdt_offset = datetime.timedelta(hours=-5)  # CDT is UTC-5
    is_dst = bool(utc_now.dst())
    if is_dst:
        cst_cdt_time = utc_now + cdt_offset
    else:
        cst_cdt_time = utc_now + cst_offset
    return cst_cdt_time.strftime('%b %d, %Y')
def notify_app(url, message):
    """
    Sends Alert to Chosen Application
    Args:
        url
        message
    Returns:
        response
    """
    if NOTIFICATION_APP == "slack" and url.startswith("xoxb"):
        oauth_token, channel_id = url.split(":")
        message["channel"] = channel_id
        message_headers = { 'Content-Type': 'application/json; charset=UTF-8', "Authorization": f"Bearer {oauth_token}"}
        response = requests.post("https://slack.com/api/chat.postMessage", headers=message_headers, json=message, timeout=30)
        if not response.json().get("ok"):
            print("Failed to send block message:", response.json().get("error"))
        return response.json()
    http_obj = Http()
    message_headers = {'Content-Type': 'application/json; charset=UTF-8'}
    response = http_obj.request(uri=url, method='POST', headers=message_headers, body=json.dumps(message))
    return response
