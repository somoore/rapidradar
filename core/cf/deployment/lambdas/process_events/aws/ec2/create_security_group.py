import time
import copy
from utils.ec2 import EC2
from utils.elb import ELB
from utils.utility import AWSHelper, Alert
from utils.logger import LOGGER
from messenger.events_messenger import EventAlert
from messenger.email_alerts import EmailAlert
from messenger.slack_bot import SlackBot

def handle_event(helper: AWSHelper, event, notification_app, webhook_urls, slack_oauth_token, sender_email, send_logs_to_azure, customer_id, shared_key, log_type, pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi):
    if 'errorCode' not in event and 'requestParameters' in event and 'responseElements' in event:
        request_params = event['requestParameters']
        response_elements = event['responseElements']
        messenger = EventAlert(notification_app, helper.account_id, helper.region, webhook_urls)
        email_messenger = EmailAlert(sender_email, helper.account_id, helper.region)
        slack_bot = None
        if slack_oauth_token:
            slack_bot = SlackBot(slack_oauth_token, helper.iam_user, helper.account_id, messenger.account_name, helper.region)
        active_session = helper.get_active_session()
        ec2_utils = EC2(active_session, helper.region)
        elb_utils = ELB(active_session, helper.region)
        try:
            group_name = request_params['groupName']
            vpc_id = request_params['vpcId']
            group_id = response_elements['groupId']
            azure_data = {
                "AccountID": helper.account_id,
                "AccountName": messenger.account_name,
                "Region": helper.region,
                "User": helper.iam_user
            }
            if group_name.startswith('launch-wizard-'):
                LOGGER.warning("Launch Wizard Security Group being created. Checking if its attached to any resource...")
                is_attached, attached_ec2_instances, attached_loadbalancers = ec2_utils.found_security_group_attachments(group_id)
                if not is_attached:
                    LOGGER.info("Not Attached to any resource. Deleting this Security Group...")
                    is_deleted, reason = ec2_utils.delete_security_group(group_id)
                    if not is_deleted:
                        LOGGER.error("Could not delete security group %s in account %s and region %s. Reason: %s", group_id, helper.account_id, helper.region, reason)
                else:
                    is_replaced_by_blackhole_sg = False
                    resource_type = ''
                    for instance in attached_ec2_instances:
                        resource_type = 'EC2 Instance'
                        attached_security_groups = ec2_utils.get_attached_security_groups_for_ec2_instance(instance['ResourceId'])
                        new_security_group_ids = copy.copy(attached_security_groups)
                        new_security_group_ids.remove(group_id)
                        is_replaced_by_blackhole_sg = False
                        if len(attached_security_groups) == 1:
                            security_group_id = ec2_utils.get_blackhole_sg_id(vpc_id, 'blackhole-security-group')
                            if security_group_id is not None:
                                new_security_group_ids.append(security_group_id)
                                is_replaced_by_blackhole_sg = True
                        if not ec2_utils.modify_ec2_security_groups(instance['ResourceId'], new_security_group_ids):
                            LOGGER.error("Could not attach updated list of security groups to EC2 Instance %s", instance['ResourceId'])
                    for lb in attached_loadbalancers:
                        resource_type = 'LoadBalancer'
                        loadbalancer_type, resource_id = ''
                        if '/' not in lb['ResourceId']:
                            loadbalancer_type = 'Classic'
                            resource_id = lb['ResourceId']
                        else:
                            lb_prefix, lb_name, lb_id = lb['ResourceId'].split('/')
                            loadbalancer_type = 'Application' if lb_prefix == 'app' else 'Network' if lb_prefix == 'net' else ''
                            resource_id = f"arn:aws:elasticloadbalancing:{helper.region}:{helper.account_id}:loadbalancer/{lb_prefix}/{lb_name}/{lb_id}"
                        attached_security_groups = elb_utils.get_lb_details(loadbalancer_type, resource_id)[2]
                        new_security_group_ids = copy.copy(attached_security_groups)
                        new_security_group_ids.remove(group_id)
                        is_replaced_by_blackhole_sg = False
                        if len(attached_security_groups) == 1:
                            security_group_id = ec2_utils.get_blackhole_sg_id(vpc_id, 'blackhole-security-group')
                            if security_group_id is not None:
                                new_security_group_ids.append(security_group_id)
                                is_replaced_by_blackhole_sg = True
                        if not elb_utils.update_attached_lb_security_groups(loadbalancer_type, resource_id, new_security_group_ids):
                            LOGGER.error("Could not attach updated list of security groups to loadbalancer %s in Account=%s and Region=%s", resource_id, helper.account_id, helper.region)

                    time.sleep(5)
                    is_deleted, reason = ec2_utils.delete_security_group(group_id)
                    if not is_deleted:
                        LOGGER.error("Could not delete security group %s in account %s and region %s. Reason: %s", group_id, helper.account_id, helper.region, reason)
                    if attached_ec2_instances or attached_loadbalancers:
                        severity = 'Low'
                        alert_args = {
                            "is_create_event": True,
                            "severity": severity,
                            "iam_user": helper.iam_user,
                            "group_name": group_name,
                            "resource_type": resource_type,
                            "attachments": [ attch['ResourceId'] for attch in attached_ec2_instances+attached_loadbalancers],
                            "is_replaced_by_blackhole_sg": is_replaced_by_blackhole_sg,
                            "is_deleted": is_deleted
                        }
                        azure_data['Severity'] = severity
                        azure_data['Event'] = f"User {helper.iam_user} created {group_name} security group and attached it to {resource_type} {[ attch['ResourceId'] for attch in attached_ec2_instances+attached_loadbalancers]} which {'has been replaced by blackhole security group and' if is_replaced_by_blackhole_sg else ''} {'has been deleted' if is_deleted else 'hasnt been deleted because its also attached to some other resource'}"
                        alerts_handler = Alert(pagerduty_helper, incident_finding_types, is_pd_integration_type_restapi, False, messenger, send_logs_to_azure, azure_data, customer_id, shared_key, log_type)
                        alerts_handler.handler('launch_wizard_security_group_replaced', alert_args, email_messenger, slack_bot)
            else:
                LOGGER.info("No Launch Wizard Security Group")
        except Exception as error:
            LOGGER.error(str(error))
    else:
        LOGGER.info("Security Group was not created for some reason")
