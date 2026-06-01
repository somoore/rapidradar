from utils.ec2 import EC2
from utils.elb import ELB
from utils.events import Events
from utils.utility import AWSHelper
from utils.logger import LOGGER

def handle_event(event, ec2_launch_blocked_wo_imdsv2, ec2_launch_blocked_w_public_ip, ec2_launch_blocked_wo_certain_tags, ec2_instance_launch_scp_tag_keys, unencrypted_ebs_volume_creation_blocked, unencrypted_ebs_volume_creation_blocked_bypass_tag_key):
    event_trigger_name = event['resources'][0].split('/')[-1]
    resource_details = event_trigger_name.replace("ten-min-cron-", "").split("_")
    account_id, region, resource_id = resource_details[0], resource_details[1], resource_details[2]
    detail = { 'account': account_id, 'region': region }
    helper = AWSHelper(detail)
    active_session = helper.get_active_session()
    ec2_utils = EC2(active_session, helper.region)
    elb_utils = ELB(active_session, helper.region)
    events_utils = Events(helper.account_id, helper.region)

    if resource_id.startswith('i-'):
        if not ec2_utils.found_keep_alive_tag(resource_id, 'instance'):
            LOGGER.info("keep-alive tag not found on EC2 Instance %s", resource_id)
            LOGGER.info("Checking if required actions were taken before we delete the resource...")
            if not ec2_utils.is_instance_private(resource_id) and ec2_launch_blocked_w_public_ip:
                LOGGER.info("EC2 Instance %s is not private. Terminating...", resource_id)
                ec2_utils.terminate_ec2_instance(resource_id)
            elif not ec2_utils.is_instance_imdsv2_enabled(resource_id) and ec2_launch_blocked_wo_imdsv2:
                LOGGER.info("IMDSv2 is not enabled for EC2 Instance %s. Terminating...", resource_id)
                ec2_utils.terminate_ec2_instance(resource_id)
            elif not ec2_utils.is_instance_root_vol_encrypted(resource_id, unencrypted_ebs_volume_creation_blocked_bypass_tag_key) and unencrypted_ebs_volume_creation_blocked:
                LOGGER.info("Root Volume of EC2 Instance %s not encrypted. Terminating...", resource_id)
                ec2_utils.terminate_ec2_instance(resource_id)
            elif not ec2_utils.found_all_scp_tags(resource_id, ec2_instance_launch_scp_tag_keys) and ec2_launch_blocked_wo_certain_tags:
                LOGGER.info("SCP tags missing on EC2 Instance %s. Terminating...")
                ec2_utils.terminate_ec2_instance(resource_id)

    elif resource_id.startswith('vol-'):
        if not ec2_utils.found_keep_alive_tag(resource_id, 'volume'):
            LOGGER.info("keep-alive tag not found on EBS Volume %s. Deleting...", resource_id)
            ec2_utils.delete_ebs_volume(resource_id)

    elif any(resource_id.startswith(prefix) for prefix in ['clb', 'alb', 'nlb', 'glb']):
        if not elb_utils.found_keep_alive_tag(resource_id):
            LOGGER.info("keep-alive tag not found on LoadBalancer %s. Deleting...", resource_id)
            elb_utils.delete_loadbalancer(resource_id)

    elif resource_id.startswith('eipalloc-'):
        if not ec2_utils.found_keep_alive_tag(resource_id, 'elastic-ip'):
            LOGGER.info("keep-alive tag not found on EIP Allocation %s. Releasing...", resource_id)
            ec2_utils.release_eip(resource_id)

    if not events_utils.cleanup_10_min_cron_rule(resource_id):
        LOGGER.error("Could not cleanup 10 min cron rule named %s", event_trigger_name)
