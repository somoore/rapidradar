import logging
import json
import time
from collections import defaultdict
from os import getenv
from utils.iam import IAM
from utils.sts import AssumeRole
from utils.utility import Helper

MANAGEMENT_ACCOUNT_ID = getenv('MANAGEMENT_ACCOUNT_ID')
CROSS_ACCOUNT_ROLE = getenv('CROSS_ACCOUNT_ROLE')
SSO_CROSS_ACCOUNT_ROLE_ARN = getenv('SSO_CROSS_ACCOUNT_ROLE_ARN')
MAX_RETRY_ATTEMPTS = 5
DELAY_SECONDS = 3
LOGGER = logging.getLogger(getenv('PROJECT_NAME'))
LOGGER.setLevel('INFO')

class EC2:
    def __init__(self, active_session, region):
        self.region = region
        self.active_session = active_session
        self.client = self.active_session.client(service_name='ec2', region_name=self.region)
        self.resource = self.active_session.resource(service_name='ec2', region_name=self.region)

    def get_security_group_name(self, group_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_security_groups(GroupIds=[group_id])
                group_name = response['SecurityGroups'][0]['GroupName']
                return group_name
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'InvalidGroup.NotFound':
                    LOGGER.info("security group %s not found", group_id)
                    return None
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise error
        return None

    def found_security_group_attachments(self, group_id):
        is_attached = False
        attached_ec2_instances = []
        attached_loadbalancers = []
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                result = self.client.describe_network_interfaces(
                    Filters=[{'Name': 'group-id','Values': [group_id]}]
                )['NetworkInterfaces']
                for interface in result:
                    if 'Attachment' in interface:
                        is_attached = True
                        if interface['InterfaceType'] in ['interface', 'network_load_balancer']:
                            context = self.get_ec2_subnet_context(interface['SubnetId'])
                            if 'InstanceId' in interface['Attachment']:
                                resource_id = interface['Attachment']['InstanceId']
                                attached_ec2_instances.append({'ResourceId': resource_id, 'Context': context})
                            elif 'InstanceOwnerId' in interface['Attachment']:
                                if interface['Attachment']['InstanceOwnerId'] in ['amazon-elb', 'amazon-aws'] and 'ELB' in interface['Description']:
                                    resource_id = interface['Description'].split('ELB ')[1]
                                    attached_loadbalancers.append({'ResourceId': resource_id, 'Context': context})
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return is_attached, attached_ec2_instances, attached_loadbalancers

    def found_eni_w_bypass_tag(self, interface_id: str, ec2_launch_blocked_w_public_ip_bypass_tag_key) -> bool:
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_network_interfaces(NetworkInterfaceIds=[interface_id])
                for interface in response['NetworkInterfaces']:
                    if 'TagSet' in interface:
                        for tag in interface['TagSet']:
                            if tag['Key'] == ec2_launch_blocked_w_public_ip_bypass_tag_key:
                                return True
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'InvalidNetworkInterfaceID.NotFound':
                    LOGGER.info("Network Interface %s not found", interface_id)
                    return False
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def get_instance_details(self, instance_id, ec2_launch_blocked_wo_imdsv2_bypass_tag_key, ec2_launch_blocked_w_public_ip_bypass_tag_key, unencrypted_ebs_volume_creation_blocked_bypass_tag_key):
        retry_attempts = 0
        delay = DELAY_SECONDS
        instance_details = {}
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_instances(InstanceIds=[instance_id])
                if 'Reservations' in response and response['Reservations']:
                    if response['Reservations'][0]['Instances']:
                        instance = response['Reservations'][0]['Instances'][0]
                        instance_status = instance['State']['Name']
                        if instance and instance_status not in ['terminated']:
                            root_device_name = instance['RootDeviceName']
                            if 'Tags' in instance:
                                instance_details['Tags'] = instance['Tags']
                                for tag in instance['Tags']:
                                    if tag['Key'] == ec2_launch_blocked_wo_imdsv2_bypass_tag_key:
                                        instance_details['FoundIMDSv2BypassTag'] = True
                            if 'NetworkInterfaces' in instance:
                                for network in instance['NetworkInterfaces']:
                                    if self.found_eni_w_bypass_tag(network['NetworkInterfaceId'], ec2_launch_blocked_w_public_ip_bypass_tag_key):
                                        instance_details['FoundPublicIPBypassTag'] = True
                                        break
                            if 'BlockDeviceMappings' in instance:
                                for dvc in instance['BlockDeviceMappings']:
                                    if dvc['DeviceName'] == root_device_name:
                                        root_volume_details = self.get_volume_details(dvc['Ebs']['VolumeId'], unencrypted_ebs_volume_creation_blocked_bypass_tag_key)
                                        instance_details['IsRootVolumeEncrypted'] = root_volume_details['IsVolumeEncrypted']
                                        if 'FoundEncryptedEBSBypassTag' in root_volume_details:
                                            instance_details['FoundEncryptedEBSBypassTag'] = root_volume_details['FoundEncryptedEBSBypassTag']
                            instance_details['LaunchTime'] = instance['LaunchTime'].strftime("%Y-%m-%dT%H:%M:%S")
                            instance_details['InstanceType'] = instance['InstanceType']
                            instance_details['PublicIpAddress'] = None if 'PublicIpAddress' not in instance else instance['PublicIpAddress']
                            instance_details['Context'] = self.get_ec2_subnet_context(instance['SubnetId'])
                            instance_details['SecurityGroups'] = [ sg['GroupId'] for sg in instance['SecurityGroups'] ]
                            instance_details['IsIMDSv2Enabled'] = False
                            if 'MetadataOptions' in instance and 'HttpTokens' in instance['MetadataOptions']:
                                if instance['MetadataOptions']['HttpTokens'] == 'required':
                                    instance_details['IsIMDSv2Enabled'] = True
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                    LOGGER.info("EC2 Instance %s not found", instance_id)
                    break
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return instance_details

    def get_attached_security_groups_for_ec2_instance(self, instance_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_instances(InstanceIds=[instance_id])
                if 'Reservations' in response and response['Reservations']:
                    instance = response['Reservations'][0]['Instances'][0]
                    if instance and 'SecurityGroups' in instance:
                        security_groups = [sg['GroupId'] for sg in instance['SecurityGroups']]
                        return security_groups
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                    LOGGER.info("EC2 Instance %s not found", instance_id)
                    break
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return []

    def get_vpc_id_for_network_interface(self, interface_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_network_interfaces(NetworkInterfaceIds=[interface_id])
                if 'NetworkInterfaces' in response and response['NetworkInterfaces']:
                    vpc_id = response['NetworkInterfaces'][0]['VpcId']
                    return vpc_id
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'InvalidNetworkInterfaceID.NotFound':
                    LOGGER.info("Network Interface %s not found", interface_id)
                    return None
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return None

    def is_instance_private(self, instance_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                reservations = self.client.describe_instances(InstanceIds=[instance_id])['Reservations']
                if len(reservations) > 0:
                    instance = reservations[0]['Instances'][0]
                    if 'PublicIpAddress' not in instance:
                        return True
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                    LOGGER.info("EC2 Instance %s not found", instance_id)
                    break
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def is_instance_imdsv2_enabled(self, instance_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                reservations = self.client.describe_instances(InstanceIds=[instance_id])['Reservations']
                for reservation in reservations:
                    for instance in reservation['Instances']:
                        if 'MetadataOptions' in instance and 'HttpTokens' in instance['MetadataOptions']:
                            if instance['MetadataOptions']['HttpTokens'] == 'required':
                                return True
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                    LOGGER.info("EC2 Instance %s not found", instance_id)
                    return False
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def get_volume_details(self, volume_id, unencrypted_ebs_volume_creation_blocked_bypass_tag_key):
        retry_attempts = 0
        delay = DELAY_SECONDS
        volume_details = {}
        volume_details['IsVolumeEncrypted'] = False
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_volumes(VolumeIds=[volume_id])
                volume = response['Volumes'][0]
                if volume:
                    volume_details['IsVolumeEncrypted'] = volume['Encrypted']
                    if 'Tags' in volume:
                        for tag in volume['Tags']:
                            if tag['Key'] == unencrypted_ebs_volume_creation_blocked_bypass_tag_key:
                                volume_details['FoundEncryptedEBSBypassTag'] = True
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'InvalidVolume.NotFound':
                    LOGGER.info("EBS Volume %s not found", volume_id)
                    return volume_details
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return volume_details

    def is_instance_root_vol_encrypted(self, instance_id, unencrypted_ebs_volume_creation_blocked_bypass_tag_key):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                reservations = self.client.describe_instances(InstanceIds=[instance_id])['Reservations']
                for reservation in reservations:
                    for instance in reservation['Instances']:
                        root_device_name = instance['RootDeviceName']
                        if 'BlockDeviceMappings' in instance:
                            for dvc in instance['BlockDeviceMappings']:
                                if dvc['DeviceName'] == root_device_name:
                                    if self.get_volume_details(dvc['Ebs']['VolumeId'], unencrypted_ebs_volume_creation_blocked_bypass_tag_key)['IsVolumeEncrypted']:
                                        return True
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                    LOGGER.info("EC2 Instance %s not found", instance_id)
                    break
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def found_all_scp_tags(self, instance_id, scp_tags):
        missing_tags = []
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                reservations = self.client.describe_instances(InstanceIds=[instance_id])['Reservations']
                for reservation in reservations:
                    for instance in reservation['Instances']:
                        if 'Tag' in instance:
                            instance_tag_keys = [ tag['Key'] for tag in instance['Tags'] ]
                            for tag in scp_tags:
                                if tag not in instance_tag_keys:
                                    missing_tags.append(tag)
                if missing_tags:
                    return False
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                    LOGGER.info("EC2 Instance %s not found", instance_id)
                    break
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def get_security_group_open_ports(self, group_id):
        is_open_to_all = False
        ports_ruleid = []
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                security_group_details = self.client.describe_security_group_rules(
                    Filters=[{'Name': 'group-id','Values': [group_id]}]
                )['SecurityGroupRules']
                for rule in security_group_details:
                    if not rule['IsEgress'] and 'CidrIpv4' in rule and rule['CidrIpv4'] == '0.0.0.0/0':
                        is_open_to_all = True
                        ports_ruleid.append({
                            "Protocol": rule['IpProtocol'],
                            "Port": rule['FromPort'] if rule['FromPort']==rule['ToPort'] else f"{str(rule['FromPort'])}-{str(rule['ToPort'])}",
                            "RuleId": rule['SecurityGroupRuleId']
                        })
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return is_open_to_all, ports_ruleid

    def found_critical_ports_open(self, security_group_id, event_port, ports_userip):
        security_group_open_ports = self.get_security_group_open_ports(security_group_id)
        if security_group_open_ports[0]:
            for item in security_group_open_ports[1]:
                port = ""
                if isinstance(event_port, str):
                    port = str(item['Port'])
                elif isinstance(event_port, int):
                    port = int(item['Port'])
                if port == event_port:
                    user_ip_address = next((json.loads(scan_port)['UserIpAddress'] for scan_port in ports_userip if str(json.loads(scan_port)['Port']) == port), '')
                    return True, { "RuleId": item['RuleId'], "UserIpAddress": user_ip_address }
        return False, None

    def delete_security_group_rule(self, group_id, sg_rule_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.revoke_security_group_ingress(
                    GroupId=group_id,
                    SecurityGroupRuleIds=[sg_rule_id]
                )
                return True
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def get_instance_id_for_network_interface(self, interface_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_network_interfaces(NetworkInterfaceIds=[interface_id])
                if 'NetworkInterfaces' in response and response['NetworkInterfaces']:
                    attachment = response['NetworkInterfaces'][0]['Attachment']
                    if attachment and 'InstanceId' in attachment:
                        instance_id = attachment['InstanceId']
                        return instance_id
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return None

    def close_opened_security_group_rule(self, group_id, group_rule_id, port, protocol, user_ip_address):
        from_port, to_port = (map(int, port.split('-')) if isinstance(port, str) and '-' in port else (int(port), int(port)))
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.modify_security_group_rules(
                    GroupId=group_id,
                    SecurityGroupRules=[{
                        'SecurityGroupRuleId': group_rule_id,
                        'SecurityGroupRule': {
                            'IpProtocol': protocol,
                            'FromPort': from_port,
                            'ToPort': to_port,
                            'CidrIpv4': f"{user_ip_address}/32",
                            'Description': f'Rule for Port {str(port)} restricted to User IP Address'
                        }
                    }]
                )
                return True
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def delete_security_group(self, group_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.delete_security_group(GroupId=group_id)
                return True, 'DELETED'
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] in ['InvalidGroup.NotFound']:
                    LOGGER.info("Security Group %s not Found", group_id)
                    return False, 'InvalidGroup.NotFound'
                if error.response['Error']['Code'] in ['DependencyViolation']:
                    LOGGER.error("Group Dependency")
                    return False, 'DependencyViolation'
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                return False, 'OTHER'

    def get_blackhole_sg_id(self, vpc_id, sg_name):
        group_id = None
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                check_if_sg_exists = self.client.describe_security_groups(
                    Filters=[{
                        'Name': 'vpc-id',
                        'Values': [vpc_id]
                    },{
                        'Name': 'group-name',
                        'Values': [sg_name]
                    }]
                )['SecurityGroups']
                if len(check_if_sg_exists) == 0:
                    LOGGER.info("...Creating new Blackhole Security Group for EC2 Instances")
                    new_sg = self.client.create_security_group(
                        Description='Blackhole Security Group',
                        GroupName=sg_name,
                        VpcId=vpc_id
                    )
                    group_id = new_sg['GroupId']
                else:
                    LOGGER.info("Security Group already exists. Not Creating a new one.")
                    group_id = check_if_sg_exists[0]['GroupId']
                return group_id
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'InvalidVpcId.NotFound':
                    LOGGER.info("VPC %s not found", vpc_id)
                    return group_id
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error("Could not get ID of Blackhole Security Group")
                raise error
        return group_id

    def modify_ec2_security_groups(self, instance_id, security_groups: list):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.modify_instance_attribute(
                    InstanceId=instance_id,
                    Groups=security_groups
                )
                return True
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def make_public_snapshot_private(self, snapshot_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.modify_snapshot_attribute(
                    Attribute='createVolumePermission',
                    CreateVolumePermission={
                        'Remove': [{
                            'Group': 'all',
                        }]
                    },
                    GroupNames=['all',],
                    OperationType='remove',
                    SnapshotId=snapshot_id
                )
                return True
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def make_public_ami_private(self, ami_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.modify_image_attribute(
                    ImageId=ami_id,
                    LaunchPermission={
                        'Remove': [{
                            'Group': 'all',
                        }]
                    }
                )
                return True
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def get_ec2_subnet_context(self, subnet_id):
        context = 'Unable to determine automatically'
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                route_tables = self.client.describe_route_tables(
                    Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}]
                )['RouteTables']
                for route_table in route_tables:
                    for route in route_table['Routes']:
                        if 'GatewayId' in route and 'igw-' in route['GatewayId']:
                            context = 'Inbound & Outbound'
                        elif 'NatGatewayId' in route:
                            context = 'Outbound Only'
                        elif 'TransitGatewayId' in route:
                            context = 'Intra-VPC communication'
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return context

    def get_instance_cost_details(self, instance_id: str):
        cost_type = 'on-demand'
        usage_operation = ''
        tenancy = ''
        platform_detail = ''
        platform = ''
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                describe_instance_response = self.client.describe_instances(InstanceIds=[instance_id])
                if describe_instance_response['Reservations'] and describe_instance_response['Reservations'][0]['Instances']:
                    instance_details = describe_instance_response['Reservations'][0]['Instances'][0]
                    if 'InstanceLifecycle' in instance_details:
                        cost_type = instance_details['InstanceLifecycle']
                    if 'Placement' in instance_details:
                        tenancy = instance_details['Placement']['Tenancy']
                    if 'UsageOperation' in instance_details:
                        usage_operation = instance_details['UsageOperation']
                    if tenancy == 'default':
                        tenancy = 'Shared'
                    elif tenancy in ['dedicated', 'host']:
                        tenancy = tenancy.capitalize()
                    elif not tenancy and cost_type == 'scheduled':
                        tenancy = 'Reserved'
                    if 'PlatformDetails' in instance_details:
                        platform_detail = instance_details['PlatformDetails']
                    platform = instance_details['Platform'] if 'Platform' in instance_details else 'linux'
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                    LOGGER.info("EC2 Instance %s not found", instance_id)
                    break
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return cost_type, tenancy, usage_operation, platform_detail, platform

    def get_spot_price(self, instance_type, prod_description, spot_request_id):
        spot_price = ''
        hourly_cost, daily_cost, monthly_cost = '', '', ''
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                start_time, end_time = '', ''
                if spot_request_id.startswith('sfr-'):
                    response = self.client.describe_spot_fleet_requests(
                        SpotFleetRequestIds=[spot_request_id]
                    )['SpotFleetRequestConfigs']
                    if len(response) > 0:
                        start_time = response[0]['SpotFleetRequestConfig']['ValidFrom']
                        end_time = response[0]['SpotFleetRequestConfig']['ValidUntil']
                elif spot_request_id.startswith('sir-'):
                    response = self.client.describe_spot_instance_requests(
                        SpotInstanceRequestIds=[spot_request_id]
                    )['SpotInstanceRequests']
                    if len(response) > 0:
                        start_time = response[0]['ValidFrom']
                        end_time = response[0]['ValidUntil']
                if start_time and end_time:
                    response = self.client.describe_spot_price_history(
                        InstanceTypes=[instance_type],
                        EndTime=end_time,
                        StartTime=start_time,
                        ProductDescriptions=[prod_description]
                    )['SpotPriceHistory']
                    if len(response) > 0:
                        spot_price = response[0]['SpotPrice']
                if spot_price:
                    hourly_cost = float(spot_price)
                    daily_cost = hourly_cost * 24
                    monthly_cost = daily_cost * 30
                    hourly_cost = f"USD {hourly_cost:.2f}"
                    daily_cost = f"USD {daily_cost:.2f}"
                    monthly_cost = f"USD {monthly_cost:.2f}"
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return hourly_cost, daily_cost, monthly_cost

    def get_instance_network_interfaces(self, instance_id):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]['NetworkInterfaces']
                return response
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                    LOGGER.info("EC2 Instance %s not found", instance_id)
                    break
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return ''

    def get_cmdb_instance_details(self, instance_id: str):
        tags = []
        launch_time, public_ip, ec2_instance_exists = '', '', True
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_instances(InstanceIds=[instance_id])
                for reservation in response['Reservations']:
                    for instance_details in reservation['Instances']:
                        if 'Tags' in instance_details:
                            tags = [ f"{tag['Key']}: {tag['Value']}" for tag in instance_details['Tags'] ]
                        if 'PublicIpAddress' in instance_details:
                            public_ip = instance_details['PublicIpAddress']
                        launch_time = instance_details['LaunchTime'].strftime("%Y-%m-%dT%H:%M:%S")
                break
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                    ec2_instance_exists = False
                    LOGGER.info("EC2 Instance %s not found", instance_id)
                    break
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return tags, launch_time, public_ip, ec2_instance_exists

    def found_suppression_tag_sg(self, security_group_id, alert_suppression_tag_key, alert_suppression_tag_value):
        found_suppresion_tag = False
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                result = self.client.describe_tags(
                    Filters=[
                        { 'Name': 'key', 'Values': [alert_suppression_tag_key]},
                        { 'Name': 'value', 'Values': [alert_suppression_tag_value]},
                        { 'Name': 'resource-id', 'Values': [security_group_id]},
                        { 'Name': 'resource-type', 'Values': ['security-group']}
                    ]
                )['Tags']
                if len(result) > 0:
                    found_suppresion_tag = True
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return found_suppresion_tag

    def add_tags_to_ec2_resource(self, resource: list, tags: list) -> bool:
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.create_tags(
                    Resources=[resource],
                    Tags=tags
                )
                return True
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def found_override_tag(self, resource_id, resource_type, override_tag_key):
        found_override_tag = False
        is_value_base64_encoded = False
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_tags(
                    Filters=[
                        {'Name': 'resource-id', 'Values': [resource_id]},
                        {'Name': 'resource-type', 'Values': [resource_type]},
                        {'Name': 'key', 'Values': [override_tag_key]},
                    ]
                )['Tags']
                for tag in response:
                    found_override_tag = True
                    if Helper().is_base64_encoded(tag['Value']):
                        is_value_base64_encoded = True
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return found_override_tag, is_value_base64_encoded

    def found_keep_alive_tag(self, resource_id, resource_type):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                response = self.client.describe_tags(
                    Filters=[
                        {'Name': 'resource-id', 'Values': [resource_id]},
                        {'Name': 'resource-type', 'Values': [resource_type]},
                        {'Name': 'tag:keep-alive', 'Values': ['true']},
                    ]
                )['Tags']
                if len(response) > 0:
                    return True
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def get_instance_status(self, instance_id: str) -> str:
        try:
            instance = self.resource.Instance(instance_id)
            if hasattr(instance, 'state'):
                state = instance.state.get('Name')
                return state
            LOGGER.info("EC2 Instance %s does not exist anymore.", instance_id)
            return "terminated"
        except self.client.exceptions.ClientError as error:
            LOGGER.error(str(error))
            return "terminated"

    def terminate_ec2_instance(self, instance_id) -> bool:
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.terminate_instances(
                    InstanceIds=[instance_id]
                )
                return True
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def delete_ebs_volume(self, volume_id) -> bool:
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.delete_volume(VolumeId=volume_id)
                return True
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def release_eip(self, allocation_id) -> bool:
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.release_address(AllocationId=allocation_id)
                return True
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def create_flow_logs(self, vpc_id, traffic_type, destination_arn) -> bool:
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.create_flow_logs(
                    ResourceIds=[vpc_id],
                    ResourceType='VPC',
                    TrafficType=traffic_type,
                    LogDestinationType='s3',
                    LogDestination=destination_arn,
                    LogFormat='${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}'
                )
                return True
            except self.client.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'InvalidVpcId.NotFound':
                    LOGGER.info("VPC %s not found", vpc_id)
                    return True
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return False

    def is_role_attached_to_ec2(self, account_id, child_account_regions, role_name):
        is_attached_to_ec2 = False
        instances = defaultdict(list)
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                instance_profiles = IAM(self.active_session).get_instance_profiles(role_name)
                for region in child_account_regions:
                    cross_account_role_arn = SSO_CROSS_ACCOUNT_ROLE_ARN if account_id == MANAGEMENT_ACCOUNT_ID else f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE}-{region}"
                    regional_active_session = AssumeRole(cross_account_role_arn).assume_role(region)
                    regional_client = regional_active_session.client(service_name='ec2', region_name=region)
                    reservations = regional_client.describe_instances()['Reservations']
                    for reservation in reservations:
                        for instance in reservation['Instances']:
                            if 'IamInstanceProfile' in instance and instance['IamInstanceProfile']['Arn'] in instance_profiles:
                                is_attached_to_ec2 = True
                                instances[region].append(instance['InstanceId'])
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                break
        return is_attached_to_ec2, instances

    def attach_managed_role_to_ec2(self, instance_id: str, profile_arn: str):
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                self.client.associate_iam_instance_profile(
                    IamInstanceProfile={
                        'Arn': profile_arn
                    },
                    InstanceId=instance_id
                )
                return True
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error("Could not attach managed IAM Role to EC2 Instance %s", instance_id)
                raise error

    def __get_all_instances_details(self, account_id, active_regions):
        instances_details = []
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                for region in active_regions:
                    cross_account_role_arn = SSO_CROSS_ACCOUNT_ROLE_ARN if account_id == MANAGEMENT_ACCOUNT_ID else f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE}-{region}"
                    regional_active_session = AssumeRole(cross_account_role_arn).assume_role(region)
                    regional_client = regional_active_session.client(service_name='ec2', region_name=region)
                    next_token, base_kwargs = '', {}
                    while next_token is not None:
                        kwargs = base_kwargs.copy()
                        if next_token != '':
                            kwargs.update({'NextToken': next_token})
                        response = regional_client.describe_instances(**kwargs)
                        for reservation in response['Reservations']:
                            for instance in reservation['Instances']:
                                if instance['State']['Name'] not in ['shutting-down', 'terminated'] and 'IamInstanceProfile' in instance:
                                    instances_details.append(instance)
                        next_token = response['NextToken'] if 'NextToken' in response else None
                return instances_details
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                raise error

    def role_associated_instances(self, role_instance_profiles, account_id, active_regions):
        associated_instances = []
        retry_attempts = 0
        delay = DELAY_SECONDS
        while retry_attempts < MAX_RETRY_ATTEMPTS:
            try:
                all_instances_details = self.__get_all_instances_details(account_id, active_regions)
                for instance in all_instances_details:
                    if instance['IamInstanceProfile']['Arn'] in role_instance_profiles:
                        associated_instances.append(instance['InstanceId'])
                break
            except self.client.exceptions.ClientError as error:
                if retry_attempts < MAX_RETRY_ATTEMPTS:
                    retry_attempts += 1
                    LOGGER.info("%s. Retrying in %s seconds...", str(error), delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                LOGGER.error(str(error))
                raise error
        return associated_instances
