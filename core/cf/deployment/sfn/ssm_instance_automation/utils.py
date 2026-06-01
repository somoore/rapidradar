from os import getenv
import json
import time
import boto3

PROJECT_NAME = getenv('PROJECT_NAME')
CROSS_ACCOUNT_ROLE = getenv('CROSS_ACCOUNT_ROLE')
ADDITIONAL_POLICIES_NAMES = getenv('ADDITIONAL_POLICIES_NAMES').replace(' ', '').split(',')
CREATE_NEW_MANAGED_POLICY = json.loads(getenv('CREATE_NEW_MANAGED_POLICY'))
MANAGED_POLICY_NAME = getenv('MANAGED_POLICY_NAME')
MANAGED_POLICY_DOCUMENT_JSON = getenv('MANAGED_POLICY_DOCUMENT_JSON')
ENABLE_EC2_INSTANCE_CONFIGURATOR = json.loads(getenv('ENABLE_EC2_INSTANCE_CONFIGURATOR'))
MAX_RETRY_ATTEMPTS = 5
DELAY_SECONDS = 3

def __assume_role(region, arn):
    """
    Assumes Role to get into Child Accounts to get details for a specific event
    Args:
        arn (str): IAM Role ARN
    Returns:
        session
    """
    sts = boto3.client('sts', region_name=region)
    response = sts.assume_role(RoleArn=arn, RoleSessionName=PROJECT_NAME)
    session = boto3.Session(aws_access_key_id=response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                    aws_session_token=response['Credentials']['SessionToken'])
    return session

def get_account_details(event):
    """
    Retrieves relevant account details from an event
    Args:
        event (dict): The AWS CloudTrail event to extract details from.
    Returns:
        tuple: A tuple containing the account ID, region.
    """
    if 'account' in event and 'region' in event:
        account_id = event['account']
        region = event['region']
        return account_id, region

def is_cloud9_instance(account_id, region, instance_id):
    """
    Check if instance is created by Cloud9, if yes then exclude the instance from the solution

    Args:
        event_detail (dict): Payload passed by CloudTrail API Event

    Returns:
        bool: True if its invoked by cloud9 else False
    """
    retry_attempts = 0
    delay = DELAY_SECONDS
    active_session = __assume_role(region, f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE}-{region}")
    client = active_session.client(service_name='cloudtrail',region_name=region)
    while retry_attempts < MAX_RETRY_ATTEMPTS:
        try:
            events = client.lookup_events(LookupAttributes=[{'AttributeKey': 'ResourceName', 'AttributeValue': instance_id}])['Events']
            for event in events:
                if event['EventName'] == 'RunInstances':
                    if 'CloudTrailEvent' in event:
                        cloudtrail_event = json.loads(event['CloudTrailEvent'])
                        user_identity = cloudtrail_event['userIdentity']
                        if 'invokedBy' in user_identity.keys():
                            if user_identity['invokedBy'] == 'cloud9.amazonaws.com':
                                return True
                    break
            return False
        except client.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'ThrottlingException' and retry_attempts < MAX_RETRY_ATTEMPTS:
                retry_attempts += 1
                print(f"{str(error)}. Retrying in {delay} seconds...")
                time.sleep(delay)
                delay *= 2
                continue
            raise error
    return False

def __get_instance_profile_roles(client, profile_name: str):
    roles = []
    try:
        instance_profile = client.get_instance_profile(InstanceProfileName=profile_name)
        roles = [ role['RoleName'] for role in instance_profile['InstanceProfile']['Roles'] ]
    except Exception as error:
        print(f"[ERROR] Could not get roles for IAM Instance Profile {profile_name}")
        raise error
    return roles

def __get_attached_role_policies(client, role_name: str):
    policy_names = []
    try:
        role_policies = client.list_attached_role_policies(RoleName=role_name)
        policy_names = [ policy['PolicyName'] for policy in role_policies['AttachedPolicies'] ]
    except Exception as error:
        print(f"[ERROR] Could not get attached Role Policies for IAM Role {role_name}")
        raise error
    return policy_names

def __get_all_managed_policies(client):
    base_kwargs = {'Scope': 'All', 'MaxItems': 1000}
    try:
        kwargs = base_kwargs.copy()
        response = client.list_policies(**kwargs)
        policies = response['Policies']
        while response.get('IsTruncated'):
            kwargs.update({'Marker': response['Marker']})
            response = client.list_policies(**kwargs)
            policies.extend(response['Policies'])
        return policies
    except Exception as error:
        print(f"[ERROR] Could not list IAM policies due to unexpected error: {str(error)}")
        raise error

def get_policy_arns(client, policy_names: list):
    policy_arns = []
    all_managed_policies = __get_all_managed_policies(client)
    for policy in all_managed_policies:
        if policy['PolicyName'] in policy_names:
            policy_arns.append(policy['Arn'])
    return policy_arns

def __attach_missing_role_policies(client, profile_name: str, additional_policy_arns, custom_managed_policy_arn):
    is_policy_attached = True
    try:
        roles = __get_instance_profile_roles(client, profile_name)
        for role in roles:
            attached_role_policies = __get_attached_role_policies(client, role)
            if 'AmazonSSMManagedInstanceCore' not in attached_role_policies:
                print("...Attaching Missing AWS Managed Policy [AmazonSSMManagedInstanceCore]")
                client.attach_role_policy(
                    RoleName=role,
                    PolicyArn='arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
                )
            if 'AmazonSSMManagedEC2InstanceDefaultPolicy' not in attached_role_policies:
                print("...Attaching Missing AWS Managed Policy [AmazonSSMManagedEC2InstanceDefaultPolicy]")
                client.attach_role_policy(
                    RoleName=role,
                    PolicyArn='arn:aws:iam::aws:policy/AmazonSSMManagedEC2InstanceDefaultPolicy'
                )
            if custom_managed_policy_arn:
                access_policy_name = custom_managed_policy_arn.split('/')[-1]
                if access_policy_name not in attached_role_policies:
                    print(f"...Attaching Missing Policy [{access_policy_name}]")
                    client.attach_role_policy(
                        RoleName=role,
                        PolicyArn=custom_managed_policy_arn
                    )

            for policy_arn in additional_policy_arns:
                if policy_arn != "":
                    additional_policy_name = policy_arn.split('/')[-1]
                    if additional_policy_name not in attached_role_policies:
                        print(f"...Attaching Missing Policy [{additional_policy_name}]")
                        client.attach_role_policy(
                            RoleName=role,
                            PolicyArn=policy_arn
                        )
    except Exception as error:
        is_policy_attached = False
        print(f"[ERROR] Could not attach missing policies to already attach IAM Role {profile_name}")
        raise error
    return is_policy_attached

def attach_managed_role_to_ec2(client, instance_id: str, profile_arn: str):
    try:
        client.associate_iam_instance_profile(
            IamInstanceProfile={
                'Arn': profile_arn
            },
            InstanceId=instance_id
        )
    except Exception as error:
        print(f"[ERROR] Could not attach managed IAM Role to EC2 Instance {instance_id}")
        raise error
    return True

def match_policy_with_current_policy(policy_document: json, new_document: json) -> bool:
    if policy_document != new_document:
        return False
    return True

def get_custom_policy_arn(client, account_id: str, json_policy):
    max_retries = 3
    retry_count = 0
    try:
        get_policy_response = client.get_policy(PolicyArn=f"arn:aws:iam::{account_id}:policy/{MANAGED_POLICY_NAME}")
        print(f"The policy {MANAGED_POLICY_NAME} already exists. Checking if it matches the current configuration..")
        get_policy_version_response = client.get_policy_version(
            PolicyArn=get_policy_response['Policy']['Arn'],
            VersionId=get_policy_response['Policy']['DefaultVersionId']
        )
        policy_document = get_policy_version_response['PolicyVersion']['Document']
        if match_policy_with_current_policy(policy_document, json_policy):
            print("Policy matches with the current configuration.")
            return get_policy_response['Policy']['Arn']
        print("Policy does not match with the current configuration. Updating it..")
        while retry_count < max_retries:
            retry_count += 1
            try:
                client.create_policy_version(
                    PolicyArn=get_policy_response['Policy']['Arn'],
                    PolicyDocument=json.dumps(json_policy),
                    SetAsDefault=True
                )
                return get_policy_response['Policy']['Arn']
            except client.exceptions.LimitExceededException:
                print("Policy exceeded version limit. Handling it..")
                policy_datails = {}
                policy_version_response = client.list_policy_versions(PolicyArn=get_policy_response['Policy']['Arn'])
                for version in policy_version_response['Versions']:
                    policy_datails[version['VersionId']] = version['CreateDate']
                sorted_policies_versions = dict(sorted(policy_datails.items(), key=lambda item: item[1], reverse=True))
                latest_version = list(sorted_policies_versions.keys())[0]
                for key in sorted_policies_versions.keys():
                    if key != latest_version:
                        client.delete_policy_version(
                            PolicyArn=get_policy_response['Policy']['Arn'],
                            VersionId=key
                        )
                print(f"Older policy versions deleted successfully. Retrying creating policy version. Attempt: {retry_count}")
    except client.exceptions.NoSuchEntityException:
        print(f"The policy {MANAGED_POLICY_NAME} does not exist, creating...")
        response = client.create_policy(
            PolicyName=MANAGED_POLICY_NAME,
            PolicyDocument=json.dumps(json_policy)
        )
        return response['Policy']['Arn']
    except Exception as error:
        print(f"[ERROR] {str(error)}")
        raise error

def __get_managed_role_name(client, role_name: str):
    try:
        response = client.get_role(RoleName=role_name)
        print(f"Role {role_name} already exists")
        return response['Role']['RoleName']
    except client.exceptions.NoSuchEntityException:
        print(f"Role {role_name} does not exist. Creating...")
        response = client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole"
                    }
                ]
            })
        )
        return response['Role']['RoleName']
    except Exception as error:
        print(f"[ERROR] {str(error)}")
        raise error

def __get_managed_instance_profile_arn(client, role_name: str):
    try:
        response = client.get_instance_profile(InstanceProfileName=role_name)
        print(f"The instance profile {role_name} already exists.")
        return response['InstanceProfile']['Arn']
    except client.exceptions.NoSuchEntityException:
        print(f"The instance profile {role_name} does not exist, creating...")
        response = client.create_instance_profile(InstanceProfileName=role_name)
        client.add_role_to_instance_profile(
            InstanceProfileName=role_name,
            RoleName=role_name
        )
        return response['InstanceProfile']['Arn']
    except Exception as error:
        print(f"[ERROR] {str(error)}")
        raise error

def __get_existing_role_instance_profile_arn(client, role_name: str):
    try:
        response = client.get_instance_profile(InstanceProfileName=role_name)
        return response['InstanceProfile']['Arn']
    except client.exceptions.NoSuchEntityException as error:
        print(f"The instance profile {role_name} does not exist. Automation could not create a new one because Auto-Creation of IAM Roles is disabled.")
        raise error
    except Exception as error:
        print(f"[ERROR] {str(error)}")
        raise error

def instance_role_manager(instance_id: str, account_id: str, region: str, role_name: str, payload, auto_manage_role: bool, existing_role_name: str, auto_attach_missing_policies: bool):
    attach_role = False
    status = 'unknown'
    wait_period = 60
    attached_instance_profiles = []
    instance = {}
    active_session = __assume_role(region, f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE}-{region}")
    ec2_client = active_session.client(service_name='ec2',region_name=region)
    iam_client = active_session.client('iam', region_name=region)
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        if 'Reservations' in response and response['Reservations']:
            if response['Reservations'][0]['Instances']:
                instance = response['Reservations'][0]['Instances'][0]
    except Exception as error:
        print(f"[ERROR] Could not Describe Instances: {str(error)}")
    if instance:
        policy_arns = get_policy_arns(iam_client, ADDITIONAL_POLICIES_NAMES)
        status = instance['State']['Name']
        if 'IamInstanceProfile' in instance:
            profile_id = instance['IamInstanceProfile']['Arn']
            profile_name = profile_id.split('/')[1]
            attached_instance_profiles.append(profile_name)
        if status == 'terminated':
            print(f"Instance {instance_id} has been terminated. Exiting..")
            return
        if status != 'running' and status != 'stopped':
            payload['TaskMarker'] = 'WaitForProperInstanceState'
            payload['WaitTime'] = wait_period
            return
        if status in ['running','stopped']:
            attach_role = True
        if len(attached_instance_profiles) != 0:
            attach_role = False
            print("Attached IAM instance Role found for EC2 instance...")
            if auto_attach_missing_policies:
                custom_access_policy_arn = ''
                if CREATE_NEW_MANAGED_POLICY and ENABLE_EC2_INSTANCE_CONFIGURATOR:
                    custom_access_policy_arn = get_custom_policy_arn(iam_client, account_id, json.loads(MANAGED_POLICY_DOCUMENT_JSON))
                print("Checking attached managed policies...")
                for profile in attached_instance_profiles:
                    if not __attach_missing_role_policies(iam_client, profile, policy_arns, custom_access_policy_arn):
                        print("[ERROR] Could not attach missing Managed Policies")
        if attach_role:
            custom_access_policy_arn = ''
            if CREATE_NEW_MANAGED_POLICY and ENABLE_EC2_INSTANCE_CONFIGURATOR:
                custom_access_policy_arn = get_custom_policy_arn(iam_client, account_id, json.loads(MANAGED_POLICY_DOCUMENT_JSON))
            managed_role_name = ''
            instance_profile_arn = ''
            if auto_manage_role:
                print(f"...Checking if IAM Role {role_name} exists.")
                managed_role_name = __get_managed_role_name(iam_client, role_name)
                instance_profile_arn = __get_managed_instance_profile_arn(iam_client, managed_role_name)
                profile_name = instance_profile_arn.split('/')[1]
                if not __attach_missing_role_policies(iam_client, profile_name, policy_arns, custom_access_policy_arn):
                    print("[ERROR] Could not attach missing Managed Policies")
            else:
                print(f"Auto-creation of IAM Roles is disabled. Attaching Existing Role {existing_role_name}...")
                managed_role_name = existing_role_name
                instance_profile_arn = __get_existing_role_instance_profile_arn(iam_client, existing_role_name)
                profile_name = instance_profile_arn.split('/')[1]
                if auto_attach_missing_policies:
                    if not __attach_missing_role_policies(iam_client, profile_name, policy_arns, custom_access_policy_arn):
                        print("[ERROR] Could not attach missing Managed Policies")
            time.sleep(10)
            if not attach_managed_role_to_ec2(ec2_client, instance_id, instance_profile_arn):
                print(f"[ERROR] Could not attach IAM Role {managed_role_name} to EC2 Instance {instance_id}")
    return

def __get_instance_vpc(client, instance_id):
    vpc_id = None
    try:
        response = client.describe_instances(InstanceIds=[instance_id])
        if 'Reservations' in response and response['Reservations']:
            instance = response['Reservations'][0]['Instances'][0]
            instance_status = instance['State']['Name']
            if instance and instance_status not in ['terminated']:
                vpc_id = instance['VpcId']
    except client.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
            print(f"EC2 Instance {instance_id} not found")
        else:
            raise error
    return vpc_id

def __get_vpc_cidr(client, vpc_id: str):
    vpc_cidr = ''
    try:
        response = client.describe_vpcs(VpcIds=[vpc_id])
        vpc_cidr = response['Vpcs'][0]['CidrBlock']
    except Exception as error:
        print(f"[ERROR] Could not get VPC CIDR for VPC {vpc_id}")
        raise error
    return vpc_cidr

def __get_managed_sg_id(client, vpc_id: str, sg_name: str):
    group_id = ''
    try:
        check_if_sg_exists = client.describe_security_groups(
            Filters=[{
                'Name': 'vpc-id',
                'Values': [vpc_id]
            },{
                'Name': 'group-name',
                'Values': [sg_name]
            }]
        )['SecurityGroups']
        if len(check_if_sg_exists) == 0:
            print("...Creating new Security Group for VPC Endpoints")
            vpc_cidr = __get_vpc_cidr(client, vpc_id)
            if vpc_cidr:
                new_sg = client.create_security_group(
                    Description='Security Group for VPC Endpoint',
                    GroupName=sg_name,
                    VpcId=vpc_id
                )
                client.authorize_security_group_ingress(
                    GroupId=new_sg['GroupId'],
                    IpPermissions=[{
                        'FromPort': 443,
                        'IpProtocol': 'tcp',
                        'IpRanges': [{
                            'CidrIp': vpc_cidr,
                            'Description': 'Allow HTTPS within VPC CIDR',
                        }],
                        'ToPort': 443,
                    }]
                )
                group_id = new_sg['GroupId']
            else:
                print(f"[ERROR] Could not get VPC CIDR for VPC {vpc_id}")
        else:
            print("Security Group already exists. Not Creating a new one.")
            group_id = check_if_sg_exists[0]['GroupId']
    except Exception as error:
        print(f"[ERROR] Could not get Security Group ID for VPC Endpoint for VPC {vpc_id}")
        raise error
    return group_id

def __get_vpc_endpoint_details(client, vpc_id: str, service_name: str):
    endpoint_details = {}
    try:
        results = client.describe_vpc_endpoints(
            Filters=[{
                'Name': 'vpc-id',
                'Values': [vpc_id]
            },{
                'Name': 'service-name',
                'Values': [service_name]
            },{
                'Name': 'vpc-endpoint-type',
                'Values': ['Interface']
            }]
        )['VpcEndpoints']
        if len(results) > 0:
            endpoint_details = results[0]
    except Exception as error:
        print(f"[ERROR] Could not get details for VPC Endpoint for Service {service_name} in VPC {vpc_id}")
        raise error
    return endpoint_details

def __modify_endpoint_attributes(client, region: str, endpoint_id: str, service_name: str, group_id: str):
    try:
        if service_name == f'com.amazonaws.{region}.s3':
            client.modify_vpc_endpoint(
                VpcEndpointId=endpoint_id,
                AddSecurityGroupIds=[group_id],
                PrivateDnsEnabled=True,
                DnsOptions={
                    'DnsRecordIpType': 'ipv4',
                    'PrivateDnsOnlyForInboundResolverEndpoint': False
                }
            )
        else:
            client.modify_vpc_endpoint(
                VpcEndpointId=endpoint_id,
                AddSecurityGroupIds=[group_id],
                PrivateDnsEnabled=True
            )
    except Exception as error:
        print(f"[ERROR] Could not modify VPC Endpoint Attributes for endpoint {endpoint_id}")
        raise error
    return True

def __get_private_subnets(client, vpc_id: str):
    private_subnet_ids = []
    subnets = {}
    try:
        response = client.describe_subnets(
            Filters=[{
                'Name': 'vpc-id',
                'Values': [vpc_id]
            }]
        )
        for subnet in response['Subnets']:
            if not subnet['MapPublicIpOnLaunch']:
                az = subnet['AvailabilityZone']
                if az not in subnets:
                    subnets[az] = subnet['SubnetId']
        for az, subnet_id in subnets.items():
            private_subnet_ids.append(subnet_id)
    except Exception as error:
        print(f"[ERROR] Could not get Private Subnets for VPC {vpc_id}")
        raise error
    return private_subnet_ids

def __create_vpc_endpoint(client, region: str, vpc_id: str, service_name: str, group_id: str):
    try:
        private_subnets = __get_private_subnets(client, vpc_id)
        if service_name == f'com.amazonaws.{region}.s3':
            client.create_vpc_endpoint(
                VpcEndpointType='Interface',
                VpcId=vpc_id,
                ServiceName=service_name,
                SubnetIds=private_subnets,
                SecurityGroupIds=[group_id],
                DnsOptions={
                    'DnsRecordIpType': 'ipv4',
                    'PrivateDnsOnlyForInboundResolverEndpoint': False
                },
                IpAddressType='ipv4',
                PrivateDnsEnabled=True
            )
        else:
            client.create_vpc_endpoint(
                VpcEndpointType='Interface',
                VpcId=vpc_id,
                ServiceName=service_name,
                SubnetIds=private_subnets,
                SecurityGroupIds=[group_id],
                IpAddressType='ipv4',
                PrivateDnsEnabled=True
            )
    except Exception as error:
        print(f"[ERROR] Could not create VPC Endpoint for Service {service_name}")
        raise error
    return True

def vpc_endpoint_manager(account_id: str, region: str, sg_name: str, vpc_endpoints, instance_id: str, payload):
    endpoint_services = [f'com.amazonaws.{region}.ssm', f'com.amazonaws.{region}.ec2messages', f'com.amazonaws.{region}.ssmmessages']
    if ENABLE_EC2_INSTANCE_CONFIGURATOR:
        endpoint_services.append(f'com.amazonaws.{region}.s3')
    if vpc_endpoints:
        if len(vpc_endpoints) != 1 and vpc_endpoints[0] != "":
            endpoint_services.extend(vpc_endpoints)
    wait_period = 60
    try:
        active_session = __assume_role(region, f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE}-{region}")
        ec2_client = active_session.client(service_name='ec2',region_name=region)
        vpc_id = __get_instance_vpc(ec2_client, instance_id)

        if vpc_id is not None:
            group_id = __get_managed_sg_id(ec2_client, vpc_id, sg_name)
            for svc in endpoint_services:
                endpoint_details = __get_vpc_endpoint_details(ec2_client, vpc_id, svc)
                if endpoint_details:
                    endpoint_group_ids = [ group['GroupId'] for group in endpoint_details['Groups'] ]
                    if not endpoint_details['PrivateDnsEnabled'] or group_id not in endpoint_group_ids:
                        if not __modify_endpoint_attributes(ec2_client, region, endpoint_details['VpcEndpointId'], svc, group_id):
                            print(f"[ERROR] Could not modify attributes for VPC Endpoint {endpoint_details['VpcEndpointId']}")
                else:
                    if not __create_vpc_endpoint(ec2_client, region, vpc_id, svc, group_id):
                        print(f"Could not create VPC Endpoint for Service {svc}")
            state = None
            for svc in endpoint_services:
                payload['WaitTime'] = 0
                payload['TaskMarker'] = 'Initialize'
                state = __get_vpc_endpoint_details(ec2_client, vpc_id, svc)['State']
                if state not in ['available', 'Available']:
                    payload['TaskMarker'] = 'WaitForEndpointAvailableState'
                    payload['WaitTime'] = wait_period
                    return
    except Exception as error:
        print(f"[ERROR] {str(error)}")
        raise error
    return
