import os
import re
import json
import time
import helper
import openpyxl
from openpyxl.styles import Font
import boto3
from botocore.exceptions import ClientError

PROCESS_ID = os.getenv('PROCESS_ID')
USER_ID = os.getenv('USER_ID')
USER_NAME = os.getenv('USERNAME')
ACCOUNT_ID = os.getenv('ACCOUNT_ID')
REGION = os.getenv('REGION')
CROSS_ACCOUNT_ROLE = os.getenv('CROSS_ACCOUNT_ROLE')
SSO_CROSS_ACCOUNT_ASSUME_ROLE_ARN = os.getenv('SSO_CROSS_ACCOUNT_ASSUME_ROLE_ARN')
BUCKET_NAME = os.getenv('BUCKET_NAME')
MAX_RETRIES = 5
RETRY_DELAY = 5
CLOUDTRAIL_THROTTLE_PERIOD = 0.5

def main():
    header = [ 'AWSRegion', 'ResourceType', 'ResourceName' ]

    object_key = f'{PROCESS_ID}/{USER_ID}/{ACCOUNT_ID}/{REGION}.xlsx'
    filename = f'/tmp/{USER_ID}_{ACCOUNT_ID}_{REGION}.xlsx'

    print(f"Generating Report for Account {ACCOUNT_ID} and Region {REGION}")
    resources = get_account_resources(ACCOUNT_ID, REGION, USER_NAME)
    if len(resources) > 0:
        workbook = openpyxl.Workbook()
        worksheet1 = workbook.active
        worksheet1.title = ACCOUNT_ID
        worksheet1.append(header)
        for cell in worksheet1[1]:
            cell.font = Font(bold=True)
        for item in resources:
            resource_type, resource_name = item.split('|')
            worksheet1.append([REGION, resource_type, resource_name])
        workbook.save(filename)

        store_report(filename, BUCKET_NAME, object_key)
        print(f"Stored report {object_key} to S3 Bucket")
    else:
        print("No Report was generated because no resources found.")

def store_report(file_path, bucket_name, object_key) -> bool:
    s3_res = boto3.resource('s3')
    try:
        s3_res.meta.client.upload_file(file_path, bucket_name, object_key)
    except Exception as error:
        print(f"Could not store Report to S3 Bucket: {str(error)}")
        raise error
    return True

def __assume_role(region, arn):
    sts = boto3.client('sts', region_name=region)
    response = sts.assume_role(RoleArn=arn, RoleSessionName='events_alert')
    session = boto3.Session(aws_access_key_id=response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                    aws_session_token=response['Credentials']['SessionToken'])
    return session

def __get_management_account_id():
    match = re.search(r'([0-9]{12})', SSO_CROSS_ACCOUNT_ASSUME_ROLE_ARN)
    return match.group(0)

def match_delete_event_pattern_re(event_name):
    delete_events_re = [
        "^BatchDelete",
        "^Detach",
        "^Delete",
        "^Deregister",
        "^Terminate",
        "^Remove",
        "^Release"
    ]
    try:
        for expression in delete_events_re:
            match = re.search(expression, event_name)
            if match is not None:
                return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_ignore_event_pattern_re(event_name):
    ignore_events_re = [
        "^Authenticate",
        "^Federate",
        "^AddPermission",
        "^PutObject",
        "^PutBucket",
        "^PutRolePolicy",
        "^PutEvaluations",
        "^PutImage",
        "^PutAccountPublicAccessBlock",
        "^PutCredentials",
        "^CreateGrant",
        "^CreateLogStream",
        "^CreateChangeSet",
        "^ConsoleLogin",
        "^Start",
        "^Initiate",
        "^Stop",
        "^UploadLayerPart",
        "^List",
        "^Describe",
        "^CompleteLayerUpload",
        "^Send",
        "^Update",
        "^Publish",
        "^CreateEnvironment",
        "SubscriptionFilter",
        "^RetireGrant",
        "^RunTask",
        "^SubmitJob",
        "^CreateAddon",
        "^(En|Dis)able",
        "(T|t)ag"
    ]
    try:
        for expression in ignore_events_re:
            match = re.search(expression, event_name)
            if match is not None:
                return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_ignore_resource_type(resource_type):
    ignore_resource_type = [
        "AWS::TrustedAdvisor::Checks"
    ]
    try:
        if resource_type in ignore_resource_type:
            return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_api_resource_type(resource_type):
    api_resource_type = [
        "AWS::ApiGateway::ApiKey",
        "AWS::ApiGateway::Authorizer",
        "AWS::ApiGateway::DomainName",
        "AWS::ApiGateway::RestApi",
        "AWS::ApiGateway::UsagePlan",
        "AWS::ApiGateway::VpcLink",
        "AWS::ApiGatewayV2::Api",
        "AWS::ApiGatewayV2::Authorizer",
        "AWS::ApiGatewayV2::DomainName",
        "AWS::ApiGatewayV2::VpcLink"
    ]
    try:
        if resource_type in api_resource_type:
            return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_ec2_resource_type(resource_type):
    ec2_resource_type = [
        "AWS::EC2::Ami",
        "AWS::EC2::CarrierGateway",
        "AWS::EC2::CustomerGateway",
        "AWS::EC2::EIP",
        "AWS::EC2::FlowLog",
        "AWS::EC2::Instance",
        "AWS::EC2::InternetGateway",
        "AWS::EC2::KeyPair",
        "AWS::EC2::LaunchTemplate",
        "AWS::EC2::LocalGatewayRouteTable",
        "AWS::EC2::NatGateway",
        "AWS::EC2::NetworkAcl",
        "AWS::EC2::NetworkInterface",
        "AWS::EC2::ReservedInstance",
        "AWS::EC2::RouteTable",
        "AWS::EC2::SecurityGroup",
        "AWS::EC2::Snapshot",
        "AWS::EC2::Subnet",
        "AWS::EC2::Volume",
        "AWS::EC2::VPC",
        "AWS::EC2::VPCEndpoint",
        "AWS::EC2::VPCPeeringConnection",
        "AWS::EC2::VPNConnection",
        "AWS::EC2::VPNGateway"
    ]
    try:
        if resource_type in ec2_resource_type:
            return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_s3_resource_type(resource_type):
    s3_resource_type = [
        "AWS::S3::AccessPoint",
        "AWS::S3::Bucket"
    ]
    try:
        if resource_type in s3_resource_type:
            return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_app_mesh_resource_type(resource_type):
    app_mesh_resource_type = [
        "AWS::AppMesh::Mesh",
        "AWS::AppMesh::VirtualGateway",
        "AWS::AppMesh::VirtualNode",
        "AWS::AppMesh::VirtualRouter",
        "AWS::AppMesh::VirtualService"
    ]
    try:
        if resource_type in app_mesh_resource_type:
            return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_app_runner_resource_type(resource_type):
    app_runner_resource_type = [
        "AWS::AppRunner::AutoScalingConfiguration",
        "AWS::AppRunner::ObservabilityConfiguration",
        "AWS::AppRunner::Service",
        "AWS::AppRunner::VpcConnector",
        "AWS::AppRunner::VpcIngressConnection",
        "AWS::AppRunner::Connection"
    ]
    try:
        if resource_type in app_runner_resource_type:
            return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_ec2_autoscaling_resource_type(resource_type):
    ec2_autoscaling_resource_type = [
        "AWS::AutoScaling::AutoScalingGroup",
        "AWS::AutoScaling::LaunchConfiguration",
        "AWS::AutoScaling::ScalingPolicy",
        "AWS::AutoScaling::ScheduledAction"
    ]
    try:
        if resource_type in ec2_autoscaling_resource_type:
            return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_backup_resource_type(resource_type):
    backup_resource_type = [
        "AWS::Backup::BackupPlan",
        "AWS::Backup::BackupSelection",
        "AWS::Backup::BackupVault",
        "AWS::Backup::Framework",
        "AWS::Backup::ReportPlan"
    ]
    try:
        if resource_type in backup_resource_type:
            return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_cloudtrail_resource_type(resource_type):
    cloudtrail_resource_type = [
        "AWS::CloudTrail::Channel",
        "AWS::CloudTrail::EventDataStore",
        "AWS::CloudTrail::Trail"
    ]
    try:
        if resource_type in cloudtrail_resource_type:
            return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_rds_resource_type(resource_type):
    rds_resource_type = [
        "AWS::RDS::DBCluster",
        "AWS::RDS::DBClusterParameterGroup",
        "AWS::RDS::DBClusterSnapshot",
        "AWS::RDS::DBInstance",
        "AWS::RDS::DBOptionGroup",
        "AWS::RDS::DBParameterGroup",
        "AWS::RDS::DBProxy",
        "AWS::RDS::DBSnapshot",
        "AWS::RDS::DBSubnetGroup"
    ]
    try:
        if resource_type in rds_resource_type:
            return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_ecs_resource_type(resource_type):
    ecs_resource_type = [
        "AWS::ECS::Cluster",
        "AWS::ECS::Service",
        "AWS::ECS::TaskDefinition"
    ]
    try:
        if resource_type in ecs_resource_type:
            return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_efs_resource_type(resource_type):
    efs_resource_type = [
        "AWS::EFS::AccessPoint",
        "AWS::EFS::FileSystem",
        "AWS::EFS::MountTarget"
    ]
    try:
        if resource_type in efs_resource_type:
            return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_eks_resource_type(resource_type):
    eks_resource_type = [
        "AWS::EKS::Cluster",
        "AWS::EKS::Nodegroup"
    ]
    try:
        if resource_type in eks_resource_type:
            return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_elbv2_resource_type(resource_type):
    elbv2_resource_type = [
        "AWS::ElasticLoadBalancingV2::LoadBalancer",
        "AWS::ElasticLoadBalancingV2::TargetGroup",
        "AWS::ElasticLoadBalancingV2::Listener"
    ]
    try:
        if resource_type in elbv2_resource_type:
            return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_scheduler_resource_type(resource_type):
    scheduler_resource_type = [
        "AWS::Scheduler::Schedule",
        "AWS::Scheduler::ScheduleGroup"
    ]
    try:
        if resource_type in scheduler_resource_type:
            return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_schema_resource_type(resource_type):
    schema_resource_type = [
        "AWS::EventSchemas::Registry",
        "AWS::EventSchemas::Schema"
    ]
    try:
        if resource_type in schema_resource_type:
            return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_sns_resource_type(resource_type):
    sns_resource_type = [
        "AWS::SNS::Subscription",
        "AWS::SNS::Topic"
    ]
    try:
        if resource_type in sns_resource_type:
            return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_route53_resource_type(resource_type):
    route53_resource_type = [
        "AWS::Route53::HostedZone",
        "AWS::Route53::HealthCheck"
    ]
    try:
        if resource_type in route53_resource_type:
            return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_network_firewall_resource_type(resource_type):
    network_firewall_resource_type = [
        "AWS::Route53::HostedZone",
        "AWS::Route53::HealthCheck"
    ]
    try:
        if resource_type in network_firewall_resource_type:
            return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_redshift_resource_type(resource_type):
    redshift_resource_type = [
        "AWS::Redshift::Cluster",
    ]
    try:
        if resource_type in redshift_resource_type:
            return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_image_builder_resource_type(resource_type):
    image_builder_resource_type = [
        "AWS::ImageBuilder::Image",
        "AWS::ImageBuilder::ImageRecipe",
        "AWS::ImageBuilder::Component",
        "AWS::ImageBuilder::ContainerRecipe"
        "AWS::ImageBuilder::ImagePipeline",
        "AWS::ImageBuilder::InfrastructureConfiguration"
    ]
    try:
        if resource_type in image_builder_resource_type:
            return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def match_create_event_pattern_re(event_name):
    create_events_re = [
        "^Allocate",
        "^Authorize",
        "^Create",
        "^Register",
        "^Import",
        "^Request",
        "^Put",
        "^Run"
    ]
    try:
        for expression in create_events_re:
            match = re.search(expression, event_name)
            if match is not None:
                return True
    except Exception as error:
        print(f"[ERROR] {str(error)}")
    return False

def cloudtrail_lookup(role_arn, region, kwargs):
    lookup = {}
    for i in range(MAX_RETRIES):
        try:
            active_session = __assume_role(region, role_arn)
            cloudtrail = active_session.client(service_name='cloudtrail',region_name=region)
            lookup = cloudtrail.lookup_events(**kwargs)
            break
        except ClientError as error:
            if error.response['Error']['Code'] == 'ThrottlingException':
                print(f'API call throttled. Waiting for {RETRY_DELAY} seconds and retrying...')
                time.sleep(RETRY_DELAY)
            else:
                print(f"[ERROR] {str(error)}")
    return lookup

def get_account_resources(account_id, region, username) -> list:
    created_resources = []
    deleted_resources = []

    try:
        role_arn = SSO_CROSS_ACCOUNT_ASSUME_ROLE_ARN if account_id == __get_management_account_id() else f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE}-{region}"
        next_token = ''
        base_kwargs = {
            'LookupAttributes': [{
                'AttributeKey': 'Username',
                'AttributeValue': username
            }]
        }
        while next_token is not None:
            kwargs = base_kwargs.copy()
            if next_token != '':
                kwargs.update({'NextToken': next_token})
            lookup = cloudtrail_lookup(role_arn, region, kwargs)
            next_token = lookup.get('NextToken')

            for event in [e for e in lookup.get('Events', []) if e.get('ReadOnly') == 'false']:
                delete_event = match_delete_event_pattern_re(event['EventName'])
                ignore_event = match_ignore_event_pattern_re(event['EventName'])

                if ignore_event:
                    break
                if not delete_event:
                    cloudtrail_event = json.loads(event['CloudTrailEvent'])
                    event_source = event['EventSource'].split('.')[0]
                    if len(event['Resources']) > 0:
                        for resource in event['Resources']:
                            if 'ResourceType' in resource and 'ResourceName' in resource:
                                if match_ignore_resource_type(resource['ResourceType']):
                                    break
                                if match_create_event_pattern_re(event['EventName']):
                                    if resource['ResourceType'].startswith(('AWS::IAM::', 'AWS::DynamoDB::Table', 'AWS::KMS::Key', 'AWS::ECR::Repository', 'AWS::ElasticLoadBalancing::LoadBalancer')) or match_app_mesh_resource_type(resource['ResourceType']) or match_efs_resource_type(resource['ResourceType']) or match_elbv2_resource_type(resource['ResourceType']) or match_image_builder_resource_type(resource['ResourceType']):
                                        if not is_iam_id(resource['ResourceName']) and not is_dynamodb_kms_appmesh_id(resource['ResourceName']) and not resource['ResourceName'].startswith(('arn:aws:', 'AWSReservedSSO_')):
                                            resource_name = resource['ResourceName'].replace(' ', '')
                                            arg1 = ''
                                            if resource['ResourceType'] == 'AWS::IAM::SshPublicKey':
                                                if 'responseElements' in cloudtrail_event and 'sSHPublicKey' in cloudtrail_event['responseElements']:
                                                    arg1 = cloudtrail_event['responseElements']['sSHPublicKey']['userName']
                                            elif resource['ResourceType'] in ['AWS::AppMesh::VirtualNode', 'AWS::AppMesh::VirtualService', 'AWS::AppMesh::VirtualRouter', 'AWS::AppMesh::VirtualGateway']:
                                                if 'responseElements' in cloudtrail_event:
                                                    mesh_name_match = re.search(r"meshName([A-Za-z0-9 /_&^'%*()$#@!+=:-]+)", str(cloudtrail_event['responseElements']))
                                                    if mesh_name_match is not None:
                                                        arg1 = mesh_name_match.group(0).replace("'","").split(" ")[1]
                                            if helper.resource_exists(role_arn, region, resource['ResourceType'], arg1, resource_name):
                                                if f"{resource['ResourceType']}|{resource_name}" not in created_resources:
                                                    created_resources.append(f"{resource['ResourceType']}|{resource_name}")
                                        else:
                                            if resource['ResourceType'] == 'AWS::ElasticLoadBalancingV2::Listener':
                                                if helper.resource_exists(role_arn, region, resource['ResourceType'], '', resource['ResourceName']):
                                                    if f"{resource['ResourceType']}|{resource['ResourceName']}" not in created_resources:
                                                        created_resources.append(f"{resource['ResourceType']}|{resource['ResourceName']}")
                                    elif match_api_resource_type(resource['ResourceType']):
                                        api_id = get_api_id(str(cloudtrail_event['requestParameters']))
                                        if helper.resource_exists(role_arn, region, resource['ResourceType'], api_id, resource['ResourceName']):
                                            if f"{resource['ResourceType']}|{resource['ResourceName']}" not in created_resources:
                                                created_resources.append(f"{resource['ResourceType']}|{resource['ResourceName']}")
                                    elif match_ec2_resource_type(resource['ResourceType']):
                                        resource_type = resource['ResourceType']
                                        resource_name = resource['ResourceName']
                                        if resource_type == 'AWS::EC2::LaunchTemplate':
                                            resource_name = resource_name if resource_name.startswith('lt-') else ''
                                        elif resource_type == 'AWS::EC2::EIP':
                                            resource_name = resource_name if resource_name.startswith('eipalloc-') else ''
                                        elif resource_type == 'AWS::EC2::SecurityGroup':
                                            resource_name = resource_name if resource_name.startswith('sg-') else ''
                                        elif resource_type == 'AWS::EC2::Instance':
                                            resource_name = resource_name if resource_name.startswith('i-') else ''
                                        if resource_name:
                                            if helper.resource_exists(role_arn, region, resource_type, '', resource_name):
                                                if f"{resource_type}|{resource_name}" not in created_resources:
                                                    created_resources.append(f"{resource_type}|{resource_name}")
                                    elif resource['ResourceType'] in ['AWS::CertificateManager::Certificate', 'AWS::AutoScalingPlans::ScalingPlan', 'AWS::CloudFormation::Stack', 'AWS::CloudWatch::Alarm', 'AWS::CodePipeline::Pipeline', 'AWS::SecretsManager::Secret', 'AWS::Lambda::Function'] or match_ec2_autoscaling_resource_type(resource['ResourceType']) or match_s3_resource_type(resource['ResourceType']) or match_sns_resource_type(resource['ResourceType']) or match_route53_resource_type(resource['ResourceType']):
                                        arg1 = ''
                                        if resource['ResourceType'] == 'AWS::S3::AccessPoint':
                                            arg1 = account_id
                                        if helper.resource_exists(role_arn, region, resource['ResourceType'], arg1, resource['ResourceName']):
                                            created_resources.append(f"{resource['ResourceType']}|{resource['ResourceName']}")
                                    elif match_app_runner_resource_type(resource['ResourceType']) or match_cloudtrail_resource_type(resource['ResourceType']) or match_network_firewall_resource_type(resource['ResourceType']):
                                        if resource['ResourceType'] == 'AWS::AppRunner::Connection':
                                            if not resource['ResourceName'].startswith('arn:aws:'):
                                                if helper.resource_exists(role_arn, region, resource['ResourceType'], '', resource['ResourceName']):
                                                    if f"{resource['ResourceType']}|{resource['ResourceName']}" not in created_resources:
                                                        created_resources.append(f"{resource['ResourceType']}|{resource['ResourceName']}")
                                        else:
                                            if resource['ResourceName'].startswith('arn:aws:'):
                                                if helper.resource_exists(role_arn, region, resource['ResourceType'], '', resource['ResourceName']):
                                                    if f"{resource['ResourceType']}|{resource['ResourceName']}" not in created_resources:
                                                        created_resources.append(f"{resource['ResourceType']}|{resource['ResourceName']}")
                                    elif match_backup_resource_type(resource['ResourceType']) or match_ecs_resource_type(resource['ResourceType']) or match_eks_resource_type(resource['ResourceType']) or match_scheduler_resource_type(resource['ResourceType']) or match_schema_resource_type(resource['ResourceType']) or resource['ResourceType'] in ['AWS::Pipes::Pipe', 'AWS::SQS::Queue']:
                                        arg1 = ''
                                        resource_name = resource['ResourceName']
                                        if 'requestParameters' in cloudtrail_event and cloudtrail_event['requestParameters'] is not None and cloudtrail_event['requestParameters'] != 'None':
                                            if resource['ResourceType'] in ['AWS::Backup::BackupSelection']:
                                                arg1 = cloudtrail_event['requestParameters']['backupPlanId']
                                            elif resource['ResourceType'] in ['AWS::ECS::Service']:
                                                arg1 = cloudtrail_event['requestParameters']['cluster']
                                            elif resource['ResourceType'] in ['AWS::Scheduler::Schedule']:
                                                resource_name = cloudtrail_event['requestParameters']['name']
                                            elif resource['ResourceType'] in ['AWS::EventSchemas::Schema']:
                                                arg1 = cloudtrail_event['requestParameters']['registryName']
                                            elif resource['ResourceType'] in ['AWS::SQS::Queue']:
                                                resource_name = cloudtrail_event['requestParameters']['queueName']
                                        if 'responseElements' in cloudtrail_event and cloudtrail_event['responseElements'] is not None and cloudtrail_event['responseElements'] != 'None':
                                            if resource['ResourceType'] in ['AWS::EKS::Nodegroup']:
                                                arg1 = cloudtrail_event['responseElements']['nodegroup']['clusterName']
                                            elif resource['ResourceType'] in ['AWS::Pipes::Pipe']:
                                                resource_name = cloudtrail_event['responseElements']['Name']
                                        if helper.resource_exists(role_arn, region, resource['ResourceType'], arg1, resource_name):
                                            if f"{resource['ResourceType']}|{resource_name}" not in created_resources:
                                                created_resources.append(f"{resource['ResourceType']}|{resource_name}")
                                    elif match_rds_resource_type(resource['ResourceType']):
                                        resource_type = resource['ResourceType']
                                        arg1 = ''
                                        if 'requestParameters' in cloudtrail_event and cloudtrail_event['requestParameters'] is not None and cloudtrail_event['requestParameters'] != 'None' and 'engine' in cloudtrail_event['requestParameters']:
                                            if cloudtrail_event['requestParameters']['engine'] == 'docdb':
                                                if event['EventName'] == 'CreateDBCluster' and resource_type == 'AWS::RDS::DBCluster':
                                                    resource_type = 'AWS::DocDB::DBCluster'
                                                elif event['EventName'] == 'CreateDBInstance' and resource_type == 'AWS::RDS::DBInstance':
                                                    resource_type = 'AWS::DocDB::DBInstance'
                                            else:
                                                if event['EventName'] == 'CreateDBClusterParameterGroup' and 'docdb' in cloudtrail_event['requestParameters']['dBParameterGroupFamily'] and resource_type == 'AWS::RDS::DBClusterParameterGroup':
                                                    resource_type = 'AWS::DocDB::DBClusterParameterGroup'
                                        if helper.resource_exists(role_arn, region, resource_type, arg1, resource['ResourceName']):
                                            if f"{resource_type}|{resource['ResourceName']}" not in created_resources:
                                                created_resources.append(f"{resource_type}|{resource['ResourceName']}")
                    else:
                        resource_type = helper.get_resource_type(event['EventName'])
                        if resource_type is not None:
                            if event_source in ['appconfig', 'codeartifact', 'codebuild', 'codestar-notifications', 'cognito-identity', 'cognito-idp', 'docdb-elastic', 'ec2', 'fsx', 'states', 'sso', 'ram', 'sso-directory']:
                                if 'responseElements' in cloudtrail_event and cloudtrail_event['responseElements'] is not None and cloudtrail_event['responseElements'] != 'None':
                                    response_elements = cloudtrail_event['responseElements']
                                    arg1 = ''
                                    pattern = r"(Name|name)([A-Za-z0-9 /_&^'%*()$#@!+=:-]+)"
                                    if event_source in ['appconfig'] or event['EventName'] == 'CreateUserPool':
                                        pattern = r"(Id|id)([A-Za-z0-9 /_&^'%*()$#@!+=:-]+)"
                                    if event['EventName'] == 'CreateRepository':
                                        if 'repository' in response_elements:
                                            arg1 = response_elements['repository']['domainName']
                                    elif event['EventName'] in ['CreateNotificationRule', 'CreateActivity', 'CreateStateMachine', 'CreatePermissionSet', 'CreateResourceShare'] or event_source == 'docdb-elastic':
                                        pattern = r"Arn([A-Za-z0-9 /_&^'%*()$#@!+=:-]+)"
                                        if event['EventName'] == 'CreatePermissionSet':
                                            arg1 = cloudtrail_event['requestParameters']['instanceArn']
                                    elif event['EventName'] == 'CreateIdentityPool':
                                        pattern = r"identityPoolId([a-z0-9 ':-]+)"
                                    elif event['EventName'] == 'CreateGroup' and event_source == 'sso-directory':
                                        pattern = r"groupId([a-z0-9 ':-]+)"
                                        arg1 = cloudtrail_event['requestParameters']['identityStoreId']
                                    elif event['EventName'] == 'CreateUserPoolClient':
                                        pattern = r"clientId([a-z0-9 :']+)"
                                        if 'userPoolClient' in response_elements:
                                            arg1 = response_elements['userPoolClient']['userPoolId']
                                    elif event_source == 'ec2':
                                        if event['EventName'] == 'CreateTransitGateway':
                                            pattern = r"transitGatewayId([a-z0-9 :'-]+)"
                                        elif event['EventName'] == 'CreateTransitGatewayVpcAttachment':
                                            pattern = r"AttachmentId([a-z0-9 :'-]+)"
                                        elif event['EventName'] == 'CreateTransitGatewayRouteTable':
                                            pattern = r"RouteTableId([a-z0-9 :'-]+)"
                                        elif event['EventName'] == 'CreateVpcEndpointServiceConfiguration':
                                            pattern = r"serviceName([a-z0-9 .:'-]+)"
                                    elif event_source == 'fsx':
                                        if event['EventName'] == 'CreateFileSystem':
                                            pattern = r"fileSystemId([a-z0-9 .:'-]+)"
                                    match = re.search(pattern, str(response_elements))
                                    if match is not None:
                                        resource_name = match.group(0).replace("'","").split(" ")[1]
                                        if helper.resource_exists(role_arn, region, resource_type, arg1, resource_name):
                                            if f"{resource_type}|{resource_name}" not in created_resources:
                                                created_resources.append(f"{resource_type}|{resource_name}")
                            elif event_source in ['s3']:
                                if 'additionalEventData' in cloudtrail_event and cloudtrail_event['additionalEventData'] is not None and cloudtrail_event['additionalEventData'] != 'None':
                                    name_match = re.search(r"(Name|name)([A-Za-z0-9 /_&^'%*()$#@!+=:-]+)", str(cloudtrail_event['additionalEventData']))
                                    if name_match is not None:
                                        resource_name = name_match.group(0).replace("'","").split(" ")[1]
                                        if helper.resource_exists(role_arn, region, resource_type, '', resource_name):
                                            if f"{resource_type}|{resource_name}" not in created_resources:
                                                created_resources.append(f"{resource_type}|{resource_name}")
                            elif event_source in ['ssm', 'athena', 'cloudformation', 'cloudfront', 'cloudwatch', 'logs', 'codecommit', 'codedeploy', 'dax', 'ds', 'dms', 'elasticbeanstalk', 'elasticache', 'events', 'waf' ,'wafv2', 'sqs', 'glue']:
                                if event['EventName'] in ['CreateNamedQuery', 'CreateDistribution', 'CreateDirectory', 'CreateCacheCluster', 'CreateReplicationGroup'] and event['EventName'] not in ['CreateDeploymentGroup']:
                                    if 'responseElements' in cloudtrail_event and cloudtrail_event['responseElements'] is not None and cloudtrail_event['responseElements'] != 'None':
                                        response_elements = cloudtrail_event['responseElements']
                                        pattern = r"(Id|id)([A-Za-z0-9 /_&^'%*()$#@!+=:-]+)"
                                        if event_source == 'waf':
                                            if event['EventName'] == 'CreateRegexPatternSet':
                                                resource_type = 'AWS::WAF::RegexPatternSet'
                                            elif event['EventName'] == 'CreateRuleGroup':
                                                resource_type = 'AWS::WAF::RuleGroup'
                                        id_match = re.search(pattern, str(response_elements))
                                        if id_match is not None:
                                            resource_name = id_match.group(0).replace("'","").split(" ")[1]
                                            if helper.resource_exists(role_arn, region, resource_type, '', resource_name):
                                                if f"{resource_type}|{resource_name}" not in created_resources:
                                                    created_resources.append(f"{resource_type}|{resource_name}")
                                else:
                                    if 'requestParameters' in cloudtrail_event and cloudtrail_event['requestParameters'] is not None and cloudtrail_event['requestParameters'] != 'None':
                                        request_params = cloudtrail_event['requestParameters']
                                        arg1 = ''
                                        pattern = r"(Name|name)([A-Za-z0-9 /_&^'%*()$#@!+=:-]+)"
                                        if event_source == 'codecommit':
                                            if event['EventName'] == 'CreateRepository':
                                                resource_type = 'AWS::CodeCommit::Repository'
                                        elif resource_type == 'AWS::CloudFormation::StackSet':
                                            arg1 = 'DELEGATED_ADMIN' if cloudtrail_event['requestParameters']['permissionModel'] == 'SERVICE_MANAGED' else 'SELF'
                                        elif resource_type == 'AWS::Glue::Table':
                                            arg1 = cloudtrail_event['requestParameters']['databaseName']
                                            pattern = r"name([A-Za-z0-9 /_&^'%*()$#@!+=:-]+)"
                                        elif event['EventName'] in ['PutSubscriptionFilter']:
                                            arg1 = cloudtrail_event['requestParameters']['logGroupName']
                                            pattern = r"filterName([A-Za-z0-9 /_&^'%*()$#@!+=:-]+)"
                                        elif event['EventName'] == 'CreateEmailIdentity':
                                            pattern = r"emailIdentity([A-Za-z0-9 /_&^'.%*()$#@!+=:-]+)"
                                            arg1 = cloudtrail_event['responseElements']['identityType']
                                        elif event_source == 'codedeploy':
                                            if event['EventName'] == 'CreateApplication':
                                                resource_type = 'AWS::CodeDeploy::Application'
                                            elif event['EventName'] == 'CreateDeploymentGroup':
                                                arg1 = cloudtrail_event['requestParameters']['applicationName']
                                                pattern = r"deploymentGroupName([A-Za-z0-9 /_&^'%*()$#@!+=:-]+)"
                                        elif event_source == 'elasticbeanstalk':
                                            if event['EventName'] == 'CreateApplication':
                                                resource_type = 'AWS::ElasticBeanstalk::Application'
                                            elif event['EventName'] == 'CreateEnvironment':
                                                resource_type = 'AWS::ElasticBeanstalk::Environment'
                                                pattern = r"environmentName([A-Za-z0-9 /_&^'%*()$#@!+=:-]+)"
                                        elif event_source == 'dms':
                                            pattern = r"Identifier([A-Za-z0-9 /_&^'%*()$#@!+=:-]+)"
                                        elif event['EventName'] == 'CreateIPSet':
                                            if event_source == 'wafv2':
                                                arg1 = cloudtrail_event['requestParameters']['scope']
                                            elif event_source == 'waf':
                                                resource_type = 'AWS::WAF::IPSet'
                                        elif event['EventName'] == 'CreateRegexPatternSet':
                                            if event_source == 'wafv2':
                                                arg1 = cloudtrail_event['requestParameters']['scope']
                                            elif event_source == 'waf':
                                                resource_type = 'AWS::WAF::RegexPatternSet'
                                                pattern = r"Identifier([A-Za-z0-9 /_&^'%*()$#@!+=:-]+)"
                                        elif event['EventName'] in ['CreateWebACL', 'CreateRuleGroup']:
                                            if event_source == 'wafv2':
                                                arg1 = cloudtrail_event['requestParameters']['scope']
                                            elif event_source == 'waf':
                                                if event['EventName'] == 'CreateWebACL':
                                                    resource_type = 'AWS::WAF::WebACL'
                                                    pattern = r"name([A-Za-z0-9 /_&^'%*()$#@!+=:-]+)"
                                        name_match = re.search(pattern, str(request_params))
                                        if name_match is not None:
                                            resource_name = name_match.group(0).replace("'","").split(" ")[1]
                                            if helper.resource_exists(role_arn, region, resource_type, arg1, resource_name):
                                                if f"{resource_type}|{resource_name}" not in created_resources:
                                                    created_resources.append(f"{resource_type}|{resource_name}")
            time.sleep(CLOUDTRAIL_THROTTLE_PERIOD)
        created_resources = list(set(created_resources))
    except Exception as error:
        print(str(error))
    return created_resources

def is_iam_id(resource_name):
    if re.match("^[A-Z0-9]+$", resource_name):
        return True
    return False

def is_dynamodb_kms_appmesh_id(resource_name):
    if re.match("^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}$", resource_name):
        return True
    return False

def get_api_id(event):
    api_id = ''
    api_id_re = [ '\'restApiId\': \'([a-z0-9]+)\'', '\'apiId\': \'([a-z0-9]+)\'']
    try:
        for expression in api_id_re:
            match = re.search(expression, event)
            if match is not None:
                api_id = (match.group(0).replace("'","")).split(':')[1].strip()
    except Exception as error:
        print(f"[ERROR] {error}")
    return api_id

if __name__ == "__main__":
    main()
