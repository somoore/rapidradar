from os import getenv
from utils.logger import LOGGER
from utils.sts import AssumeRole
from utils.backup import Backup
from utils.iam import IAM
from utils.ec2 import EC2
from utils.efs import EFS
from utils.eks import EKS
from utils.fsx import FSX
from utils.rds import RDS
from utils.elb import ELB
from utils.s3 import S3Control
from utils.secretsmanager import SecretsManager
from utils.sso_helper import SSOHelper

CROSS_ACCOUNT_ROLE = getenv('CROSS_ACCOUNT_ROLE')
EXPECTED_PERMISSIONS_BOUNDARY = getenv('EXPECTED_PERMISSIONS_BOUNDARY')
MANAGEMENT_ACCOUNT_ID = getenv('MANAGEMENT_ACCOUNT_ID')
DEPLOYMENT_TARGETS = getenv('DEPLOYMENT_TARGETS').replace(' ', '').split(',')
EXCLUDE_ACCOUNTS = getenv('EXCLUDE_ACCOUNTS')
EXCLUDE_ACCOUNTS = EXCLUDE_ACCOUNTS.replace(' ', '').split(',') if EXCLUDE_ACCOUNTS else []

def validate_account_access(account_id: str) -> bool:
    ssp_helper = SSOHelper()
    deployment_accounts = ssp_helper.get_active_child_accounts(DEPLOYMENT_TARGETS, EXCLUDE_ACCOUNTS)
    if account_id not in deployment_accounts:
        LOGGER.error("Account ID %s is not in the allowed list: %s", account_id, deployment_accounts)
        return False
    return True

def construct_cross_account_role_arn(account_id: str, region: str) -> str:
    if account_id == MANAGEMENT_ACCOUNT_ID:
        LOGGER.error("MANAGEMENT ACCOUNT DETECTED! We can't make any change in management account. Exiting...")
        return Exception("MANAGEMENT ACCOUNT DETECTED! We can't make any change in management account. Exiting..")
    if not validate_account_access(account_id):
        raise Exception(f"Account validation failed for account {account_id}")
    role_name = f"{CROSS_ACCOUNT_ROLE}-{region}"
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    active_session = AssumeRole(role_arn).assume_role(region)
    iam_utils = IAM(active_session)
    get_role_response = iam_utils.role_details(role_name)
    if not get_role_response:
        LOGGER.error("Role %s does not exist in account %s.", role_name, account_id)
        return False
    if EXPECTED_PERMISSIONS_BOUNDARY:
        role = get_role_response.get('Role', {})
        boundary = role.get('PermissionsBoundary', {}).get('PermissionsBoundaryArn', '')
        if EXPECTED_PERMISSIONS_BOUNDARY not in boundary:
            LOGGER.error("Role %s in account %s has incorrect permissions boundary: %s (expected: %s)", role_name, account_id, boundary, EXPECTED_PERMISSIONS_BOUNDARY)
            return False
    return role_arn

def remediate_resource(account_id: str, region: str, resource_type: str, resource_id: str):
    cross_account_role_arn = construct_cross_account_role_arn(account_id, region)
    active_session = AssumeRole(cross_account_role_arn).assume_role(region)
    try:
        if resource_type == "Public EC2 AMI":
            ec2_utils = EC2(active_session, region)
            if not ec2_utils.make_public_ami_private(resource_id):
                LOGGER.error("Failed to make %s %s private in Account %s Region %s", resource_type, resource_id, account_id, region)
                return False
            return True
        if resource_type == "Public EBS Snapshot":
            ec2_utils = EC2(active_session, region)
            if not ec2_utils.make_public_snapshot_private(resource_id):
                LOGGER.error("Failed to make %s %s private in Account %s Region %s", resource_type, resource_id, account_id, region)
                return False
            return True
        if resource_type in ["Public RDS DB Cluster Snapshot", "RDS DB Instance Snapshot"]:
            rds_utils = RDS(active_session, region)
            if not rds_utils.make_public_db_snapshot_private(resource_id, True if "DB Cluster" in resource_type else False):
                LOGGER.error("Failed to make %s %s private in Account %s Region %s", resource_type, resource_id, account_id, region)
                return False
            return True
        if resource_type == "S3 Account Public Access Block":
            s3_control_utils = S3Control(active_session)
            if not s3_control_utils.enable_account_block_public_access(account_id):
                LOGGER.error("Failed to enable %s for Account %s", resource_type, account_id)
                return False
            return True
        LOGGER.error("Remediation of Resource Type %s is not being handled currently", resource_type)
        return False
    except Exception as error:
        LOGGER.error(str(error))
        return False

def tag_resource(account_id: str, region: str, resource_type: str, resource_id: str, tags: list):
    cross_account_role_arn = construct_cross_account_role_arn(account_id, region)
    active_session = AssumeRole(cross_account_role_arn).assume_role(region)
    try:
        if resource_type == "Backup Plan":
            backup_utils = Backup(active_session, region)
            backup_tags = {}
            for tag in tags:
                backup_tags[tag['Key']] = tag['Value']
            if not backup_utils.tag_backup_plan(resource_id, backup_tags):
                LOGGER.error("Failed to tag %s %s in Account %s Region %s", resource_type, resource_id, account_id, region)
                return False
            return True
        if resource_type in ["Elastic IP", "EC2 AMI", "EBS Snapshot", "EC2 VPC", "EC2 Subnet", "EBS Volume", "EC2 Instance"]:
            ec2_utils = EC2(active_session, region)
            if not ec2_utils.add_tags_to_ec2_resource(resource_id, tags):
                LOGGER.error("Failed to tag %s %s in Account %s Region %s", resource_type, resource_id, account_id, region)
                return False
            return True
        if resource_type == "EFS FileSystem":
            efs_utils = EFS(active_session, region)
            if not efs_utils.add_tags_to_filesystem(resource_id, tags):
                LOGGER.error("Failed to tag %s %s in Account %s Region %s", resource_type, resource_id, account_id, region)
                return False
            return True
        if resource_type == "EKS Cluster":
            eks_utils = EKS(active_session, region)
            eks_cluster_tags = {}
            for tag in tags:
                eks_cluster_tags[tag['Key']] = tag['Value']
            if not eks_utils.add_tags_to_eks_cluster(account_id, resource_id, eks_cluster_tags):
                LOGGER.error("Failed to tag %s %s in Account %s Region %s", resource_type, resource_id, account_id, region)
                return False
            return True
        if resource_type == "FSX FileSystem":
            fsx_utils = FSX(active_session, region)
            if not fsx_utils.tag_filesystem(account_id, resource_id, tags):
                LOGGER.error("Failed to tag %s %s in Account %s Region %s", resource_type, resource_id, account_id, region)
                return False
            return True
        if resource_type in ["RDS Cluster", "RDS Instance"]:
            rds_utils = RDS(active_session, region)
            resource = f"db:{resource_id}" if resource_type == "RDS Instance" else f"cluster:{resource_id}"
            if not rds_utils.add_tags_to_rds(account_id, resource, tags):
                LOGGER.error("Failed to tag %s %s in Account %s Region %s", resource_type, resource_id, account_id, region)
                return False
            return True
        if resource_type.endswith("LoadBalancer"):
            elb_utils = ELB(active_session, region)
            if not elb_utils.tag_loadbalancer(resource_type, resource_id, tags):
                LOGGER.error("Failed to tag %s %s in Account %s Region %s", resource_type, resource_id, account_id, region)
                return False
            return True
        if resource_type == "SecretManager Secret":
            secretsmanager_utils = SecretsManager(active_session, region)
            if not secretsmanager_utils.tag_secret(resource_id, tags):
                LOGGER.error("Failed to tag %s %s in Account %s Region %s", resource_type, resource_id, account_id, region)
                return False
            return True
        LOGGER.error("Tagging of Resource Type %s is not being handled currently", resource_type)
        return False
    except Exception as error:
        LOGGER.error(str(error))
        return False

def delete_resource(account_id: str, region: str, resource_type: str, resource_id: str):
    cross_account_role_arn = construct_cross_account_role_arn(account_id, region)
    active_session = AssumeRole(cross_account_role_arn).assume_role(region)
    try:
        if resource_type == "IAM User":
            iam_utils = IAM(active_session)
            if not iam_utils.delete_user(resource_id):
                LOGGER.error("Failed to delete %s %s in Account %s Region %s", resource_type, resource_id, account_id, region)
                return False
            return True
        if resource_type == "IAM Access Key":
            iam_utils = IAM(active_session)
            iam_user, access_key = resource_id.split(":")
            if not iam_utils.delete_access_key(iam_user, access_key):
                LOGGER.error("Failed to delete %s %s in Account %s Region %s", resource_type, resource_id, account_id, region)
                return False
            return True
        if resource_type == "Elastic IP":
            ec2_utils = EC2(active_session, region)
            if not ec2_utils.release_eip(resource_id):
                LOGGER.error("Failed to release %s %s in Account %s Region %s", resource_type, resource_id, account_id, region)
                return False
            return True
        if resource_type == "Security Group Ingress":
            ec2_utils = EC2(active_session, region)
            group_id, ingress_rule_id = resource_id.split(":")
            if not ec2_utils.delete_security_group_rule(group_id, ingress_rule_id):
                LOGGER.error("Failed to release %s %s in Account %s Region %s", resource_type, resource_id, account_id, region)
                return False
            return True
        if resource_type == "IAM Role Policy":
            iam_utils = IAM(active_session)
            role_name, policy = resource_id.split(":", 1)
            if policy.startswith("arn:"):
                if not iam_utils.detach_role_policy(role_name, policy):
                    LOGGER.error("Failed to detach %s %s in Account %s Region %s", resource_type, resource_id, account_id, region)
                    return False
                return True
            if not iam_utils.delete_role_policy(role_name, policy):
                LOGGER.error("Failed to delete %s %s in Account %s Region %s", resource_type, resource_id, account_id, region)
                return False
            return True
        if resource_type == "IAM User Login Profile":
            iam_utils = IAM(active_session)
            if not iam_utils.delete_iam_login_profile(resource_id):
                LOGGER.error("Failed to delete %s of User %s in Account %s Region %s", resource_type, resource_id, account_id, region)
                return False
            return True
        LOGGER.error("Deletion of Resource Type %s is not being handled currently", resource_type)
        return False
    except Exception as error:
        LOGGER.error(str(error))
        return False
