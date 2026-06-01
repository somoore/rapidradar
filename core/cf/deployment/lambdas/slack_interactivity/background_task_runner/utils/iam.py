from utils.logger import LOGGER

class IAM:
    def __init__(self, active_session):
        self.client = active_session.client(service_name='iam', region_name='us-east-1')

    def role_details(self, role_name):
        try:
            response = self.client.get_role(RoleName=role_name)
            return response
        except self.client.exceptions.NoSuchEntityException:
            LOGGER.info("Role %s does not exist. ", role_name)
        return []

    def delete_user(self, iam_user):
        try:
            self.client.delete_user(UserName=iam_user)
            LOGGER.info("Successfully deleted IAM User %s", iam_user)
            return True
        except self.client.exceptions.ClientError as error:
            if error.response['Error']['Code'] in ['NoSuchEntityException']:
                LOGGER.info("IAM User %s was not found", iam_user)
                return True
            LOGGER.error(str(error))
        return False

    def delete_access_key(self, iam_user, access_key):
        try:
            self.client.delete_access_key(
                UserName=iam_user,
                AccessKeyId=access_key
            )
            LOGGER.info("Successfully deleted IAM Access Key %s associated with IAM User %s", access_key, iam_user)
            return True
        except self.client.exceptions.ClientError as error:
            if error.response['Error']['Code'] in ['NoSuchEntityException']:
                LOGGER.info("IAM User %s or Access Key %s was not found", iam_user, access_key)
                return True
            LOGGER.error(str(error))
        return False

    def detach_role_policy(self, role_name, policy_arn):
        try:
            self.client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            LOGGER.info("Successfully detached IAM Role Policy %s from IAM Role %s", policy_arn, role_name)
            return True
        except self.client.exceptions.ClientError as error:
            if error.response['Error']['Code'] in ['NoSuchEntityException', 'InvalidInputException']:
                LOGGER.info("IAM Role %s not Found", role_name)
                return True
            LOGGER.error(str(error))
            return False

    def delete_role_policy(self, role_name, policy_name):
        try:
            self.client.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
            LOGGER.info("Successfully deleted IAM Role Policy %s from IAM Role %s", policy_name, role_name)
            return True
        except self.client.exceptions.ClientError as error:
            if error.response['Error']['Code'] in ['NoSuchEntityException', 'InvalidInputException']:
                LOGGER.info("IAM Role %s not Found", role_name)
                return True
            LOGGER.error(str(error))
            return False

    def delete_iam_login_profile(self, iam_user):
        try:
            self.client.delete_login_profile(UserName=iam_user)
            LOGGER.info("Successfully deleted login profile of IAM User %s", iam_user)
            return True
        except self.client.exceptions.ClientError as error:
            if error.response['Error']['Code'] in ['NoSuchEntityException']:
                LOGGER.info("IAM User %s was not found", iam_user)
                return True
            LOGGER.error(str(error))
            return False
