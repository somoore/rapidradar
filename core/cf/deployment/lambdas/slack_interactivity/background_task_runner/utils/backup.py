from utils.logger import LOGGER

class Backup:
    def __init__(self, active_session, region):
        self.region = region
        self.client = active_session.client(service_name='backup', region_name=self.region)

    def tag_backup_plan(self, backup_plan_arn, tags):
        try:
            self.client.tag_resource(
                ResourceArn=backup_plan_arn,
                Tags=tags
            )
            LOGGER.info("Successfully tagged Backup Plan %s with tags: %s", backup_plan_arn, tags)
            return True
        except self.client.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'ResourceNotFoundException':
                LOGGER.info("Backup plan %s was not found", backup_plan_arn)
                return True
            LOGGER.error(str(error))
        return False
