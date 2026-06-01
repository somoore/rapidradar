import re
import boto3
from botocore.exceptions import ClientError

ERROR_CODES = [
    'NotFoundException',
    '404',
    'ResourceNotFoundException',
    'InvalidVpnGatewayID.NotFound',
    'NoSuchEntity',
    'ParameterNotFound',
    'InvalidDocument',
    'TrailNotFoundException',
    'ChannelNotFoundException',
    'RepositoryDoesNotExistException',
    'QueueDoesNotExist',
    'LoadBalancerNotFound',
    'StateMachineDoesNotExist',
    'NatGatewayNotFound',
    'InvalidGroup.NotFound',
    'InvalidAllocationID.NotFound',
    'InvalidVpcID.NotFound',
    'InvalidSnapshot.NotFound',
    'InvalidVolume.NotFound',
    'InvalidAMIID.NotFound',
    'InvalidInstanceID.NotFound',
    'InvalidSubnetID.NotFound',
    'EntityNotFoundException',
    'ListenerNotFound',
    'FileSystemNotFound',
    'InvalidTransitGatewayAttachmentID.NotFound',
    'InvalidRouteTableID.NotFound',
    'InvalidTransitGatewayID.NotFound',
    'InvalidVpcEndpointId.NotFound',
    'DBClusterNotFoundFault',
    'ClusterNotFoundFault',
    'CacheClusterNotFound',
    'CacheParameterGroupNotFound',
    'InvalidNetworkInterfaceID.NotFound',
    'InvalidInternetGatewayID.NotFound',
    'DBInstanceNotFound',
    'TargetGroupNotFound',
    'CacheSubnetGroupNotFoundFault',
    'ReplicationGroupNotFoundFault',
    'RepositoryNotFoundException',
    'UnknownResourceException',
    'StackSetNotFoundException'
]
def resource_exists(role_arn, region, resource_type, arg1, resource_name):
    resource_type_methods = {
        'AWS::AppConfig::Application': {
            'method': 'appconfig.get_application',
            'base_kwargs': {
                'ApplicationId': resource_name
            }
        },
        'AWS::AppConfig::DeploymentStrategy': {
            'method': 'appconfig.get_deployment_strategy',
            'base_kwargs': {
                'DeploymentStrategyId': resource_name
            }
        },
        'AWS::AppMesh::Mesh': {
            'method': 'appmesh.describe_mesh',
            'base_kwargs': {
                'meshName': resource_name
            }
        },
        'AWS::AppMesh::VirtualNode': {
            'method': 'appmesh.describe_virtual_node',
            'base_kwargs': {
                'meshName': arg1,
                'virtualNodeName': resource_name
            }
        },
        'AWS::AppMesh::VirtualService': {
            'method': 'appmesh.describe_virtual_service',
            'base_kwargs': {
                'meshName': arg1,
                'virtualServiceName': resource_name
            }
        },
        'AWS::AppMesh::VirtualRouter': {
            'method': 'appmesh.describe_virtual_router',
            'base_kwargs': {
                'meshName': arg1,
                'virtualRouterName': resource_name
            }
        },
        'AWS::AppMesh::VirtualGateway': {
            'method': 'appmesh.describe_virtual_gateway',
            'base_kwargs': {
                'meshName': arg1,
                'virtualGatewayName': resource_name
            }
        },
        'AWS::AppRunner::Service': {
            'method': 'apprunner.describe_service',
            'base_kwargs': {
                'ServiceArn': resource_name
            }
        },
        'AWS::AppRunner::AutoScalingConfiguration': {
            'method': 'apprunner.describe_auto_scaling_configuration',
            'base_kwargs': {
                'AutoScalingConfigurationArn': resource_name
            }
        },
        'AWS::AppRunner::Connection': {
            'method': 'apprunner.list_connections',
            'base_kwargs': {
                'ConnectionName': resource_name
            }
        },
        'AWS::AppRunner::ObservabilityConfiguration': {
            'method': 'apprunner.describe_observability_configuration',
            'base_kwargs': {
                'ObservabilityConfigurationArn': resource_name
            }
        },
        'AWS::AppRunner::VpcConnector': {
            'method': 'apprunner.describe_vpc_connector',
            'base_kwargs': {
                'VpcConnectorArn': resource_name
            }
        },
        'AWS::AppRunner::VpcIngressConnection': {
            'method': 'apprunner.describe_vpc_ingress_connection',
            'base_kwargs': {
                'VpcIngressConnectionArn': resource_name
            }
        },
        'AWS::ApiGateway::ApiKey': {
            'method': 'apigateway.get_api_key',
            'base_kwargs': {
                'apiKey': resource_name,
                'includeValue': False
            }
        },
        'AWS::ApiGateway::Authorizer': {
            'method': 'apigateway.get_authorizer',
            'base_kwargs': {
                'restApiId': arg1,
                'authorizerId': resource_name
            }
        },
        'AWS::ApiGateway::DomainName': {
            'method': 'apigateway.get_domain_name',
            'base_kwargs': {
                'domainName': resource_name
            }
        },
        'AWS::ApiGateway::RestApi': {
            'method': 'apigateway.get_rest_api',
            'base_kwargs': {
                'restApiId': resource_name
            }
        },
        'AWS::ApiGateway::UsagePlan': {
            'method': 'apigateway.get_usage_plan',
            'base_kwargs': {
                'usagePlanId': resource_name
            }
        },
        'AWS::ApiGateway::VpcLink': {
            'method': 'apigateway.get_vpc_link',
            'base_kwargs': {
                'vpcLinkId': resource_name
            }
        },
        'AWS::ApiGatewayV2::Api': {
            'method': 'apigatewayv2.get_api_key',
            'base_kwargs': {
                'ApiId': resource_name
            }
        },
        'AWS::ApiGatewayV2::Authorizer': {
            'method': 'apigatewayv2.get_authorizer',
            'base_kwargs': {
                'ApiId': arg1,
                'AuthorizerId': resource_name
            }
        },
        'AWS::ApiGatewayV2::DomainName': {
            'method': 'apigatewayv2.get_domain_name',
            'base_kwargs': {
                'DomainName': resource_name
            }
        },
        'AWS::ApiGatewayV2::VpcLink': {
            'method': 'apigatewayv2.get_vpc_link',
            'base_kwargs': {
                'VpcLinkId': resource_name
            }
        },
        'AWS::Athena::WorkGroup': {
            'method': 'athena.get_work_group',
            'base_kwargs': {
                'WorkGroup': resource_name
            }
        },
        'AWS::Athena::NamedQuery': {
            'method': 'athena.get_named_query',
            'base_kwargs': {
                'NamedQueryId': resource_name
            }
        },
        'AWS::AutoScaling::AutoScalingGroup': {
            'method': 'autoscaling.describe_auto_scaling_groups',
            'base_kwargs': {
                'AutoScalingGroupNames': [resource_name]
            }
        },
        'AWS::AutoScaling::LaunchConfiguration': {
            'method': 'autoscaling.describe_launch_configurations',
            'base_kwargs': {
                'LaunchConfigurationNames': [resource_name]
            }
        },
        'AWS::AutoScaling::ScalingPolicy': {
            'method': 'autoscaling.describe_policies',
            'base_kwargs': {
                'PolicyNames': [resource_name]
            }
        },
        'AWS::AutoScaling::ScheduledAction': {
            'method': 'autoscaling.describe_scheduled_actions',
            'base_kwargs': {
                'ScheduledActionNames': [resource_name]
            }
        },
        'AWS::AutoScalingPlans::ScalingPlan': {
            'method': 'autoscaling-plans.describe_scaling_plans',
            'base_kwargs': {
                'ScalingPlanNames': [resource_name]
            }
        },
        'AWS::Backup::BackupPlan': {
            'method': 'backup.get_backup_plan',
            'base_kwargs': {
                'BackupPlanId': resource_name
            }
        },
        'AWS::Backup::BackupSelection': {
            'method': 'backup.get_backup_selection',
            'base_kwargs': {
                'BackupPlanId': arg1,
                'SelectionId': resource_name
            }
        },
        'AWS::Backup::BackupVault': {
            'method': 'backup.describe_backup_vault',
            'base_kwargs': {
                'BackupVaultName': resource_name
            }
        },
        'AWS::Backup::Framework': {
            'method': 'backup.describe_framework',
            'base_kwargs': {
                'FrameworkName': resource_name
            }
        },
        'AWS::Backup::ReportPlan': {
            'method': 'backup.describe_report_plan',
            'base_kwargs': {
                'ReportPlanName': resource_name
            }
        },
        'AWS::CertificateManager::Certificate': {
            'method': 'acm.describe_certificate',
            'base_kwargs': {
                'CertificateArn': resource_name
            }
        },
        'AWS::CloudFormation::Stack': {
            'method': 'cloudformation.describe_stacks',
            'base_kwargs': {
                'StackName': resource_name
            }
        },
        'AWS::CloudFormation::StackSet': {
            'method': 'cloudformation.list_stack_sets',
            'base_kwargs': {
                'Status': 'ACTIVE',
                'CallAs': arg1
            }
        },
        'AWS::CloudFront::Distribution': {
            'method': 'cloudfront.get_distribution',
            'base_kwargs': {
                'Id': resource_name
            }
        },
        'AWS::CloudTrail::Trail': {
            'method': 'cloudtrail.get_trail',
            'base_kwargs': {
                'Name': resource_name
            }
        },
        'AWS::CloudTrail::Channel': {
            'method': 'cloudtrail.get_channel',
            'base_kwargs': {
                'Channel': resource_name
            }
        },
        'AWS::CloudTrail::EventDataStore': {
            'method': 'cloudtrail.get_event_data_store',
            'base_kwargs': {
                'EventDataStore': resource_name
            }
        },
        'AWS::CloudWatch::Alarm': {
            'method': 'cloudwatch.describe_alarms',
            'base_kwargs': {
                'AlarmNames': [resource_name]
            }
        },
        'AWS::CloudWatch::Dashboard': {
            'method': 'cloudwatch.get_dashboard',
            'base_kwargs': {
                'DashboardName': resource_name
            }
        },
        'AWS::CodeArtifact::Domain': {
            'method': 'codeartifact.describe_domain',
            'base_kwargs': {
                'domain': resource_name
            }
        },
        'AWS::CodeArtifact::Repository': {
            'method': 'codeartifact.describe_repository',
            'base_kwargs': {
                'domain': arg1,
                'repository': resource_name
            }
        },
        'AWS::CodeBuild::Project': {
            'method': 'codebuild.list_projects',
            'base_kwargs': {}
        },
        'AWS::CodeCommit::Repository': {
            'method': 'codecommit.get_repository',
            'base_kwargs': {
                'repositoryName': resource_name
            }
        },
        'AWS::CodeDeploy::Application': {
            'method': 'codedeploy.get_application',
            'base_kwargs': {
                'applicationName': resource_name
            }
        },
        'AWS::CodeDeploy::DeploymentConfig': {
            'method': 'codedeploy.get_deployment_config',
            'base_kwargs': {
                'deploymentConfigName': resource_name
            }
        },
        'AWS::CodeDeploy::DeploymentGroup': {
            'method': 'codedeploy.get_deployment_group',
            'base_kwargs': {
                'applicationName': arg1,
                'deploymentGroupName': resource_name
            }
        },
        'AWS::CodePipeline::Pipeline': {
            'method': 'codepipeline.get_pipeline',
            'base_kwargs': {
                'name': resource_name
            }
        },
        'AWS::CodeStarNotifications::NotificationRule': {
            'method': 'codestar-notifications.describe_notification_rule',
            'base_kwargs': {
                'Arn': resource_name
            }
        },
        'AWS::Cognito::IdentityPool': {
            'method': 'cognito-identity.describe_identity_pool',
            'base_kwargs': {
                'IdentityPoolId': resource_name
            }
        },
        'AWS::Cognito::UserPool': {
            'method': 'cognito-idp.describe_user_pool',
            'base_kwargs': {
                'UserPoolId': resource_name
            }
        },
        'AWS::Cognito::UserPoolClient': {
            'method': 'cognito-idp.describe_user_pool_client',
            'base_kwargs': {
                'UserPoolId': arg1,
                'ClientId': resource_name
            }
        },
        'AWS::DAX::Cluster': {
            'method': 'dax.describe_clusters',
            'base_kwargs': {
                'ClusterNames': [resource_name]
            }
        },
        'AWS::DAX::ParameterGroup': {
            'method': 'dax.describe_parameter_groups',
            'base_kwargs': {
                'ParameterGroupNames': [resource_name]
            }
        },
        'AWS::DAX::SubnetGroup': {
            'method': 'dax.describe_subnet_groups',
            'base_kwargs': {
                'SubnetGroupNames': [resource_name]
            }
        },
        'AWS::DocDB::DBCluster': {
            'method': 'docdb.describe_db_clusters',
            'base_kwargs': {
                'DBClusterIdentifier': resource_name
            }
        },
        'AWS::DocDB::DBInstance': {
            'method': 'docdb.describe_db_instances',
            'base_kwargs': {
                'DBInstanceIdentifier': resource_name
            }
        },
        'AWS::DocDB::DBClusterParameterGroup': {
            'method': 'docdb.describe_db_cluster_parameter_groups',
            'base_kwargs': {
                'DBClusterParameterGroupName': resource_name
            }
        },
        'AWS::DirectoryService::SimpleAD': {
            'method': 'ds.describe_directories',
            'base_kwargs': {
                'DirectoryIds': [resource_name]
            }
        },
        'AWS::DMS::Certificate': {
            'method': 'dms.describe_certificates',
            'base_kwargs': {
                'Filters': [{
                    'Name': 'certificate-id',
                    'Values': [resource_name]
                }]
            }
        },
        'AWS::DMS::ReplicationInstance': {
            'method': 'dms.describe_replication_instances',
            'base_kwargs': {
                'Filters': [{
                    'Name': 'replication-instance-id',
                    'Values': [resource_name]
                }]
            }
        },
        'AWS::DMS::ReplicationSubnetGroup': {
            'method': 'dms.describe_replication_subnet_groups',
            'base_kwargs': {
                'Filters': [{
                    'Name': 'replication-subnet-group-id',
                    'Values': [resource_name]
                }]
            }
        },
        'AWS::DynamoDB::Table': {
            'method': 'dynamodb.describe_table',
            'base_kwargs': {
                'TableName': resource_name
            }
        },
        'AWS::EC2::Ami': {
            'method': 'ec2.describe_images',
            'base_kwargs': {
                'ImageIds': [resource_name]
            }
        },
        'AWS::EC2::CarrierGateway': {
            'method': 'ec2.describe_carrier_gateways',
            'base_kwargs': {
                'CarrierGatewayIds': [resource_name]
            }
        },
        'AWS::EC2::CustomerGateway': {
            'method': 'ec2.describe_customer_gateways',
            'base_kwargs': {
                'CustomerGatewayIds': [resource_name]
            }
        },
        'AWS::EC2::EIP': {
            'method': 'ec2.describe_addresses',
            'base_kwargs': {
                'AllocationIds': [resource_name]
            }
        },
        'AWS::EC2::FlowLog': {
            'method': 'ec2.describe_flow_logs',
            'base_kwargs': {
                'FlowLogIds': [resource_name]
            }
        },
        'AWS::EC2::Instance': {
            'method': 'ec2.describe_instances',
            'base_kwargs': {
                'InstanceIds': [resource_name]
            }
        },
        'AWS::EC2::InternetGateway': {
            'method': 'ec2.describe_internet_gateways',
            'base_kwargs': {
                'InternetGatewayIds': [resource_name]
            }
        },
        'AWS::EC2::KeyPair': {
            'method': 'ec2.describe_key_pairs',
            'base_kwargs': {
                'KeyNames': [resource_name]
            }
        },
        'AWS::EC2::LaunchTemplate': {
            'method': 'ec2.describe_launch_templates',
            'base_kwargs': {
                'LaunchTemplateIds': [resource_name]
            }
        },
        'AWS::EC2::LocalGatewayRouteTable': {
            'method': 'ec2.describe_local_gateway_route_tables',
            'base_kwargs': {
                'LocalGatewayRouteTableIds': [resource_name]
            }
        },
        'AWS::EC2::NatGateway': {
            'method': 'ec2.describe_nat_gateways',
            'base_kwargs': {
                'NatGatewayIds': [resource_name]
            }
        },
        'AWS::EC2::NetworkAcl': {
            'method': 'ec2.describe_network_acls',
            'base_kwargs': {
                'NetworkAclIds': [resource_name]
            }
        },
        'AWS::EC2::NetworkInterface': {
            'method': 'ec2.describe_network_interfaces',
            'base_kwargs': {
                'NetworkInterfaceIds': [resource_name]
            }
        },
        'AWS::EC2::ReservedInstance': {
            'method': 'ec2.describe_reserved_instances',
            'base_kwargs': {
                'ReservedInstancesIds': [resource_name]
            }
        },
        'AWS::EC2::RouteTable': {
            'method': 'ec2.describe_route_tables',
            'base_kwargs': {
                'RouteTableIds': [resource_name]
            }
        },
        'AWS::EC2::SecurityGroup': {
            'method': 'ec2.describe_security_groups',
            'base_kwargs': {
                'GroupIds': [resource_name]
            }
        },
        'AWS::EC2::Snapshot': {
            'method': 'ec2.describe_snapshots',
            'base_kwargs': {
                'SnapshotIds': [resource_name]
            }
        },
        'AWS::EC2::Subnet': {
            'method': 'ec2.describe_subnets',
            'base_kwargs': {
                'SubnetIds': [resource_name]
            }
        },
        'AWS::EC2::TransitGateway': {
            'method': 'ec2.describe_transit_gateways',
            'base_kwargs': {
                'TransitGatewayIds': [resource_name]
            }
        },
        'AWS::EC2::TransitGatewayRouteTable': {
            'method': 'ec2.describe_transit_gateway_route_tables',
            'base_kwargs': {
                'TransitGatewayRouteTableIds': [resource_name]
            }
        },
        'AWS::EC2::TransitGatewayVpcAttachment': {
            'method': 'ec2.describe_transit_gateway_vpc_attachments',
            'base_kwargs': {
                'TransitGatewayAttachmentIds': [resource_name]
            }
        },
        'AWS::EC2::Volume': {
            'method': 'ec2.describe_volumes',
            'base_kwargs': {
                'VolumeIds': [resource_name]
            }
        },
        'AWS::EC2::VPC': {
            'method': 'ec2.describe_vpcs',
            'base_kwargs': {
                'VpcIds': [resource_name]
            }
        },
        'AWS::EC2::VPCEndpoint': {
            'method': 'ec2.describe_vpc_endpoints',
            'base_kwargs': {
                'VpcEndpointIds': [resource_name]
            }
        },
        'AWS::EC2::VPCEndpointService': {
            'method': 'ec2.describe_vpc_endpoint_services',
            'base_kwargs': {
                'ServiceNames': [resource_name]
            }
        },
        'AWS::EC2::VPCPeeringConnection': {
            'method': 'ec2.describe_vpc_peering_connections',
            'base_kwargs': {
                'VpcPeeringConnectionIds': [resource_name]
            }
        },
        'AWS::EC2::VPNConnection': {
            'method': 'ec2.describe_vpn_connections',
            'base_kwargs': {
                'VpnConnectionIds': [resource_name]
            }
        },
        'AWS::EC2::VPNGateway': {
            'method': 'ec2.describe_vpn_gateways',
            'base_kwargs': {
                'VpnGatewayIds': [resource_name]
            }
        },
        'AWS::ECR::Repository': {
            'method': 'ecr.describe_repositories',
            'base_kwargs': {
                'repositoryNames': [resource_name]
            }
        },
        'AWS::ECS::Cluster': {
            'method': 'ecs.describe_clusters',
            'base_kwargs': {
                'clusters': [resource_name]
            }
        },
        'AWS::ECS::Service': {
            'method': 'ecs.describe_services',
            'base_kwargs': {
                'cluster': arg1,
                'services': [resource_name]
            }
        },
        'AWS::ECS::TaskDefinition': {
            'method': 'ecs.describe_task_definition',
            'base_kwargs': {
                'taskDefinition': resource_name
            }
        },
        'AWS::EFS::AccessPoint': {
            'method': 'efs.describe_access_points',
            'base_kwargs': {
                'AccessPointId': resource_name
            }
        },
        'AWS::EFS::FileSystem': {
            'method': 'efs.describe_file_systems',
            'base_kwargs': {
                'FileSystemId': resource_name
            }
        },
        'AWS::EFS::MountTarget': {
            'method': 'efs.describe_mount_targets',
            'base_kwargs': {
                'MountTargetId': resource_name
            }
        },
        'AWS::EKS::Cluster': {
            'method': 'eks.describe_cluster',
            'base_kwargs': {
                'name': resource_name
            }
        },
        'AWS::EKS::Nodegroup': {
            'method': 'eks.describe_nodegroup',
            'base_kwargs': {
                'clusterName': arg1,
                'nodegroupName': resource_name
            }
        },
        'AWS::ElasticBeanstalk::Application': {
            'method': 'elasticbeanstalk.describe_applications',
            'base_kwargs': {
                'ApplicationNames': [resource_name]
            }
        },
        'AWS::ElasticBeanstalk::Environment': {
            'method': 'elasticbeanstalk.describe_environments',
            'base_kwargs': {
                'EnvironmentNames': [resource_name]
            }
        },
        'AWS::ElasticLoadBalancing::LoadBalancer': {
            'method': 'elb.describe_load_balancers',
            'base_kwargs': {
                'LoadBalancerNames': [resource_name]
            }
        },
        'AWS::ElasticLoadBalancingV2::LoadBalancer': {
            'method': 'elbv2.describe_load_balancers',
            'base_kwargs': {
                'Names': [resource_name]
            }
        },
        'AWS::ElasticLoadBalancingV2::TargetGroup': {
            'method': 'elbv2.describe_target_groups',
            'base_kwargs': {
                'Names': [resource_name]
            }
        },
        'AWS::ElasticLoadBalancingV2::Listener': {
            'method': 'elbv2.describe_listeners',
            'base_kwargs': {
                'ListenerArns': [resource_name]
            }
        },
        'AWS::ElastiCache::CacheCluster': {
            'method': 'elasticache.describe_cache_clusters',
            'base_kwargs': {
                'CacheClusterId': resource_name
            }
        },
        'AWS::ElastiCache::ParameterGroup': {
            'method': 'elasticache.describe_cache_parameter_groups',
            'base_kwargs': {
                'CacheParameterGroupName': resource_name
            }
        },
        'AWS::ElastiCache::SubnetGroup': {
            'method': 'elasticache.describe_cache_subnet_groups',
            'base_kwargs': {
                'CacheSubnetGroupName': resource_name
            }
        },
        'AWS::ElastiCache::ReplicationGroup': {
            'method': 'elasticache.describe_replication_groups',
            'base_kwargs': {
                'ReplicationGroupId': resource_name
            }
        },
        'AWS::Events::Rule': {
            'method': 'events.describe_rule',
            'base_kwargs': {
                'Name': resource_name
            }
        },
        'AWS::Events::EventBus': {
            'method': 'events.describe_event_bus',
            'base_kwargs': {
                'Name': resource_name
            }
        },
        'AWS::EventSchemas::Registry': {
            'method': 'schemas.describe_registry',
            'base_kwargs': {
                'RegistryName': resource_name
            }
        },
        'AWS::EventSchemas::Schema': {
            'method': 'schemas.describe_schema',
            'base_kwargs': {
                'RegistryName': arg1,
                'SchemaName': resource_name
            }
        },
        'AWS::FSx::FileSystem': {
            'method': 'fsx.describe_file_systems',
            'base_kwargs': {
                'FileSystemIds': [resource_name]
            }
        },
        'AWS::Glue::Crawler': {
            'method': 'glue.get_crawler',
            'base_kwargs': {
                'Name': resource_name
            }
        },
        'AWS::Glue::Database': {
            'method': 'glue.get_database',
            'base_kwargs': {
                'Name': resource_name
            }
        },
        'AWS::Glue::Job': {
            'method': 'glue.get_job',
            'base_kwargs': {
                'JobName': resource_name
            }
        },
        'AWS::Glue::Table': {
            'method': 'glue.get_table',
            'base_kwargs': {
                'DatabaseName': arg1,
                'Name': resource_name
            }
        },
        'AWS::Glue::Trigger': {
            'method': 'glue.get_trigger',
            'base_kwargs': {
                'Name': resource_name
            }
        },
        'AWS::IAM::AccessKey': {
            'method': 'iam.get_access_key_last_used',
            'base_kwargs': {
                'AccessKeyId': resource_name
            }
        },
        'AWS::IAM::Group': {
            'method': 'iam.get_group',
            'base_kwargs': {
                'GroupName': resource_name
            }
        },
        'AWS::IAM::InstanceProfile': {
            'method': 'iam.get_instance_profile',
            'base_kwargs': {
                'InstanceProfileName': resource_name
            }
        },
        'AWS::IAM::Policy': {
            'method': 'iam.list_policies',
            'base_kwargs': {
                'Scope': 'Local'
            }
        },
        'AWS::IAM::Role': {
            'method': 'iam.get_role',
            'base_kwargs': {
                'RoleName': resource_name
            }
        },
        'AWS::IAM::SshPublicKey': {
            'method': 'iam.list_ssh_public_keys',
            'base_kwargs': {
                'UserName': arg1
            }
        },
        'AWS::IdentityStore::Group': {
            'method': 'identitystore.describe_group',
            'base_kwargs': {
                'IdentityStoreId': arg1,
                'GroupId': resource_name
            }
        },
        'AWS::ImageBuilder::Image': {
            'method': 'imagebuilder.list_ssh_public_keys',
            'base_kwargs': {
                'imageBuildVersionArn': resource_name
            }
        },
        'AWS::ImageBuilder::ImageRecipe': {
            'method': 'imagebuilder.get_image_recipe',
            'base_kwargs': {
                'imageRecipeArn': resource_name
            }
        },
        'AWS::ImageBuilder::Component': {
            'method': 'imagebuilder.list_ssh_public_keys',
            'base_kwargs': {
                'componentBuildVersionArn': resource_name
            }
        },
        'AWS::ImageBuilder::ContainerRecipe': {
            'method': 'imagebuilder.get_container_recipe',
            'base_kwargs': {
                'containerRecipeArn': resource_name
            }
        },
        'AWS::ImageBuilder::ImagePipeline': {
            'method': 'imagebuilder.get_image_pipeline',
            'base_kwargs': {
                'imagePipelineArn': resource_name
            }
        },
        'AWS::ImageBuilder::InfrastructureConfiguration': {
            'method': 'imagebuilder.get_infrastructure_configuration',
            'base_kwargs': {
                'infrastructureConfigurationArn': resource_name
            }
        },
        'AWS::IAM::User': {
            'method': 'iam.get_user',
            'base_kwargs': {
                'UserName': resource_name
            }
        },
        'AWS::KMS::Key': {
            'method': 'kms.describe_key',
            'base_kwargs': {
                'KeyId': resource_name
            }
        },
        'AWS::Lambda::Function': {
            'method': 'lambda.get_function',
            'base_kwargs': {
                'FunctionName': resource_name
            }
        },
        'AWS::Logs::LogGroup': {
            'method': 'logs.describe_log_groups',
            'base_kwargs': {
                'logGroupNamePattern': resource_name
            }
        },
        'AWS::Logs::SubscriptionFilter': {
            'method': 'logs.describe_subscription_filters',
            'base_kwargs': {
                'logGroupName': arg1,
                'filterNamePrefix': resource_name
            }
        },
        'AWS::NetworkFirewall::Firewall': {
            'method': 'network-firewall.describe_firewall',
            'base_kwargs': {
                'FirewallArn': resource_name
            }
        },
        'AWS::NetworkFirewall::FirewallPolicy': {
            'method': 'network-firewall.describe_firewall_policy',
            'base_kwargs': {
                'FirewallPolicyArn': resource_name
            }
        },
        'AWS::Pipes::Pipe': {
            'method': 'pipes.describe_pipe',
            'base_kwargs': {
                'Name': resource_name
            }
        },
        'AWS::Redshift::Cluster': {
            'method': 'rds.describe_clusters',
            'base_kwargs': {
                'ClusterIdentifier': resource_name
            }
        },
        'AWS::RDS::DBCluster': {
            'method': 'rds.describe_db_clusters',
            'base_kwargs': {
                'DBClusterIdentifier': resource_name
            }
        },
        'AWS::RDS::DBClusterParameterGroup': {
            'method': 'rds.describe_db_cluster_parameter_groups',
            'base_kwargs': {
                'DBClusterParameterGroupName': resource_name
            }
        },
        'AWS::RDS::DBClusterSnapshot': {
            'method': 'rds.describe_db_cluster_snapshots',
            'base_kwargs': {
                'DBClusterSnapshotIdentifier': resource_name
            }
        },
        'AWS::RDS::DBInstance': {
            'method': 'rds.describe_db_instances',
            'base_kwargs': {
                'DBInstanceIdentifier': resource_name
            }
        },
        'AWS::RDS::DBOptionGroup': {
            'method': 'rds.describe_option_groups',
            'base_kwargs': {
                'OptionGroupName': resource_name
            }
        },
        'AWS::RDS::DBParameterGroup': {
            'method': 'rds.describe_db_parameter_groups',
            'base_kwargs': {
                'DBParameterGroupName': resource_name
            }
        },
        'AWS::RDS::DBProxy': {
            'method': 'rds.describe_db_proxies',
            'base_kwargs': {
                'DBProxyName': resource_name
            }
        },
        'AWS::RDS::DBSnapshot': {
            'method': 'rds.describe_db_snapshots',
            'base_kwargs': {
                'DBSnapshotIdentifier': resource_name
            }
        },
        'AWS::RDS::DBSubnetGroup': {
            'method': 'rds.describe_db_subnet_groups',
            'base_kwargs': {
                'DBSubnetGroupName': resource_name
            }
        },
        'AWS::RAM::ResourceShare': {
            'method': 'ram.get_resource_shares',
            'base_kwargs': {
                'resourceShareArns': [resource_name],
                'resourceOwner': 'SELF'
            }
        },
        'AWS::Route53::HostedZone': {
            'method': 'route53.get_hosted_zone',
            'base_kwargs': {
                'Id': resource_name
            }
        },
        'AWS::Route53::HealthCheck': {
            'method': 'route53.get_health_check',
            'base_kwargs': {
                'HealthCheckId': resource_name
            }
        },
        'AWS::Scheduler::Schedule': {
            'method': 'scheduler.get_schedule',
            'base_kwargs': {
                'Name': resource_name
            }
        },
        'AWS::Scheduler::ScheduleGroup': {
            'method': 'scheduler.get_schedule_group',
            'base_kwargs': {
                'Name': resource_name
            }
        },
        'AWS::S3::AccessPoint': {
            'method': 's3control.get_access_point',
            'base_kwargs': {
                'AccountId': arg1,
                'Name': resource_name
            }
        },
        'AWS::S3::Bucket': {
            'method': 's3.head_bucket',
            'base_kwargs': {
                'Bucket': resource_name
            }
        },
        'AWS::SecretsManager::Secret': {
            'method': 'secretsmanager.describe_secret',
            'base_kwargs': {
                'SecretId': resource_name
            }
        },
        'AWS::SES::ConfigurationSet': {
            'method': 'ses.describe_configuration_set',
            'base_kwargs': {
                'ConfigurationSetName': resource_name
            }
        },
        'AWS::SES::EmailIdentity': {
            'method': 'ses.list_identities',
            'base_kwargs': {
                'IdentityType': arg1
            }
        },
        'AWS::SNS::Subscription': {
            'method': 'sns.get_subscription_attributes',
            'base_kwargs': {
                'SubscriptionArn': resource_name
            }
        },
        'AWS::SNS::Topic': {
            'method': 'sns.list_subscriptions_by_topic',
            'base_kwargs': {
                'TopicArn': resource_name
            }
        },
        'AWS::SQS::Queue': {
            'method': 'sqs.get_queue_url',
            'base_kwargs': {
                'QueueName': resource_name
            }
        },
        'AWS::SSM::Document': {
            'method': 'ssm.get_document',
            'base_kwargs': {
                'Name': resource_name
            }
        },
        'AWS::SSM::Parameter': {
            'method': 'ssm.get_parameter',
            'base_kwargs': {
                'Name': resource_name
            }
        },
        'AWS::SSO::PermissionSet': {
            'method': 'sso-admin.describe_permission_set',
            'base_kwargs': {
                'InstanceArn': arg1,
                'PermissionSetArn': resource_name
            }
        },
        'AWS::StepFunctions::Activity': {
            'method': 'stepfunctions.describe_activity',
            'base_kwargs': {
                'activityArn': resource_name
            }
        },
        'AWS::StepFunctions::StateMachine': {
            'method': 'stepfunctions.describe_state_machine',
            'base_kwargs': {
                'stateMachineArn': resource_name
            }
        },
        'AWS::WAF::IPSet': {
            'method': 'waf.get_ip_set',
            'base_kwargs': {
                'IPSetId': resource_name
            }
        },
        'AWS::WAF::RegexPatternSet': {
            'method': 'waf.get_regex_pattern_set',
            'base_kwargs': {
                'RegexPatternSetId': resource_name
            }
        },
        'AWS::WAF::WebACL': {
            'method': 'waf.get_web_acl',
            'base_kwargs': {
                'WebACLId': resource_name
            }
        },
        'AWS::WAF::RuleGroup': {
            'method': 'waf.get_rule_group',
            'base_kwargs': {
                'RuleGroupId': resource_name
            }
        },
        'AWS::WAFv2::IPSet': {
            'method': 'wafv2.list_ip_sets',
            'base_kwargs': {
                'Scope': arg1
            }
        },
        'AWS::WAFv2::RegexPatternSet': {
            'method': 'wafv2.list_regex_pattern_sets',
            'base_kwargs': {
                'Scope': arg1
            }
        },
        'AWS::WAFv2::WebACL': {
            'method': 'wafv2.list_web_acls',
            'base_kwargs': {
                'Scope': arg1
            }
        },
        'AWS::WAFv2::RuleGroup': {
            'method': 'wafv2.list_rule_groups',
            'base_kwargs': {
                'Scope': arg1
            }
        },
        'AWS::WorkSpaces::ConnectionAlias': {
            'method': 'workspaces.describe_connection_aliases',
            'base_kwargs': {
                'AliasIds': [resource_name]
            }
        },
        'AWS::WorkSpaces::Workspace': {
            'method': 'workspaces.describe_workspaces',
            'base_kwargs': {
                'WorkspaceIds': [resource_name]
            }
        },
    }
    try:
        method_name = resource_type_methods[resource_type]['method']
        kwargs = resource_type_methods[resource_type]['base_kwargs']

        active_session = __assume_role(region, role_arn)
        client = active_session.client(service_name=method_name.split('.')[0], region_name=region)
        print(f'[ResourceType] {resource_type}')
        print(f'[ResourceName] {resource_name}')
        method = getattr(client, method_name.split('.')[1])
        response = method(**kwargs)
        print(response)
        if 'Reservations' in response:
            if len(response['Reservations']) > 0:
                return True
            return False
        if 'ScalingPolicies' in response:
            if len(response['ScalingPolicies']) > 0:
                return True
            return False
        if 'services' in response:
            if len(response['services']) > 0:
                return True
            return False
        if 'VpnGateways' in response:
            if response['VpnGateways'][0]['State'] == 'deleted':
                return False
        if 'Policies' in response:
            for policy in response['Policies']:
                if policy['PolicyName'] == resource_name:
                    return True
            return False
        if 'SSHPublicKeys' in response:
            for key in response['SSHPublicKeys']:
                if key['SSHPublicKeyId'] == resource_name:
                    return True
            return False
        if 'logGroups' in response:
            if len(response['logGroups']) > 0:
                return True
            return False
        if 'projects' in response:
            for proj in response['projects']:
                if proj == resource_name:
                    return True
            return False
        if 'IPSets' in response:
            for ip_set in response['IPSets']:
                if ip_set['Name'] == resource_name:
                    return True
            return False
        if 'RegexPatternSets' in response:
            for reg in response['RegexPatternSets']:
                if reg['Name'] == resource_name:
                    return True
            return False
        if 'WebACLs' in response:
            for acl in response['WebACLs']:
                if acl['Name'] == response:
                    return True
            return False
        if 'Identities' in response:
            for identity in response['Identities']:
                if identity == resource_name:
                    return True
            return False
        if 'RuleGroups' in response:
            for rg in response['RuleGroups']:
                if rg['Name'] == resource_name:
                    return True
            return False
        if 'FlowLogs' in response:
            if len(response['FlowLogs']) > 0:
                return True
            return False
        if 'Stacks' in response:
            if 'DeletionTime' not in response['Stacks'][0]:
                return True
            return False
        if 'Summaries' in response:
            for summary in response['Summaries']:
                if summary['StackSetName'] == resource_name:
                    return True
            return False
    except ClientError as error:
        if error.response['Error']['Code'] in ERROR_CODES:
            print('Resource not found.')
        else:
            print(f'Unexpected error: {str(error)}')
        return False
    except KeyError:
        print("Key not found")
    return True

def __assume_role(region, arn):
    sts = boto3.client('sts', region_name=region)
    response = sts.assume_role(RoleArn=arn, RoleSessionName='events_alert')
    session = boto3.Session(aws_access_key_id=response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                    aws_session_token=response['Credentials']['SessionToken'])
    return session

def get_resource_type(event_name):
    try:
        resource_type_event_map = {
            'CreateApplication': 'AWS::AppConfig::Application',
            'CreateDeploymentStrategy': 'AWS::AppConfig::DeploymentStrategy',
            'CreateAccessPoint': 'AWS::S3::AccessPoint',
            'PutParameter': 'AWS::SSM::Parameter',
            'CreateDocument': 'AWS::SSM::Document',
            'CreateWorkGroup': 'AWS::Athena::WorkGroup',
            'CreateNamedQuery': 'AWS::Athena::NamedQuery',
            'CreateStackSet': 'AWS::CloudFormation::StackSet',
            'CreateDistribution': 'AWS::CloudFront::Distribution',
            'PutDashboard': 'AWS::CloudWatch::Dashboard',
            'CreateLogGroup': 'AWS::Logs::LogGroup',
            'PutSubscriptionFilter': 'AWS::Logs::SubscriptionFilter',
            'CreateDomain': 'AWS::CodeArtifact::Domain',
            'CreateRepository': 'AWS::CodeArtifact::Repository',
            'CreateProject': 'AWS::CodeBuild::Project',
            'CreateDeploymentConfig': 'AWS::CodeDeploy::DeploymentConfig',
            'CreateDeploymentGroup':'AWS::CodeDeploy::DeploymentGroup',
            'CreateNotificationRule': 'AWS::CodeStarNotifications::NotificationRule',
            'CreateIdentityPool': 'AWS::Cognito::IdentityPool',
            'CreateUserPool': 'AWS::Cognito::UserPool',
            'CreateUserPoolClient': 'AWS::Cognito::UserPoolClient',
            'CreateCluster': 'AWS::DAX::Cluster',
            'CreateParameterGroup': 'AWS::DAX::ParameterGroup',
            'CreateSubnetGroup': 'AWS::DAX::SubnetGroup',
            'CreateDirectory': 'AWS::DirectoryService::SimpleAD',
            'CreateReplicationInstance': 'AWS::DMS::ReplicationInstance',
            'CreateReplicationSubnetGroup': 'AWS::DMS::ReplicationSubnetGroup',
            'ImportCertificate': 'AWS::DMS::Certificate',
            'CreateTransitGateway': 'AWS::EC2::TransitGateway',
            'CreateTransitGatewayRouteTable': 'AWS::EC2::TransitGatewayRouteTable',
            'CreateTransitGatewayVpcAttachment': 'AWS::EC2::TransitGatewayVpcAttachment',
            'CreateVpcEndpointServiceConfiguration': 'AWS::EC2::VPCEndpointService',
            'CreateCacheCluster': 'AWS::ElastiCache::CacheCluster',
            'CreateCacheParameterGroup': 'AWS::ElastiCache::ParameterGroup',
            'CreateCacheSubnetGroup': 'AWS::ElastiCache::SubnetGroup',
            'CreateReplicationGroup': 'AWS::ElastiCache::ReplicationGroup',
            'PutRule': 'AWS::Events::Rule',
            'CreateEventBus': 'AWS::Events::EventBus',
            'CreateFileSystem': 'AWS::FSx::FileSystem',
            'CreateDatabase': 'AWS::Glue::Database',
            'CreateCrawler': 'AWS::Glue::Crawler',
            'CreateJob': 'AWS::Glue::Job',
            'CreateIPSet': 'AWS::WAFv2::IPSet',
            'CreateRegexPatternSet': 'AWS::WAFv2::RegexPatternSet',
            'CreateWebACL': 'AWS::WAFv2::WebACL',
            'CreateRuleGroup': 'AWS::WAFv2::RuleGroup',
            'CreateActivity': 'AWS::StepFunctions::Activity',
            'CreateStateMachine': 'AWS::StepFunctions::StateMachine',
            'CreatePermissionSet': 'AWS::SSO::PermissionSet',
            'CreateConfigurationSet': 'AWS::SES::ConfigurationSet',
            'CreateEmailIdentity': 'AWS::SES::EmailIdentity',
            'CreateResourceShare': 'AWS::RAM::ResourceShare',
            'CreateFirewall': 'AWS::NetworkFirewall::Firewall',
            'CreateGroup': 'AWS::IdentityStore::Group',
            'CreateTable': 'AWS::Glue::Table',
            'CreateTrigger': 'AWS::Glue::Trigger'
        }
        for key, value in resource_type_event_map.items():
            regex = f'^{key}$'
            if re.match(regex, event_name):
                return value
        raise KeyError
    except KeyError:
        print(f"Key {event_name} not found")
    return None
