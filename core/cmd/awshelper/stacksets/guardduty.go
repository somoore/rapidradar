package stacksets

import (
	"rrcore/cmd/awshelper"
	"rrcore/cmd/helper"

	cfTypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go/aws"
)

func GetGuardDutyKmsKeyStackSetConfig(orgMetadata *awshelper.AWSOrgMetadata, stackSetName, templateFile, templateURL string, isStandaloneDeployment, isMainRegionDeployment bool, deploymentTargets, excludedAccounts, standaloneAcountsOUIds []string) *awshelper.StackSetProps {
	var setOrgDeploymentTarget bool
	stackSetDeploymentTargets := &cfTypes.DeploymentTargets{}
	stackSetAutoDeployment := &cfTypes.AutoDeployment{}
	var isServiceManaged bool
	var stackSetPermissionModel cfTypes.PermissionModels
	var stackSetCallAs cfTypes.CallAs

	if !helper.IsValEmpty(orgMetadata.GuardDutyAdminAccountId) {
		stackSetDeploymentTargets = &cfTypes.DeploymentTargets{}
		stackSetPermissionModel = cfTypes.PermissionModelsSelfManaged
		stackSetCallAs = cfTypes.CallAsSelf
		stackSetAutoDeployment = &cfTypes.AutoDeployment{}
	} else {
		setOrgDeploymentTarget = true
	}

	if setOrgDeploymentTarget {
		isServiceManaged = true
		stackSetPermissionModel = cfTypes.PermissionModelsServiceManaged
		if orgMetadata.AutomationAccountId == orgMetadata.ManagementAccountId {
			stackSetCallAs = cfTypes.CallAsSelf
		} else {
			stackSetCallAs = cfTypes.CallAsDelegatedAdmin
		}
		if !isStandaloneDeployment {
			stackSetAutoDeployment = &cfTypes.AutoDeployment{
				Enabled:                      aws.Bool(true),
				RetainStacksOnAccountRemoval: aws.Bool(false),
			}
			stackSetDeploymentTargets.OrganizationalUnitIds = deploymentTargets
			if len(excludedAccounts) != 0 {
				stackSetDeploymentTargets.Accounts = excludedAccounts
				stackSetDeploymentTargets.AccountFilterType = cfTypes.AccountFilterTypeDifference
			}
		} else {
			stackSetDeploymentTargets.OrganizationalUnitIds = standaloneAcountsOUIds
			stackSetDeploymentTargets.Accounts = deploymentTargets
			stackSetDeploymentTargets.AccountFilterType = cfTypes.AccountFilterTypeIntersection
		}
	}
	return &awshelper.StackSetProps{
		StackSetName:           stackSetName,
		TemplateFile:           templateFile,
		TemplateUrl:            templateURL,
		IsMainRegionDeployment: isMainRegionDeployment,
		IsServiceManaged:       isServiceManaged,
		CallAs:                 stackSetCallAs,
		PermissionModel:        stackSetPermissionModel,
		DeploymentTargets:      stackSetDeploymentTargets,
		AutoDeployment:         stackSetAutoDeployment,
	}
}

func GetGuardDutyBucketStackSetConfig(orgMetadata *awshelper.AWSOrgMetadata, stackSetName, templateFile, templateURL string, isStandaloneDeployment, isMainRegionDeployment bool, deploymentTargets, excludedAccounts, standaloneAcountsOUIds []string) *awshelper.StackSetProps {
	stackSetDeploymentTargets := &cfTypes.DeploymentTargets{}
	stackSetAutoDeployment := &cfTypes.AutoDeployment{}
	var isServiceManaged bool
	var stackSetPermissionModel cfTypes.PermissionModels
	var stackSetCallAs cfTypes.CallAs

	if !helper.IsValEmpty(orgMetadata.LogArchiveAccountId) || !helper.IsValEmpty(orgMetadata.GuardDutyAdminAccountId) {
		stackSetDeploymentTargets = &cfTypes.DeploymentTargets{}
		stackSetPermissionModel = cfTypes.PermissionModelsSelfManaged
		stackSetCallAs = cfTypes.CallAsSelf
	} else {
		isServiceManaged = true
		stackSetPermissionModel = cfTypes.PermissionModelsServiceManaged
		if orgMetadata.AutomationAccountId == orgMetadata.ManagementAccountId {
			stackSetCallAs = cfTypes.CallAsSelf
		} else {
			stackSetCallAs = cfTypes.CallAsDelegatedAdmin
		}
		if !isStandaloneDeployment {
			stackSetAutoDeployment = &cfTypes.AutoDeployment{
				Enabled:                      aws.Bool(true),
				RetainStacksOnAccountRemoval: aws.Bool(false),
			}
			stackSetDeploymentTargets.OrganizationalUnitIds = deploymentTargets
			if len(excludedAccounts) != 0 {
				stackSetDeploymentTargets.Accounts = excludedAccounts
				stackSetDeploymentTargets.AccountFilterType = cfTypes.AccountFilterTypeDifference
			}
		} else {
			stackSetDeploymentTargets.OrganizationalUnitIds = standaloneAcountsOUIds
			stackSetDeploymentTargets.Accounts = deploymentTargets
			stackSetDeploymentTargets.AccountFilterType = cfTypes.AccountFilterTypeDifference
		}
	}
	return &awshelper.StackSetProps{
		StackSetName:           stackSetName,
		TemplateFile:           templateFile,
		TemplateUrl:            templateURL,
		IsMainRegionDeployment: isMainRegionDeployment,
		IsServiceManaged:       isServiceManaged,
		CallAs:                 stackSetCallAs,
		PermissionModel:        stackSetPermissionModel,
		DeploymentTargets:      stackSetDeploymentTargets,
		AutoDeployment:         stackSetAutoDeployment,
	}
}

func GetGuardDutyAdminDelegationStackSetConfig(orgMetadata *awshelper.AWSOrgMetadata, stackSetName, templateFile, templateURL string, isStandaloneDeployment, isMainRegionDeployment bool, deploymentTargets, excludedAccounts, standaloneAcountsOUIds []string) *awshelper.StackSetProps {
	return &awshelper.StackSetProps{
		StackSetName:           stackSetName,
		TemplateFile:           templateFile,
		TemplateUrl:            templateURL,
		IsMainRegionDeployment: isMainRegionDeployment,
		IsServiceManaged:       false,
		CallAs:                 cfTypes.CallAsSelf,
		PermissionModel:        cfTypes.PermissionModelsSelfManaged,
		DeploymentTargets:      &cfTypes.DeploymentTargets{},
		AutoDeployment:         &cfTypes.AutoDeployment{},
	}
}

func GetGuardDutyEnablerStackSetConfig(orgMetadata *awshelper.AWSOrgMetadata, stackSetName, templateFile, templateURL string, isStandaloneDeployment, isMainRegionDeployment bool, deploymentTargets, excludedAccounts, standaloneAcountsOUIds []string) *awshelper.StackSetProps {
	var setOrgDeploymentTarget bool
	stackSetDeploymentTargets := &cfTypes.DeploymentTargets{}
	stackSetAutoDeployment := &cfTypes.AutoDeployment{}
	var isServiceManaged bool
	var stackSetPermissionModel cfTypes.PermissionModels
	var stackSetCallAs cfTypes.CallAs

	if !helper.IsValEmpty(orgMetadata.GuardDutyAdminAccountId) {
		stackSetDeploymentTargets = &cfTypes.DeploymentTargets{}
		stackSetPermissionModel = cfTypes.PermissionModelsSelfManaged
		stackSetCallAs = cfTypes.CallAsSelf
	} else {
		isServiceManaged = true
		setOrgDeploymentTarget = true
		stackSetPermissionModel = cfTypes.PermissionModelsServiceManaged
		if orgMetadata.AutomationAccountId == orgMetadata.ManagementAccountId {
			stackSetCallAs = cfTypes.CallAsSelf
		} else {
			stackSetCallAs = cfTypes.CallAsDelegatedAdmin
		}
	}
	if setOrgDeploymentTarget {
		if !isStandaloneDeployment {
			stackSetAutoDeployment = &cfTypes.AutoDeployment{
				Enabled:                      aws.Bool(true),
				RetainStacksOnAccountRemoval: aws.Bool(false),
			}
			stackSetDeploymentTargets.OrganizationalUnitIds = deploymentTargets
			if len(excludedAccounts) != 0 {
				stackSetDeploymentTargets.Accounts = excludedAccounts
				stackSetDeploymentTargets.AccountFilterType = cfTypes.AccountFilterTypeDifference
			}
		} else {
			stackSetDeploymentTargets.OrganizationalUnitIds = standaloneAcountsOUIds
			stackSetDeploymentTargets.Accounts = deploymentTargets
			stackSetDeploymentTargets.AccountFilterType = cfTypes.AccountFilterTypeIntersection
		}
	}
	return &awshelper.StackSetProps{
		StackSetName:           stackSetName,
		TemplateFile:           templateFile,
		TemplateUrl:            templateURL,
		IsMainRegionDeployment: isMainRegionDeployment,
		IsServiceManaged:       isServiceManaged,
		CallAs:                 stackSetCallAs,
		PermissionModel:        stackSetPermissionModel,
		DeploymentTargets:      stackSetDeploymentTargets,
		AutoDeployment:         stackSetAutoDeployment,
	}
}
