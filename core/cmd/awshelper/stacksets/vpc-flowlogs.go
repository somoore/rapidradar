package stacksets

import (
	"rrcore/cmd/awshelper"
	"rrcore/cmd/helper"

	cfTypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
)

func GetVpcFlowLogsStackSetsConfig(orgMetadata *awshelper.AWSOrgMetadata, stackSetName, templateFile, templateURL string, isStandaloneDeployment, isMainRegionDeployment bool, deploymentTargets, excludedAccounts, standaloneAcountsOUIds []string) *awshelper.StackSetProps {
	stackSetDeploymentTargets := &cfTypes.DeploymentTargets{}
	stackSetAutoDeployment := &cfTypes.AutoDeployment{}
	var isServiceManaged bool
	var stackSetPermissionModel cfTypes.PermissionModels
	var stackSetCallAs cfTypes.CallAs

	if !helper.IsValEmpty(orgMetadata.LogArchiveAccountId) {
		stackSetDeploymentTargets = &cfTypes.DeploymentTargets{}
		stackSetPermissionModel = cfTypes.PermissionModelsSelfManaged
		stackSetCallAs = cfTypes.CallAsSelf
	} else {
		stackSetPermissionModel = cfTypes.PermissionModelsServiceManaged
		if orgMetadata.AutomationAccountId == orgMetadata.ManagementAccountId {
			stackSetCallAs = cfTypes.CallAsSelf
		} else {
			stackSetCallAs = cfTypes.CallAsDelegatedAdmin
		}
		// setting deployment targets
		if !isStandaloneDeployment {
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
