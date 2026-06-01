package stacksets

import (
	"rrcore/cmd/awshelper"
	"rrcore/cmd/helper"

	"github.com/aws/aws-sdk-go-v2/aws"
	cfTypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
)

func GetCfStackSetExecutionRoleStackSetConfig(orgMetadata *awshelper.AWSOrgMetadata, stackSetName, templateFile, templateURL, flowLogsAdminAccountId string, isStandaloneDeployment bool, deploymentTargets, excludedAccounts, standaloneAcountsOUIds, deploymentAccountsOUIds []string) *awshelper.StackSetProps {
	stackSetDeploymentTargets := &cfTypes.DeploymentTargets{}
	stackSetAutoDeployment := &cfTypes.AutoDeployment{}
	var stackSetCallAs cfTypes.CallAs

	if orgMetadata.AutomationAccountId == orgMetadata.ManagementAccountId {
		stackSetCallAs = cfTypes.CallAsSelf
	} else {
		stackSetCallAs = cfTypes.CallAsDelegatedAdmin
	}
	if !isStandaloneDeployment {
		stackSetDeploymentTargets.OrganizationalUnitIds = deploymentAccountsOUIds
		modifiedExcludedAccounts := excludedAccounts
		if !helper.IsValEmpty(flowLogsAdminAccountId) {
			if contains(excludedAccounts, orgMetadata.AutomationAccountId) {
				modifiedExcludedAccounts = removeItem(excludedAccounts, orgMetadata.AutomationAccountId)
			}
		}
		if len(modifiedExcludedAccounts) != 0 {
			stackSetDeploymentTargets.Accounts = modifiedExcludedAccounts
			stackSetDeploymentTargets.AccountFilterType = cfTypes.AccountFilterTypeDifference
		}
		stackSetAutoDeployment = &cfTypes.AutoDeployment{
			Enabled:                      aws.Bool(true),
			RetainStacksOnAccountRemoval: aws.Bool(false),
		}
	} else {
		stackSetDeploymentTargets.OrganizationalUnitIds = standaloneAcountsOUIds
		stackSetDeploymentTargets.Accounts = deploymentTargets
		stackSetDeploymentTargets.AccountFilterType = cfTypes.AccountFilterTypeIntersection
	}
	return &awshelper.StackSetProps{
		StackSetName:           stackSetName,
		TemplateFile:           templateFile,
		TemplateUrl:            templateURL,
		IsMainRegionDeployment: true,
		IsServiceManaged:       true,
		CallAs:                 stackSetCallAs,
		PermissionModel:        cfTypes.PermissionModelsServiceManaged,
		DeploymentTargets:      stackSetDeploymentTargets,
		AutoDeployment:         stackSetAutoDeployment,
	}
}

func removeItem(slice []string, item string) []string {
	newSlice := []string{}
	for _, v := range slice {
		if v != item {
			newSlice = append(newSlice, v)
		}
	}
	return newSlice
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
