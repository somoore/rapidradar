package stacksets

import (
	"rrcore/cmd/awshelper"

	"github.com/aws/aws-sdk-go-v2/aws"
	cfTypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
)

func GetOrgChildStackSetConfig(orgMetadata *awshelper.AWSOrgMetadata, stackSetName, templateFile, templateURL string, isStandaloneDeployment, isMainRegionDeployment bool, deploymentTargets, excludedAccounts []string) *awshelper.StackSetProps {
	stackSetDeploymentTargets := &cfTypes.DeploymentTargets{}
	stackSetAutoDeployment := &cfTypes.AutoDeployment{}
	var stackSetPermissionModel cfTypes.PermissionModels
	var stackSetCallAs cfTypes.CallAs

	if isStandaloneDeployment {
		stackSetAutoDeployment = &cfTypes.AutoDeployment{}
		stackSetCallAs = cfTypes.CallAsSelf
		stackSetPermissionModel = cfTypes.PermissionModelsSelfManaged
	} else {
		stackSetPermissionModel = cfTypes.PermissionModelsServiceManaged
		stackSetAutoDeployment = &cfTypes.AutoDeployment{
			Enabled:                      aws.Bool(true),
			RetainStacksOnAccountRemoval: aws.Bool(false),
		}
		stackSetDeploymentTargets.OrganizationalUnitIds = deploymentTargets
		if len(excludedAccounts) != 0 {
			stackSetDeploymentTargets.Accounts = excludedAccounts
			stackSetDeploymentTargets.AccountFilterType = cfTypes.AccountFilterTypeDifference
		}
		if orgMetadata.AutomationAccountId == orgMetadata.ManagementAccountId {
			stackSetCallAs = cfTypes.CallAsSelf
		} else {
			stackSetCallAs = cfTypes.CallAsDelegatedAdmin
		}
	}

	return &awshelper.StackSetProps{
		StackSetName:           stackSetName,
		TemplateFile:           templateFile,
		TemplateUrl:            templateURL,
		IsMainRegionDeployment: isMainRegionDeployment,
		IsServiceManaged:       true,
		CallAs:                 stackSetCallAs,
		PermissionModel:        stackSetPermissionModel,
		DeploymentTargets:      stackSetDeploymentTargets,
		AutoDeployment:         stackSetAutoDeployment,
	}
}
