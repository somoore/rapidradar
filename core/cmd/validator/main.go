package validator

import (
	"os"
	"strconv"
)

func ValidateParameters(deploymentTargets []string) {
	boolEnvVarKeys := []string{
		"IsControlTowerEnabled",
		"CfStackSetExecutionRoleCreation",
		"CreateManagementTrail",
		"IsOrganizationTrail",
		"AddSupportforAzureCloud",
		"AddSupportforPagerDuty",
		"EnableEC2InstanceConfigurator",
		"AutoAttachIAMRoleEC2",
		"AutoAttachMissingPolicies",
		"AutoCreateVPCEndpoints",
		"CreateNewManagedPolicy",
		"TrackSSMDocumentAssociationFailures",
		"CreatePagerDutyIncidentsForSSMFailures",
		"EnableHourlySSMFailureReminders",
		"EnableGuardDuty",
	}

	checkIfDeploymentTargetsAreEmpty()
	enableEC2InstanceConfigurator, _ := strconv.ParseBool(os.Getenv("EnableEC2InstanceConfigurator"))
	if enableEC2InstanceConfigurator {
		validateSSMDocumentContentJson()
	}

	_, _, foundAccountIds := validateDeploymentTargets(deploymentTargets)
	for _, key := range boolEnvVarKeys {
		validateBoolEnvVars(key)
	}

	validateExcludeAndAdminAccounts(foundAccountIds)
	validateSeverityTypes("SendHourlyAlertsForSeverityTypes")
	validateServiceDeploymentAction()

	createManagementTrail, _ := strconv.ParseBool(os.Getenv("CreateManagementTrail"))
	createDataTrail, _ := strconv.ParseBool(os.Getenv("CreateDataTrail"))
	isOrganizationTrail, _ := strconv.ParseBool(os.Getenv("IsOrganizationTrail"))
	isControlTowerEnabled, _ := strconv.ParseBool(os.Getenv("IsControlTowerEnabled"))
	validateTrailParams(createManagementTrail, createDataTrail, isOrganizationTrail, isControlTowerEnabled)

	for _, key := range []string{"EngineerFacingNotificationsApp", "SecurityAdminFacingNotificationsApp"} {
		validateNotificationsApp(key)
	}

	enableGuardDuty, _ := strconv.ParseBool(os.Getenv("EnableGuardDuty"))
	if enableGuardDuty {
		validateSeverityTypes("GuardDutySeverityLevels")
	}
	addSupportforCMDB, _ := strconv.ParseBool(os.Getenv("AddSupportforCMDB"))
	validateCMDBParams(addSupportforCMDB)
	validateAlertsCustomisationParams()
	validateSCPParams(addSupportforCMDB)
	validateAutoTaggerParams(addSupportforCMDB)

	addSupportforAzureCloud, _ := strconv.ParseBool(os.Getenv("AddSupportforAzureCloud"))
	validateAzureCloudParams(addSupportforAzureCloud)

	addSupportforPagerDuty, _ := strconv.ParseBool(os.Getenv("AddSupportforPagerDuty"))
	validatePagerDutyParams(addSupportforPagerDuty)

	createNewManagedPolicy, _ := strconv.ParseBool(os.Getenv("CreateNewManagedPolicy"))
	validateManagedPolicy(createNewManagedPolicy)
}
