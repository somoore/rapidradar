package validator

import (
	"os"
	"regexp"
	"rrcore/cmd/helper"
	"rrcore/cmd/logger"
	"strings"
)

var allowedSeverities = map[string]bool{
	"CRITICAL": true,
	"HIGH":     true,
	"MEDIUM":   true,
	"LOW":      true,
	"ALL":      true,
}

func checkIfDeploymentTargetsAreEmpty() {
	if helper.IsValEmpty(os.Getenv("DeploymentTargets")) {
		logger.Fatalln(`Environment Variables have not yet been updated in env/ folder. Please update them according to your needs before starting deployment.

DeploymentTargets cannot be empty. Please provide comma-separated list of Accounts or Organizational Unit IDs where you want to deploy Post Deploy SSM Automation.`)
	}
}

func validateParamsPlaceholders(envKey string) {
	envValue := os.Getenv(envKey)

	if helper.IsValEmpty(envValue) {
		logger.Fatalf("%s cannot be empty. Please provide valid value for %s.", envKey, envKey)
	} else {
		// regex pattern for placeholders in `<...>` format
		regex := regexp.MustCompile(`<[^>]+>`)
		placeholders := regex.FindAllString(envValue, -1)

		if len(placeholders) > 0 {
			logger.Fatalf("unreplaced placeholders found in the value of %s parameter: \n%s\nPlease update value for %s replacing placeholders.", envKey, strings.Join(placeholders, "\n"), envKey)
		}
	}
}

func validateDeploymentTargets(deploymentTargets []string) (bool, bool, bool) {
	var foundRootOU bool
	var foundParentOUs bool
	var foundAccountIds bool
	count := 0
	for _, target := range deploymentTargets {
		count++
		if strings.HasPrefix(target, "r-") {
			foundRootOU = true
		} else if strings.HasPrefix(target, "ou-") {
			foundParentOUs = true
		} else if regexp.MustCompile(`^\d{12}$`).MatchString(target) {
			foundAccountIds = true
		}
	}
	if foundRootOU && count > 1 {
		logger.Fatalln("DeploymentTargets with root OU should be just one value and not multiple comma-separated values.")
	} else if foundParentOUs && foundAccountIds {
		logger.Fatalln("DeploymentTargets can either be a comma-separated list of Organizational Unit IDs or Account IDs or can just be a Root OU. They cannot be a mix of the three.")
	}
	return foundRootOU, foundParentOUs, foundAccountIds
}

func validateBoolEnvVars(envKey string) {
	envValue := os.Getenv(envKey)
	validPattern := regexp.MustCompile(`^(true|false)$`)

	if !validPattern.MatchString(envValue) {
		logger.Fatalf("Invalid Value for %s. It can only be 'true' or 'false'.", envKey)
	}
}

func validateExcludeAndAdminAccounts(foundAccountIds bool) {
	excludedAccounts := os.Getenv("ExcludeAccounts")
	guardDutyAdminAccountId := os.Getenv("GuardDutyAdminAccountId")
	inspectorAdminAccountId := os.Getenv("InspectorAdminAccountId")
	securityHubAdminAccountId := os.Getenv("SecurityHubAdminAccountId")
	logArchiveAccountId := os.Getenv("LogArchiveAccountId")
	if foundAccountIds {
		if !helper.IsValEmpty(excludedAccounts) {
			logger.Fatalln("Please do not provide value for ExcludeAccounts if DeploymentTargets are AWS Accounts.")
		}
		if !helper.IsValEmpty(guardDutyAdminAccountId) {
			logger.Fatalln("Please do not provide value for GuardDutyAdminAccountId if DeploymentTargets are AWS Accounts.")
		}
		if !helper.IsValEmpty(inspectorAdminAccountId) {
			logger.Fatalln("Please do not provide value for InspectorAdminAccountId if DeploymentTargets are AWS Accounts.")
		}
		if !helper.IsValEmpty(securityHubAdminAccountId) {
			logger.Fatalln("Please do not provide value for SecurityHubAdminAccountId if DeploymentTargets are AWS Accounts.")
		}
		if !helper.IsValEmpty(logArchiveAccountId) {
			logger.Fatalln("Please do not provide value for LogArchiveAccountId if DeploymentTargets are AWS Accounts.")
		}
	} else {
		if !helper.IsValEmpty(guardDutyAdminAccountId) && !regexp.MustCompile(`^\d{12}$`).MatchString(guardDutyAdminAccountId) {
			logger.Fatalln("GuardDutyAdminAccountId is not valid. Please provide a valid account ID and update all environment variables in env/common.yml before starting the deployment.")
		}
		if !helper.IsValEmpty(inspectorAdminAccountId) && !regexp.MustCompile(`^\d{12}$`).MatchString(inspectorAdminAccountId) {
			logger.Fatalln("InspectorAdminAccountId is not valid. Please provide a valid account ID and update all environment variables in env/common.yml before starting the deployment.")
		}
		if !helper.IsValEmpty(securityHubAdminAccountId) && !regexp.MustCompile(`^\d{12}$`).MatchString(securityHubAdminAccountId) {
			logger.Fatalln("SecurityHubAdminAccountId is not valid. Please provide a valid account ID and update all environment variables in env/common.yml before starting the deployment.")
		}
		if !helper.IsValEmpty(logArchiveAccountId) && !regexp.MustCompile(`^\d{12}$`).MatchString(logArchiveAccountId) {
			logger.Fatalln("LogArchiveAccountId is not valid. Please provide a valid account ID and update all environment variables in env/common.yml before starting the deployment.")
		}
	}
}

func validateSeverityTypes(envKey string) {
	envValue := os.Getenv(envKey)
	if helper.IsValEmpty(envValue) {
		logger.Fatalf("%s cannot be empty. \nPlease provide a comma-separated list of severity types for hourly alerts. \nAllowed values: CRITICAL, HIGH, MEDIUM, LOW, ALL \n\nExample: CRITICAL,HIGH", envKey)
	}
	severities := strings.Split(envValue, ",")

	if len(severities) > 1 && contains(severities, "ALL") {
		logger.Fatalln("Invalid input: 'ALL' cannot be combined with other severity levels. \nAllowed values: CRITICAL, HIGH, MEDIUM, LOW, ALL \n\nExample: ALL (or specific severities like CRITICAL,HIGH)")
	}
	for _, severity := range severities {
		severity = strings.TrimSpace(severity)
		if _, exists := allowedSeverities[severity]; !exists {
			logger.Fatalf("Invalid value '%s' found in %s. \nAllowed values: CRITICAL, HIGH, MEDIUM, LOW, ALL", severity, envKey)
		}
	}
}

func validateServiceDeploymentAction() {
	awsServiceDeploymentAction := os.Getenv("AWSServiceDeploymentAction")
	validPattern := regexp.MustCompile(`^(Delete|Ignore|<nil>)?$`)
	if !validPattern.MatchString(awsServiceDeploymentAction) {
		logger.Fatalln("Invalid value for AWSServiceDeploymentAction. It can either be 'Delete' or 'Ignore'.")
	}
}

func validateTrailParams(createManagementTrail, createDataTrail, isOrganizationTrail, isControlTowerEnabled bool) {
	centralizedLogsS3BucketName := os.Getenv("CentralizedLogsS3BucketName")
	validateParamsPlaceholders("CentralizedLogsS3BucketName")
	if !isOrganizationTrail && !helper.IsValEmpty(centralizedLogsS3BucketName) {
		logger.Fatalln("Please do not provide value for CentralizedLogsS3BucketName when IsOrganizationTrail is set to false. \n When IsOrganizationTrail is set to false, it will create CloudTrail trails and its resources at account level. If you want to create CloudTrail Trails at Organization-level, you can set IsOrganizationTrail to 'true'.")
	}
	if createManagementTrail {
		if helper.IsValEmpty(centralizedLogsS3BucketName) {
			logger.Fatalln("If CreateManagementTrail is set to true, CentralizedLogsS3BucketName cannot be empty. \nPlease provide value for CentralizedLogsS3BucketName.")
		}
		if isControlTowerEnabled {
			logger.Warnf("WARNING: Since Control Tower is enabled in your organization, CloudTrail trail for management events might have already been setup for your whole organization. In this case, it's better to set CreateManagementTrail to false to avoid charges due to duplicated logged management events.")
		}
		trailCloudWatchLogGroupName := os.Getenv("TrailCloudWatchLogGroupName")
		if helper.IsValEmpty(trailCloudWatchLogGroupName) {
			logger.Fatalln("If CreateManagementTrail is set to true, TrailCloudWatchLogGroupName cannot be empty. \nPlease provide value for TrailCloudWatchLogGroupName.")
		}
	} else {
		if !isControlTowerEnabled {
			logger.Fatalln("If IsControlTowerEnabled is set to false, CreateManagementTrail has to be set to true so that management events can be tracked using CloudTrail.")
		}
	}
	if !createDataTrail {
		logger.Warnf("WARNING: Since you have set CreateDataTrail to false, S3 Data Events will not be tracked or alerted.")
	}
}

func validateNotificationsApp(envKey string) {
	envValue := os.Getenv(envKey)
	var validPattern *regexp.Regexp
	if envKey == "SecurityAdminFacingNotificationsApp" {
		validPattern = regexp.MustCompile(`^(slack|msteams|googlechat|<nil>)?$`)
	} else {
		validPattern = regexp.MustCompile(`^(slack|msteams|googlechat)$`)
	}

	if !validPattern.MatchString(envValue) {
		logger.Fatalf("Invalid Notifications App provided for %s. It can only be 'slack', 'msteams', or 'googlechat'.", envKey)
	}
}

func validateAzureCloudParams(addSupportforAzureCloud bool) {
	azureCustomerId := os.Getenv("AzureCustomerId")
	azureSharedKeySSM := os.Getenv("AzureSharedKeySSM")
	azureLogType := os.Getenv("AzureLogType")
	if addSupportforAzureCloud {
		if helper.IsValEmpty(azureCustomerId) {
			logger.Fatalln("If AddSupportforAzureCloud is set to true, then AzureCustomerId cannot be empty.\nPlease provide Customer ID for Azure Cloud.")
		}
		if helper.IsValEmpty(azureSharedKeySSM) {
			logger.Fatalln("If AddSupportforAzureCloud is set to true, then AzureSharedKeySSM cannot be empty.\nPlease provide name of SSM Parameter Store item which contains Shared Key for Azure Cloud")
		}
		if helper.IsValEmpty(azureLogType) {
			logger.Fatalln("If AddSupportforAzureCloud is set to true, then AzureLogType cannot be empty.\nPlease provide Log Type for Azure Cloud LogAnalytics.")
		}
	}
}

func validatePagerDutyParams(addSupportforPagerDuty bool) {
	createIncidentForSeverityTypes := os.Getenv("CreateIncidentForSeverityTypes")
	pagerDutyIntegrationType := os.Getenv("PagerDutyIntegrationType")
	pagerDutyRoutingKeySSM := os.Getenv("PagerDutyRoutingKeySSM")
	pagerDutyServiceId := os.Getenv("PagerDutyServiceId")
	pagerDutyApiTokenSSM := os.Getenv("PagerDutyApiTokenSSM")
	pagerDutyUserEmailAddress := os.Getenv("PagerDutyUserEmailAddress")
	if addSupportforPagerDuty {
		if helper.IsValEmpty(createIncidentForSeverityTypes) {
			logger.Fatalln("If AddSupportforPagerDuty is set to true, then CreateIncidentForSeverityTypes cannot be empty. \nPlease give comma separated severity type of findings you want to create incidents for on PagerDuty. \nAllowed values are CRITICAL, HIGH, MEDIUM, LOW, ALL. \ne.g., CRITICAL,HIGH")
		} else {
			validateSeverityTypes("CreateIncidentForSeverityTypes")
		}

		validPattern := regexp.MustCompile(`^(EventsAPIv2|RESTAPI)$`)
		if !validPattern.MatchString(pagerDutyIntegrationType) {
			logger.Fatalf("Invalid Value for PagerDutyIntegrationType. It can either be 'EventsAPIv2' or 'RESTAPI'.")
		}
		if pagerDutyIntegrationType == "EventsAPIv2" {
			if helper.IsValEmpty(pagerDutyRoutingKeySSM) {
				logger.Fatalln(`If PagerDutyIntegrationType is set to EventsAPIv2, then PagerDutyRoutingKeySSM cannot be empty.
				Please provide name of SSM Parameter Store item which contains Routing/Integration Key for Events API v2 for PagerDuty.`)
			}
			if !helper.IsValEmpty(pagerDutyServiceId) {
				logger.Fatalln("If PagerDutyIntegrationType is set to EventsAPIv2, value for PagerDutyServiceId cannot be provided.")
			}
		} else if pagerDutyIntegrationType == "RESTAPI" {
			if helper.IsValEmpty(pagerDutyApiTokenSSM) {
				logger.Fatalln(`If PagerDutyIntegrationType is set to RESTAPI, then PagerDutyApiTokenSSM cannot be empty.
				Please provide name of SSM Parameter Store item which contains API Token for PagerDuty.`)
			}
			if helper.IsValEmpty(pagerDutyServiceId) {
				logger.Fatalln(`If PagerDutyIntegrationType is set to RESTAPI, then PagerDutyServiceId cannot be empty.
				Please provide Service ID for Service on PagerDuty where incidents are to be created.`)
			}
			if helper.IsValEmpty(pagerDutyUserEmailAddress) {
				logger.Fatalln(`If PagerDutyIntegrationType is set to RESTAPI, then PagerDutyUserEmailAddress cannot be empty.
				Please provide email address of a valid PagerDuty user on the account associated with the auth token.`)
			}
		}
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
