package yamlenv

import (
	"fmt"
	"log"
	"os"
	"rrcore/cmd/helper"
	"rrcore/cmd/logger"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"
)

type StackNames struct {
	CfStackSetAdministrationRoleStackName  string
	CfStackSetExecutionRoleStackSetName    string
	LambdaLayersStackName                  string
	ManagementAccountStackName             string
	AutomationDynamoDbTablesStackName      string
	AutomationAccountSecretsStackName      string
	AutomationAccountStackName             string
	VpcFlowLogsDeliveryKmsKeyStackSetName  string
	VpcFlowLogsDeliveryBucketStackSetName  string
	GuardDutyDeliveryKmsKeyStackSetName    string
	GuardDutyDeliveryBucketStackSetName    string
	GuardDutyAdminDelegationStackSetName   string
	GuardDutyEnablerStackSetName           string
	InspectorAdminDelegationStackSetName   string
	InspectorEnablerStackSetName           string
	SecurityHubAdminDelegationStackSetName string
	SecurityHubEnablerStackSetName         string
	SSMDocumentStackName                   string
	OrgChildStackSetName                   string
}

func LoadAllEnvVars(dirPath string) (map[string]string, map[string]any, map[string]any, error) {
	envVarsMap := make(map[string]string)
	files, err := getYAMLFilesInDir(dirPath)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, file := range files {
		envVars, err := loadEnvVarsFromYAML(file)
		if err != nil {
			log.Fatalf("Error loading YAML file: %v", err)
			return nil, nil, nil, err
		}

		exportedVars, err := exportYamlVars(envVars)
		if err != nil {
			return nil, nil, nil, err
		}
		for key, value := range exportedVars {
			envVarsMap[key] = value
		}
	}
	ssmNamesMap, secretNamesMap, notificationsConfigSecretNamesMap := getAllSSMParameterItemsNamesMap(envVarsMap)
	return ssmNamesMap, secretNamesMap, notificationsConfigSecretNamesMap, nil
}

func LoadAllStackNames(filePath string) (*StackNames, error) {
	var stackNames StackNames
	envVars, err := loadEnvVarsFromYAML(filePath)
	if err != nil {
		log.Fatalf("Error loading YAML file: %v", err)
		return nil, err
	}
	for yamlVar, yamlValue := range envVars {
		formattedVal := helper.ReplaceEnvVarVal("ProjectName", yamlValue)
		if err := os.Setenv(yamlVar, formattedVal); err != nil {
			return nil, err
		}
		if yamlVar == "CloudFormationStackSetAdministrationRoleStackName" {
			stackNames.CfStackSetAdministrationRoleStackName = formattedVal
		} else if yamlVar == "CloudFormationStackSetExecutionRoleStackSetName" {
			stackNames.CfStackSetExecutionRoleStackSetName = formattedVal
		} else if yamlVar == "LambdaLayersStackName" {
			stackNames.LambdaLayersStackName = formattedVal
		} else if yamlVar == "ManagementAccountStackName" {
			stackNames.ManagementAccountStackName = formattedVal
		} else if yamlVar == "AutomationDynamoDbTablesStackName" {
			stackNames.AutomationDynamoDbTablesStackName = formattedVal
		} else if yamlVar == "AutomationAccountSecretsStackName" {
			stackNames.AutomationAccountSecretsStackName = formattedVal
		} else if yamlVar == "AutomationAccountStackName" {
			stackNames.AutomationAccountStackName = formattedVal
		} else if yamlVar == "VpcFlowLogsDeliveryKmsKeyStackSetName" {
			stackNames.VpcFlowLogsDeliveryKmsKeyStackSetName = formattedVal
		} else if yamlVar == "VpcFlowLogsDeliveryBucketStackSetName" {
			stackNames.VpcFlowLogsDeliveryBucketStackSetName = formattedVal
		} else if yamlVar == "GuardDutyDeliveryKmsKeyStackSetName" {
			stackNames.GuardDutyDeliveryKmsKeyStackSetName = formattedVal
		} else if yamlVar == "GuardDutyDeliveryBucketStackSetName" {
			stackNames.GuardDutyDeliveryBucketStackSetName = formattedVal
		} else if yamlVar == "GuardDutyAdminDelegationStackSetName" {
			stackNames.GuardDutyAdminDelegationStackSetName = formattedVal
		} else if yamlVar == "GuardDutyEnablerStackSetName" {
			stackNames.GuardDutyEnablerStackSetName = formattedVal
		} else if yamlVar == "InspectorAdminDelegationStackSetName" {
			stackNames.InspectorAdminDelegationStackSetName = formattedVal
		} else if yamlVar == "InspectorEnablerStackSetName" {
			stackNames.InspectorEnablerStackSetName = formattedVal
		} else if yamlVar == "SecurityHubAdminDelegationStackSetName" {
			stackNames.SecurityHubAdminDelegationStackSetName = formattedVal
		} else if yamlVar == "SecurityHubEnablerStackSetName" {
			stackNames.SecurityHubEnablerStackSetName = formattedVal
		} else if yamlVar == "SSMDocumentStackName" {
			stackNames.SSMDocumentStackName = formattedVal
		} else if yamlVar == "OrgChildStackSetName" {
			stackNames.OrgChildStackSetName = formattedVal
		}
	}
	return &stackNames, nil
}

func loadEnvVarsFromYAML(filePath string) (map[string]string, error) {
	// Read the YAML file
	file, err := os.ReadFile(filePath) // #nosec G304 -- filePath comes from repository configuration discovery.
	if err != nil {
		return nil, err
	}

	// Unmarshal the YAML into a generic map
	config := make(map[string]interface{})
	err = yaml.Unmarshal(file, &config)
	if err != nil {
		return nil, err
	}

	envVars := make(map[string]string)
	for key, value := range config {
		envVars[key] = fmt.Sprintf("%v", value)
	}

	return envVars, nil
}

func exportYamlVars(envVars map[string]string) (map[string]string, error) {
	mappedVars := make(map[string]string)
	for yamlVar, yamlValue := range envVars {
		mappedVars[yamlVar] = yamlValue
		formattedVal := ""
		if helper.IsValEmpty(yamlValue) {
			formattedVal = ""
		} else {
			formattedVal = yamlValue
		}
		if err := os.Setenv(yamlVar, formattedVal); err != nil {
			return nil, err
		}
		logger.Debugln("Set " + yamlVar + "=" + redactDebugValue(yamlVar, formattedVal))
	}
	logger.Debugln("Set DEBUG=" + os.Getenv("DEBUG"))
	return mappedVars, nil
}

func redactDebugValue(key, value string) string {
	if value == "" {
		return ""
	}
	lowerKey := strings.ToLower(key)
	sensitiveMarkers := []string{"secret", "token", "password", "credential", "webhook", "key"}
	for _, marker := range sensitiveMarkers {
		if strings.Contains(lowerKey, marker) {
			return "[REDACTED]"
		}
	}
	trimmedValue := strings.TrimSpace(value)
	if len(trimmedValue) > 256 && (strings.HasPrefix(trimmedValue, "{") || strings.HasPrefix(trimmedValue, "[")) {
		return "[REDACTED]"
	}
	return value
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func getNotificationsAppSupportedConfig(notificationsApp string) []string {
	if notificationsApp == "slack" {
		return []string{
			"WEBHOOK BASED",
			"APP BASED",
		}
	} else {
		return []string{
			"WEBHOOK BASED",
		}
	}
}

func getAllSSMParameterItemsNamesMap(envVars map[string]string) (map[string]string, map[string]any, map[string]any) {
	notificationsConfigSecretNamesMap := map[string]any{}
	notificationsConfigVars := map[string]map[string]string{
		"APP BASED": {
			"BOT_OAUTH_TOKEN": "OAuth Token for your Slack bot App",
			"CHANNEL_ID":      "ID of the Slack channel designated to receive threat alerts",
		},
		"WEBHOOK BASED": {
			"WEBHOOK_URL": "Webhook URL",
		},
	}
	notificationsConfigCfVars := map[string]map[string]string{
		"Engineer Facing": {
			"EngineerFacingNotificationsApp": "EngineerFacingNotificationsConfigsSecretName",
		},
		"Security Admin Facing": {
			"SecurityAdminFacingNotificationsApp": "SecurityAdminFacingNotificationsConfigsSecretName",
		},
	}
	secretNamesMap := map[string]any{}
	var slackSecretKeys map[string]string
	enableSlackSocketMode, _ := strconv.ParseBool(os.Getenv("EnableSlackSocketMode"))
	if enableSlackSocketMode {
		slackSecretKeys = map[string]string{
			"BOT_OAUTH_TOKEN":     "OAuth Token for your Slack bot",
			"BOT_APP_TOKEN":       "App-level token for Slack Socket Mode connection",
			"SECURITY_CHANNEL_ID": "ID of the Slack channel designated for security notifications",
		}
	} else {
		slackSecretKeys = map[string]string{
			"BOT_OAUTH_TOKEN":      "OAuth Token for your Slack bot",
			"SECURITY_CHANNEL_ID":  "ID of the Slack channel designated for security notifications",
			"SLACK_SIGNING_SECRET": "Signing Secret from Slack used to verify that incoming requests are authentic",
		}
	}
	secretCfVars := map[string]map[string]map[string]string{
		"SlackBotConfigSecretName": {
			"Slack Bot configuration secret": slackSecretKeys,
		},
	}

	ssmNamesMap := make(map[string]string)
	dependentSsmCfVars := map[string]map[string]string{
		"AddSupportforAzureCloud": {
			"AzureSharedKeySSM": "Shared Key for Azure Cloud",
		},
		"AddSupportforPagerDuty": {
			"PagerDutyRoutingKeySSM": "Routing/Integration Key for Events API v2 for PagerDuty",
			"PagerDutyApiTokenSSM":   "API token for PagerDuty REST API",
		},
		"TrackTailscaleIPs": {
			"OAuthClientSecretSSM": "Oauth Client Secret for TailScale",
		},
	}

	for notificationType, CfKeys := range notificationsConfigCfVars {
		for notificationsAppCfKey, notificationsConfigSecretCfKey := range CfKeys {
			notificationsApp := envVars[notificationsAppCfKey]
			notificationsConfigSecretName := envVars[notificationsConfigSecretCfKey]
			if !helper.IsValEmpty(notificationsApp) && !helper.IsValEmpty(notificationsConfigSecretName) {
				notificationsConfig := make(map[string]map[string]string)
				for _, cfg := range getNotificationsAppSupportedConfig(notificationsApp) {
					notificationsConfig[cfg] = notificationsConfigVars[cfg]
				}
				notificationsConfigSecretNamesMap[notificationsConfigSecretName] = map[string]any{
					"NotificationType":     notificationType,
					"NotificationAppCfKey": notificationsAppCfKey,
					"DependentSecrets":     notificationsConfig,
				}
			}
		}
	}

	for secretCfKey, dependentSecrets := range secretCfVars {
		secretName := envVars[secretCfKey]
		if !helper.IsValEmpty(secretName) {
			secretNamesMap[secretName] = map[string]any{
				"CfKey":            secretCfKey,
				"DependentSecrets": dependentSecrets,
			}
		}
	}

	for ssmCfKey, ssmCfValue := range dependentSsmCfVars {
		envBool, err := strconv.ParseBool(envVars[ssmCfKey])
		if err != nil {
			logger.Errorf("Error parsing boolean for key %s: %v", ssmCfKey, err)
			continue
		}
		if envBool {
			if ssmCfKey == "AddSupportforPagerDuty" {
				if envVars["PagerDutyIntegrationType"] == "EventsAPIv2" {
					for ssmName, ssmDesc := range ssmCfValue {
						if ssmName == "PagerDutyRoutingKeySSM" {
							ssmNamesMap[envVars[ssmName]] = ssmDesc
						}
					}
				} else if envVars["PagerDutyIntegrationType"] == "RESTAPI" {
					for ssmName, ssmDesc := range ssmCfValue {
						if ssmName == "PagerDutyApiTokenSSM" {
							ssmNamesMap[envVars[ssmName]] = ssmDesc
						}
					}
				}
			} else {
				for ssmName, ssmDesc := range ssmCfValue {
					ssmNamesMap[envVars[ssmName]] = ssmDesc
				}
			}
		}
	}
	return ssmNamesMap, secretNamesMap, notificationsConfigSecretNamesMap
}
