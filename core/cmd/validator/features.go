package validator

import (
	"encoding/json"
	"os"
	"rrcore/cmd/helper"
	"rrcore/cmd/logger"
	"strconv"
	"strings"
)

var requiredSCPTagKeys = map[string]bool{
	"DeployedBy":   true,
	"DeployMethod": true,
	"Team":         true,
}

func validateCMDBParams(addSupportforCMDB bool) {
	tagResourcesKey := []string{
		"TagEC2Instances",
		"TagEksClusters",
		"TagRDSClusterInstances",
		"TagEFS",
	}
	if addSupportforCMDB {
		for _, envKey := range tagResourcesKey {
			keyVal, _ := strconv.ParseBool(os.Getenv(envKey))
			if !keyVal {
				logger.Fatalf("If AddSupportforCMDB is set to true, then %s also has to be true", envKey)
			}
		}
	}
}

func validateManagedPolicy(createNewManagedPolicy bool) {
	managedPolicyName := os.Getenv("ManagedPolicyName")
	managedPolicyDocumentJson := os.Getenv("ManagedPolicyDocumentJson")
	if createNewManagedPolicy {
		if helper.IsValEmpty(managedPolicyName) {
			logger.Fatalln("If CreateNewManagedPolicy is set to true, ManagedPolicyName cannot be empty.\nPlease provide a name for the new policy in ManagedPolicyName.")
		}
		if helper.IsValEmpty(managedPolicyDocumentJson) {
			logger.Fatalln("If CreateNewManagedPolicy is set to true, ManagedPolicyDocumentJson cannot be empty.\nPlease provide a valid JSON document for the new policy in ManagedPolicyDocumentJson.")
		}

		var jsonCheck map[string]interface{}
		if err := json.Unmarshal([]byte(managedPolicyDocumentJson), &jsonCheck); err != nil {
			logger.Fatalln("Invalid JSON format in ManagedPolicyDocumentJson.\nPlease provide a correctly formatted JSON document.")
		}
	}
}

func validateSSMDocumentContentJson() {
	ssmDocumentContentJson := os.Getenv("SSMDocumentContentJson")
	if helper.IsValEmpty(ssmDocumentContentJson) {
		logger.Fatalln("SSMDocumentContentJson cannot be empty. Please provide valid JSON for shared SSM Document in SSMDocumentContentJson.")
	} else {
		validateParamsPlaceholders("SSMDocumentContentJson")
		var jsonCheck map[string]interface{}
		if err := json.Unmarshal([]byte(ssmDocumentContentJson), &jsonCheck); err != nil {
			logger.Fatalln("Invalid JSON format in SSMDocumentContentJson.\n🔧 Please provide a correctly formatted JSON document.")
		}
	}
}

func validateAlertsCustomisationParams() {
	params := []struct {
		disableVar string
		blockVar   string
	}{
		{"DisableFindingEC2LaunchWithoutIMDSv2", "BlockEC2LaunchWithoutIMDSV2"},
		{"DisableFindingEC2LaunchWithPublicIP", "BlockEC2LaunchWithPublicIP"},
		{"DisableFindingUnencryptedEBSVolume", "BlockUnencryptedEBSVolumeCreation"},
	}
	for _, param := range params {
		disable, _ := strconv.ParseBool(os.Getenv(param.disableVar))
		block, _ := strconv.ParseBool(os.Getenv(param.blockVar))

		if disable && block {
			logger.Fatalf("If %s is set to true, SCP cannot be enabled for the same.\nPlease set %s to false.", param.disableVar, param.blockVar)
		}
	}
}

func validateSCPParams(AddSupportforCMDB bool) {
	params := []struct {
		envVarBlock string
		envVarTags  string
	}{
		{"BlockEC2LaunchWithoutCertainTags", "EC2InstanceLaunchSCPTagKeys"},
		{"BlockEksClusterCreationWithoutCertainTags", "EksClusterCreationSCPTagKeys"},
		{"BlockRdsClusterInstanceCreationWithoutCertainTags", "RdsClusterInstanceCreationSCPTagKeys"},
		{"BlockEfsFileSystemCreationWithoutCertainTags", "EfsFileSystemCreationSCPTagKeys"},
	}

	for _, param := range params {
		blockEnabled, _ := strconv.ParseBool(os.Getenv(param.envVarBlock))
		tagKeys := os.Getenv(param.envVarTags)

		if blockEnabled {
			if helper.IsValEmpty(tagKeys) {
				logger.Fatalf("If %s is set to true, then %s cannot be empty. \nPlease provide tag keys e.g. key1,key2,key3", param.envVarBlock, param.envVarTags)
			}
			if AddSupportforCMDB && !checkTags(tagKeys) {
				logger.Fatalf("If AddSupportforCMDB is set to true, then %s needs to have DeployedBy, DeployMethod and Team tags along with your desired tags. \nPlease add DeployedBy,DeployMethod,Team tag keys to your list in order to proceed.", param.envVarTags)
			}
		}
	}
}

func validateAutoTaggerParams(addSupportforCMDB bool) {
	params := []struct {
		tagResource        string
		notifyResource     string
		tagsKeyValue       string
		tagTemplate        string
		tagKeysForTemplate string
	}{
		{"TagVPCs", "SendMissingTagsNotificationVPCs", "TagsKeyValueVPCs", "TagVPCUsingTagTemplateForTerraformDeployment", "VPCTagKeysForTagTemplateGeneration"},
		{"TagSubnets", "SendMissingTagsNotificationSubnets", "TagsKeyValueSubnets", "TagSubnetUsingTagTemplateForTerraformDeployment", "SubnetTagKeysForTagTemplateGeneration"},
		{"TagEbsVolumes", "SendMissingTagsNotificationEbsVolumes", "TagsKeyValueEbsVolumes", "TagEbsVolumeUsingTagTemplateForTerraformDeployment", "EbsVolumeTagKeysForTagTemplateGeneration"},
		{"TagEIPs", "SendMissingTagsNotificationEIPs", "TagsKeyValueEIPs", "TagEIPUsingTagTemplateForTerraformDeployment", "EIPTagKeysForTagTemplateGeneration"},
		{"TagEbsSnapshots", "SendMissingTagsNotificationEbsSnapshots", "TagsKeyValueEbsSnapshots", "TagEbsSnapshotUsingTagTemplateForTerraformDeployment", "EbsSnapshotTagKeysForTagTemplateGeneration"},
		{"TagAMIs", "SendMissingTagsNotificationAMIs", "TagsKeyValueAMIs", "TagAMIUsingTagTemplateForTerraformDeployment", "AMITagKeysForTagTemplateGeneration"},
		{"TagEC2Instances", "SendMissingTagsNotificationEC2Instances", "TagsKeyValueEC2Instances", "TagEC2InstanceUsingTagTemplateForTerraformDeployment", "EC2InstanceTagKeysForTagTemplateGeneration"},
		{"TagEksClusters", "SendMissingTagsNotificationEksClusters", "TagsKeyValueEksClusters", "TagEksClusterUsingTagTemplateForTerraformDeployment", "EksClusterTagKeysForTagTemplateGeneration"},
		{"TagRDSClusterInstances", "SendMissingTagsNotificationRDSClusterInstances", "TagsKeyValueRDSClusterInstances", "TagRDSClusterInstanceUsingTagTemplateForTerraformDeployment", "RDSClusterInstanceTagKeysForTagTemplateGeneration"},
		{"TagEFS", "SendMissingTagsNotificationEFS", "TagsKeyValueEFS", "TagEfsUsingTagTemplateForTerraformDeployment", "EFSTagKeysForTagTemplateGeneration"},
		{"TagFSX", "SendMissingTagsNotificationFSX", "TagsKeyValueFSX", "TagFsxUsingTagTemplateForTerraformDeployment", "FSXTagKeysForTagTemplateGeneration"},
		{"TagSecrets", "SendMissingTagsNotificationSecrets", "TagsKeyValueSecrets", "TagSecretUsingTagTemplateForTerraformDeployment", "SecretTagKeysForTagTemplateGeneration"},
		{"TagBackupPlans", "SendMissingTagsNotificationBackupPlans", "TagsKeyValueBackupPlans", "TagBackupPlanUsingTagTemplateForTerraformDeployment", "BackupPlanTagKeysForTagTemplateGeneration"},
		{"TagLoadbalancers", "SendMissingTagsNotificationLoadbalancers", "TagsKeyValueLoadbalancers", "TagLoadbalancerUsingTagTemplateForTerraformDeployment", "LoadbalancerTagKeysForTagTemplateGeneration"},
	}
	cmdbParams := []string{
		"EC2InstanceTagKeysForTagTemplateGeneration",
		"EksClusterTagKeysForTagTemplateGeneration",
		"RDSClusterInstanceTagKeysForTagTemplateGeneration",
		"EFSTagKeysForTagTemplateGeneration",
	}

	for _, param := range params {
		tagResource, _ := strconv.ParseBool(os.Getenv(param.tagResource))
		notifyResource, _ := strconv.ParseBool(os.Getenv(param.notifyResource))
		tagsKeyValue := os.Getenv(param.tagsKeyValue)
		tagTemplate, _ := strconv.ParseBool(os.Getenv(param.tagTemplate))
		tagKeysForTemplate := os.Getenv(param.tagKeysForTemplate)

		if tagResource {
			if notifyResource {
				logger.Fatalf("If %s is set to true, %s cannot be set to true", param.tagResource, param.notifyResource)
			}
			if helper.IsValEmpty(tagsKeyValue) {
				logger.Fatalf("If %s is set to true, then %s cannot be empty.\nPlease provide tags key-value e.g. \"key1=value1,key2=value2\"", param.tagResource, param.tagsKeyValue)
			}
		}
		if tagTemplate {
			if !tagResource {
				logger.Fatalf("If %s is set to true, then %s also has to be true", param.tagTemplate, param.tagResource)
			}
			if helper.IsValEmpty(tagKeysForTemplate) {
				logger.Fatalf("If %s is set to true, then %s cannot be empty.\nPlease provide tag keys for tag template generation.", param.tagTemplate, param.tagKeysForTemplate)
			}
			if addSupportforCMDB && contains(cmdbParams, param.tagKeysForTemplate) {
				if !checkTags(tagKeysForTemplate) {
					logger.Fatalf("If AddSupportforCMDB is set to true, then %s needs to have DeployedBy, DeployMethod and Team tags as well along with your desired tags. \nPlease add DeployedBy,DeployMethod,Team tag keys to your list in order to proceed.", param.tagKeysForTemplate)
				}
			}
		}
	}
}

func checkTags(tags string) bool {
	tagsToCheck := []string{"DeployedBy", "DeployMethod", "Team"}
	tagList := strings.Split(tags, ",")
	tagMap := make(map[string]bool)
	for _, tag := range tagList {
		tagMap[strings.TrimSpace(tag)] = true
	}
	for _, requiredTag := range tagsToCheck {
		if !tagMap[requiredTag] {
			return false
		}
	}
	return true
}
