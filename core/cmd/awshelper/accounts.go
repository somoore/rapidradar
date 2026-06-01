package awshelper

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"rrcore/cmd/helper"
	"rrcore/cmd/logger"
	"rrcore/cmd/spinner"
	"rrcore/cmd/yamlenv"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgTypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

const (
	MAX_RETRY_ATTEMPTS  = 5
	DELAY_SECONDS       = 2
	ORG_THROTTLE_PERIOD = 2 * time.Second
)

type AWSOrgMetadata struct {
	ManagementAccountProfileName string
	ManagementAccountId          string
	ManagementAccountRegion      string
	AutomationAccountProfileName string
	AutomationAccountId          string
	AutomationAccountRegion      string
	LogArchiveAccountId          string
	GuardDutyAdminAccountId      string
	InspectorAdminAccountId      string
	SecurityHubAdminAccountId    string
	OrganizationId               string
}

func GetAWSAccountDetails(automationAccountStackName string) (*AWSOrgMetadata, error) {
	managementAccountProfileName := os.Getenv("ManagementAccountProfileName")
	var automationAccountProfileName string
	var err error

	// if ManagementAccountProfileName is empty, prompt user to select profile
	if helper.IsValEmpty(managementAccountProfileName) {
		managementAccountProfileName, err = getAndSetProfileName("ManagementAccountProfileName", "Management Account")
		if err != nil {
			logger.Errorln("Failed to get Management Account Profile name")
			return nil, err
		}
		err = yamlenv.UpdateYAML("env/common.yml", "ManagementAccountProfileName", managementAccountProfileName)
		if err != nil {
			logger.Errorln("Failed to add value for ManagementAccountProfileName to env/common.yml")
			return nil, err
		}
	}
	// Set management account ID and region
	managementAccountId, err := getAWSAccountID(managementAccountProfileName)
	if err != nil {
		logger.Errorln("Failed to get ID of Management Account")
		return nil, err
	}
	managementAccountRegion, err := getAWSRegion(managementAccountProfileName)
	if err != nil {
		logger.Errorln("Failed to get Region of Management Account")
		return nil, err
	}

	// Check if Delegated Admin is set for CloudFormation StackSet
	cfStackSetDelegatedAdmin, err := getCfStackSetDelegatedAdmin(managementAccountProfileName)
	if err != nil {
		logger.Errorln("Failed to get delegated Admin of Cloudformation StackSet")
		return nil, err
	}

	// If Delegated Admin is not set for CloudFormation StackSets, set AutomationAccountProfileName=ManagementAccountProfileName,
	// Otherwise, check if stack already exists in management account, if it does, set AutomationAccountProfileName=ManagementAccountProfileName,
	// else prompt user to select profile for Automation Account
	if cfStackSetDelegatedAdmin == "" {
		automationAccountProfileName = managementAccountProfileName
	} else {
		cfg, err := config.LoadDefaultConfig(context.TODO(),
			config.WithSharedConfigProfile(managementAccountProfileName),
			config.WithRegion(managementAccountRegion),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to load AWS config: %w", err)
		}
		cfnClient := cloudformation.NewFromConfig(cfg)

		automationAccountStackExists, _, err := checkIfStackExists(cfnClient, automationAccountStackName)
		if err != nil {
			logger.Errorf("Failed to check existence of Cloudformation Stack %s in Management Account %s", automationAccountStackName, managementAccountId)
			return nil, err
		}
		if automationAccountStackExists {
			automationAccountProfileName = managementAccountProfileName
		} else {
			automationAccountProfileName = os.Getenv("AutomationAccountProfileName")
			if helper.IsValEmpty(automationAccountProfileName) {
				spinner.Pause()
				logger.Warnf("You have AWS Account %s set as Delegated Administrator for CloudFormation StackSets. PLEASE SELECT PROFILE FOR THIS ACCOUNT!", cfStackSetDelegatedAdmin)
				spinner.Resume()
				automationAccountProfileName, err = getAndSetProfileName("AutomationAccountProfileName", "Automation Account")
				if err != nil {
					logger.Errorln("Failed to get Automation Account Profile name")
					return nil, err
				}
				err = yamlenv.UpdateYAML("env/common.yml", "AutomationAccountProfileName", automationAccountProfileName)
				if err != nil {
					logger.Errorln("Failed to add value for AutomationAccountProfileName to env/common.yml")
					return nil, err
				}
			}
		}
	}

	// Set automation account ID and region
	automationAccountId, err := getAWSAccountID(automationAccountProfileName)
	if err != nil {
		logger.Errorln("Failed to get ID of Automation Account")
		return nil, err
	}
	automationAccountRegion, err := getAWSRegion(automationAccountProfileName)
	if err != nil {
		logger.Errorln("Failed to get Region of Automation Account")
		return nil, err
	}

	// get Organization ID
	organizationID, err := getOrganizationID(managementAccountProfileName)
	if err != nil {
		logger.Errorln("Failed to get ID of current Organization")
		return nil, err
	}

	return &AWSOrgMetadata{
		ManagementAccountProfileName: managementAccountProfileName,
		ManagementAccountId:          managementAccountId,
		ManagementAccountRegion:      managementAccountRegion,
		AutomationAccountProfileName: automationAccountProfileName,
		AutomationAccountId:          automationAccountId,
		AutomationAccountRegion:      automationAccountRegion,
		LogArchiveAccountId:          os.Getenv("LogArchiveAccountId"),
		GuardDutyAdminAccountId:      os.Getenv("GuardDutyAdminAccountId"),
		InspectorAdminAccountId:      os.Getenv("InspectorAdminAccountId"),
		SecurityHubAdminAccountId:    os.Getenv("SecurityHubAdminAccountId"),
		OrganizationId:               organizationID,
	}, nil
}

func getAndSetProfileName(key, long string) (string, error) {
	allProfiles, err := getAWSProfilesCLI()
	if err != nil {
		log.Fatalf("failed to get all Profiles: %v", err)
		return "", err
	}
	spinner.Pause()
	profileName := helper.AskWithSelection(fmt.Sprintf("Select %s Profile name: ", long), allProfiles)
	spinner.Resume()
	if err := os.Setenv(key, profileName); err != nil {
		return "", err
	}
	return profileName, nil
}

func getAWSProfilesCLI() ([]string, error) {
	cmd := exec.Command("aws", "configure", "list-profiles")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running aws cli: %w", err)
	}

	profiles := strings.Split(strings.TrimSpace(string(output)), "\n")
	return profiles, nil
}

func getOrganizationID(profile string) (string, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %w", err)
	}

	orgClient := organizations.NewFromConfig(cfg)

	output, err := orgClient.DescribeOrganization(context.TODO(), &organizations.DescribeOrganizationInput{})
	if err != nil {
		return "", fmt.Errorf("failed to describe organization: %w", err)
	}

	return *output.Organization.Id, nil
}

func getRootOU(profile string) (string, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %w", err)
	}
	orgClient := organizations.NewFromConfig(cfg)

	resp, err := orgClient.ListRoots(context.TODO(), &organizations.ListRootsInput{})
	if err != nil {
		return "", fmt.Errorf("failed to list roots: %w", err)
	}
	if len(resp.Roots) == 0 {
		return "", fmt.Errorf("no root found in the organization")
	}

	return *resp.Roots[0].Id, nil
}

func getAccountParentOU(profile, accountId string) (string, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %w", err)
	}

	orgClient := organizations.NewFromConfig(cfg)
	resp, err := orgClient.ListParents(context.TODO(), &organizations.ListParentsInput{
		ChildId: aws.String(accountId),
	})
	if err != nil {
		return "", fmt.Errorf("failed to list parents: %w", err)
	}

	return *resp.Parents[0].Id, nil
}

func GetOUIdsforAccounts(profile string, deploymentTargets []string) ([]string, error) {
	seenOU := make(map[string]bool)
	var orgUnitIds []string
	for _, account := range deploymentTargets {
		parentOU, err := getAccountParentOU(profile, account)
		if err != nil {
			return nil, fmt.Errorf("failed to get parent OU of Account %s: %w", account, err)
		}
		if !seenOU[parentOU] {
			seenOU[parentOU] = true
			orgUnitIds = append(orgUnitIds, parentOU)
		}
	}
	logger.Debugf("Parent OUs of AWS accounts [%s] in DeploymentTargets:\n%s", strings.Join(deploymentTargets, ", "), strings.Join(orgUnitIds, ", "))
	return orgUnitIds, nil
}

func getDeploymentTargetChildren(orgClient *organizations.Client, childType orgTypes.ChildType, ouId, managementAccountId string, excludedAccounts []string) ([]string, error) {
	ctx := context.TODO()
	children := []string{}
	retryAttempts := 0
	delay := time.Duration(DELAY_SECONDS) * time.Second
	baseInput := &organizations.ListChildrenInput{
		ParentId:  aws.String(ouId),
		ChildType: childType,
	}
	nextToken := aws.String("")
	for retryAttempts < MAX_RETRY_ATTEMPTS {
		tryNext := true
		for tryNext {
			input := *baseInput
			if *nextToken != "" {
				input.NextToken = nextToken
			}
			time.Sleep(ORG_THROTTLE_PERIOD)
			response, err := orgClient.ListChildren(ctx, &input)
			if err != nil {
				if retryAttempts < MAX_RETRY_ATTEMPTS {
					retryAttempts++
					logger.Debugf("%s. Retrying in %d seconds...", err.Error(), delay)
					time.Sleep(delay)
					delay *= 2
					continue
				}
				return nil, fmt.Errorf("failed to list children: %w", err)
			}
			for _, child := range response.Children {
				if childType == orgTypes.ChildTypeAccount {
					if !contains(excludedAccounts, *child.Id) && *child.Id != managementAccountId {
						children = append(children, *child.Id)
					}
				} else if childType == orgTypes.ChildTypeOrganizationalUnit {
					accountChildren, err := getDeploymentTargetChildren(orgClient, orgTypes.ChildTypeAccount, *child.Id, managementAccountId, excludedAccounts)
					if err != nil {
						return nil, err
					}
					children = append(children, accountChildren...)

					ouChildren, err := getDeploymentTargetChildren(orgClient, orgTypes.ChildTypeOrganizationalUnit, *child.Id, managementAccountId, excludedAccounts)
					if err != nil {
						return nil, err
					}
					children = append(children, ouChildren...)
				}
			}
			if response.NextToken == nil {
				tryNext = false
			} else {
				nextToken = response.NextToken
			}
		}
		break
	}
	return children, nil
}

func getDeploymentTargetActiveAccounts(orgClient *organizations.Client, deploymentTargetsType, managementAccountId string, deploymentTargets, excludedAccounts []string) ([]string, error) {
	allAccounts := []string{}
	activeAccounts := []string{}
	retryAttempts := 0
	delay := time.Duration(DELAY_SECONDS) * time.Second

	for retryAttempts < MAX_RETRY_ATTEMPTS {
		tryNext := true
		for tryNext {
			if deploymentTargetsType == "STANDALONE" {
				allAccounts = append(allAccounts, deploymentTargets...)
			} else {
				for _, target := range deploymentTargets {
					accounts, err := getDeploymentTargetChildren(orgClient, orgTypes.ChildTypeAccount, target, managementAccountId, excludedAccounts)
					if err != nil {
						return nil, err
					}
					allAccounts = append(allAccounts, accounts...)
					accounts, err = getDeploymentTargetChildren(orgClient, orgTypes.ChildTypeOrganizationalUnit, target, managementAccountId, excludedAccounts)
					if err != nil {
						return nil, err
					}
					allAccounts = append(allAccounts, accounts...)
				}
			}
			for _, account := range allAccounts {
				response, err := orgClient.DescribeAccount(context.TODO(), &organizations.DescribeAccountInput{
					AccountId: &account,
				})
				if err != nil {
					if retryAttempts < MAX_RETRY_ATTEMPTS {
						retryAttempts++
						logger.Debugf("%s. Retrying in %d seconds...", err.Error(), delay)
						time.Sleep(delay)
						delay *= 2
						continue
					}
					return nil, fmt.Errorf("failed to describe account: %w", err)
				}
				if response.Account != nil && response.Account.Status == orgTypes.AccountStatusActive {
					activeAccounts = append(activeAccounts, *response.Account.Id)
				}
				time.Sleep(ORG_THROTTLE_PERIOD)
			}
			break
		}
		break
	}
	return activeAccounts, nil
}

func GetAllOUActiveAccounts(profile, deploymentTargetsType, managementAccountId string, deploymentTargets, excludedAccounts []string) ([]string, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	orgClient := organizations.NewFromConfig(cfg)

	activeAccounts, err := getDeploymentTargetActiveAccounts(orgClient, deploymentTargetsType, managementAccountId, deploymentTargets, excludedAccounts)
	if err != nil {
		return nil, fmt.Errorf("failed to get all active accounts from deployment targets: %w", err)
	}
	logger.Debugf("Found %d active AWS accounts in DeploymentTargets: %s", len(activeAccounts), strings.Join(activeAccounts, ", "))
	return activeAccounts, nil
}

func GetSSORolePermissionAccounts(activeTargetAccounts []string, orgMetadata *AWSOrgMetadata) []string {
	ssoRolePermissionAccounts := activeTargetAccounts
	enableVpcFlowLogs, _ := strconv.ParseBool(os.Getenv("EnableVpcFlowLogs"))
	enableGuardDuty, _ := strconv.ParseBool(os.Getenv("EnableGuardDuty"))
	enableInspector, _ := strconv.ParseBool(os.Getenv("EnableInspector2"))
	enableSecurityHub, _ := strconv.ParseBool(os.Getenv("EnableSecurityHub"))

	if !helper.IsValEmpty(orgMetadata.LogArchiveAccountId) {
		if !contains(ssoRolePermissionAccounts, orgMetadata.LogArchiveAccountId) {
			ssoRolePermissionAccounts = append(ssoRolePermissionAccounts, orgMetadata.LogArchiveAccountId)
		}
		if enableVpcFlowLogs && orgMetadata.AutomationAccountId != orgMetadata.ManagementAccountId {
			if !contains(ssoRolePermissionAccounts, orgMetadata.AutomationAccountId) {
				ssoRolePermissionAccounts = append(ssoRolePermissionAccounts, orgMetadata.AutomationAccountId)
			}
		}
	}

	if enableGuardDuty && !helper.IsValEmpty(orgMetadata.GuardDutyAdminAccountId) {
		if !contains(ssoRolePermissionAccounts, orgMetadata.GuardDutyAdminAccountId) {
			ssoRolePermissionAccounts = append(ssoRolePermissionAccounts, orgMetadata.GuardDutyAdminAccountId)
		}
	}
	if enableInspector && !helper.IsValEmpty(orgMetadata.InspectorAdminAccountId) {
		if !contains(ssoRolePermissionAccounts, orgMetadata.InspectorAdminAccountId) {
			ssoRolePermissionAccounts = append(ssoRolePermissionAccounts, orgMetadata.InspectorAdminAccountId)
		}
	}
	if enableSecurityHub && !helper.IsValEmpty(orgMetadata.SecurityHubAdminAccountId) {
		if !contains(ssoRolePermissionAccounts, orgMetadata.SecurityHubAdminAccountId) {
			ssoRolePermissionAccounts = append(ssoRolePermissionAccounts, orgMetadata.SecurityHubAdminAccountId)
		}
	}
	logger.Debugf("Found %d active AWS accounts for SSO Role Permissions: %s", len(ssoRolePermissionAccounts), strings.Join(ssoRolePermissionAccounts, ", "))
	return ssoRolePermissionAccounts
}

func FilterAddRemoveAccounts(newAccounts, oldAccounts []string) (accountsToAdd []string, accountsToDelete []string) {
	for _, item := range newAccounts {
		if !contains(oldAccounts, item) {
			accountsToAdd = append(accountsToAdd, item)
		}
	}
	for _, item := range oldAccounts {
		if !contains(newAccounts, item) {
			accountsToDelete = append(accountsToDelete, item)
		}
	}
	return accountsToAdd, accountsToDelete
}

func FilterAddRemoveRegions(newActiveRegions, oldActiveRegions []string) (regionsToAdd []string, regionsToDelete []string) {
	for _, item := range newActiveRegions {
		if !contains(oldActiveRegions, item) {
			regionsToAdd = append(regionsToAdd, item)
		}
	}
	for _, item := range oldActiveRegions {
		if !contains(newActiveRegions, item) {
			regionsToDelete = append(regionsToDelete, item)
		}
	}
	return regionsToAdd, regionsToDelete
}
