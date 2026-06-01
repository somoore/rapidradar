package awshelper

import (
	"context"
	"fmt"
	"os"
	"rrcore/cmd/logger"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ses"
)

func EmailsAddedAsSESIdentity(profile, automationAccountId string) {
	senderEmailAddress := os.Getenv("SenderEmailAddress")
	receiverEmailAddresses := os.Getenv("ReceiverEmailAddressess")

	senderSesExists, err := checkSESIdentityExists(profile, senderEmailAddress)
	if err != nil {
		panic(fmt.Errorf("failed to check existence of sender emails ses identity: %w", err))
	}
	if !senderSesExists {
		logger.Fatalf("Your provided email address for SenderEmailAddress parameter does not exist as SES Idenity in %s AWS Account.\nPlease create SES Identity for email address %s or domain %s in %s AWS Account and verify it before going ahead with the deployment.", automationAccountId, senderEmailAddress, strings.Split(senderEmailAddress, "@")[1], automationAccountId)
	}
	for _, email := range strings.Split(receiverEmailAddresses, ",") {
		receiverSesExists, err := checkSESIdentityExists(profile, email)
		if err != nil {
			panic(fmt.Errorf("failed to check existence of receiver emails ses identity: %w", err))
		}
		if !receiverSesExists {
			logger.Fatalf("Your provided email address for ReceiverEmailAddressess parameter does not exist as SES Idenity in %s AWS Account.\nPlease create SES Identity for email address %s or domain %s in %s AWS Account and verify it before going ahead with the deployment.", automationAccountId, email, strings.Split(email, "@")[1], automationAccountId)
		}
	}
}

func checkSESIdentityExists(profile, emailAddress string) (bool, error) {
	parts := strings.Split(emailAddress, "@")
	if len(parts) != 2 {
		return false, fmt.Errorf("invalid email format: %s", emailAddress)
	}
	emailDomain := parts[1]

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(profile),
	)
	if err != nil {
		return false, fmt.Errorf("failed to load AWS config: %w", err)
	}

	sesClient := ses.NewFromConfig(cfg)

	output, err := sesClient.ListIdentities(context.TODO(), &ses.ListIdentitiesInput{})
	if err != nil {
		return false, fmt.Errorf("failed to list SES identities: %w", err)
	}

	// Check if email or domain exists in SES Identities
	for _, identity := range output.Identities {
		if identity == emailAddress || identity == emailDomain {
			return true, nil
		}
	}

	return false, nil
}
