package awshelper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"rrcore/cmd/logger"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3Types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go/aws"
)

func checkIfS3BucketExists(client *s3.Client, bucketName string) (bool, error) {
	_, err := client.HeadBucket(context.TODO(), &s3.HeadBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		var notFoundErr *s3Types.NotFound
		if ok := errors.As(err, &notFoundErr); ok {
			return false, nil
		}
		return false, fmt.Errorf("failed to check existence of S3 Bucket %s: %w", bucketName, err)
	}
	return true, nil
}

func createS3BucketIfNotExists(client *s3.Client, bucketName, region string) error {
	exists, err := checkIfS3BucketExists(client, bucketName)
	if err != nil {
		return err
	}
	if exists {
		logger.Debugf("✅ S3 Bucket '%s' already exists.", bucketName)
		return nil
	}
	logger.Debugf("🚀 Creating S3 bucket '%s' in region '%s'...", bucketName, region)
	createBucketInput := &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	}
	if region != "us-east-1" {
		createBucketInput.CreateBucketConfiguration = &s3Types.CreateBucketConfiguration{
			LocationConstraint: s3Types.BucketLocationConstraint(region),
		}
	}

	_, err = client.CreateBucket(context.TODO(), createBucketInput)
	if err != nil {
		return fmt.Errorf("failed to create S3 bucket: %w", err)
	}
	logger.Debugf("✅ S3 Bucket '%s' created successfully.", bucketName)
	return nil
}

func uploadTemplateToS3Bucket(client *s3.Client, cfgRegion, bucketName, bucketKey, templatePath string) (string, error) {
	var templateUrl string

	file, err := os.Open(templatePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file %q: %w", templatePath, err)
	}
	defer file.Close()

	input := &s3.PutObjectInput{
		Bucket: &bucketName,
		Key:    &bucketKey,
		Body:   file,
	}
	_, err = client.PutObject(context.TODO(), input)
	if err != nil {
		return "", fmt.Errorf("failed to upload template file %s to S3 Bucket %s: %w", templatePath, bucketName, err)
	}
	templateUrl = fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", bucketName, cfgRegion, bucketKey)
	return templateUrl, nil
}

func emptyS3Bucket(client *s3.Client, bucketName string) error {
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			return fmt.Errorf("failed to list objects: %w", err)
		}

		// Collect object identifiers for deletion
		var objects []s3Types.ObjectIdentifier
		for _, obj := range page.Contents {
			objects = append(objects, s3Types.ObjectIdentifier{Key: obj.Key})
		}
		// Skip if no objects
		if len(objects) == 0 {
			break
		}

		// Delete objects in batch
		_, err = client.DeleteObjects(context.TODO(), &s3.DeleteObjectsInput{
			Bucket: aws.String(bucketName),
			Delete: &s3Types.Delete{Objects: objects},
		})
		if err != nil {
			return fmt.Errorf("failed to delete objects: %w", err)
		}
	}
	logger.Debugf("✅ All objects deleted from bucket '%s'.\n", bucketName)
	return nil
}

func DeleteS3BucketIfExists(client *s3.Client, bucketName string) error {
	exists, err := checkIfS3BucketExists(client, bucketName)
	if err != nil {
		return err
	}
	if !exists {
		logger.Debugf("✅ S3 Bucket '%s' does not exist.", bucketName)
	} else {
		logger.Debugf("🗑️ Deleting all objects from S3 Bucket '%s'...", bucketName)
		err = emptyS3Bucket(client, bucketName)
		if err != nil {
			return fmt.Errorf("failed to delete objects from bucket: %w", err)
		}

		logger.Debugf("🚀 S3 Bucket '%s' exists. Deleting it...", bucketName)
		_, err = client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			return fmt.Errorf("failed to delete S3 bucket: %w", err)
		}
		logger.Debugf("🗑️ S3 Bucket '%s' deleted successfully.", bucketName)
	}
	return nil
}
