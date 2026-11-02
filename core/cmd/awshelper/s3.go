package awshelper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"rrcore/cmd/logger"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3Types "github.com/aws/aws-sdk-go-v2/service/s3/types"
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

	file, err := os.Open(templatePath) // #nosec G304 -- templatePath is a repository-controlled CloudFormation template path.
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

// s3BucketEmptier is the subset of the S3 API needed to empty a bucket.
type s3BucketEmptier interface {
	s3.ListObjectVersionsAPIClient
	DeleteObjects(context.Context, *s3.DeleteObjectsInput, ...func(*s3.Options)) (*s3.DeleteObjectsOutput, error)
}

// emptyS3Bucket permanently deletes every object version and delete marker in the bucket.
// Deleting only the current keys of a versioned bucket just adds delete markers, which leaves
// the bucket non-empty and makes DeleteBucket fail with BucketNotEmpty. ListObjectVersions also
// covers unversioned buckets, whose objects are returned with the "null" version id.
func emptyS3Bucket(client s3BucketEmptier, bucketName string) error {
	paginator := s3.NewListObjectVersionsPaginator(client, &s3.ListObjectVersionsInput{
		Bucket: aws.String(bucketName),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			return fmt.Errorf("failed to list object versions: %w", err)
		}

		// A page holds at most 1000 versions plus delete markers combined, which matches the
		// DeleteObjects batch limit.
		objects := make([]s3Types.ObjectIdentifier, 0, len(page.Versions)+len(page.DeleteMarkers))
		for _, version := range page.Versions {
			objects = append(objects, s3Types.ObjectIdentifier{Key: version.Key, VersionId: version.VersionId})
		}
		for _, marker := range page.DeleteMarkers {
			objects = append(objects, s3Types.ObjectIdentifier{Key: marker.Key, VersionId: marker.VersionId})
		}
		if len(objects) == 0 {
			continue
		}

		output, err := client.DeleteObjects(context.TODO(), &s3.DeleteObjectsInput{
			Bucket: aws.String(bucketName),
			Delete: &s3Types.Delete{Objects: objects, Quiet: aws.Bool(true)},
		})
		if err != nil {
			return fmt.Errorf("failed to delete objects: %w", err)
		}
		// DeleteObjects reports per-key failures in the response body, not as an error.
		if output != nil && len(output.Errors) > 0 {
			first := output.Errors[0]
			return fmt.Errorf("failed to delete %d object version(s), first %s (version %s): %s %s",
				len(output.Errors), aws.ToString(first.Key), aws.ToString(first.VersionId),
				aws.ToString(first.Code), aws.ToString(first.Message))
		}
	}
	logger.Debugf("✅ All object versions deleted from bucket '%s'.\n", bucketName)
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
