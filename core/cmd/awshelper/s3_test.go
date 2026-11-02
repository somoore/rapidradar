package awshelper

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3Types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type fakeBucketEmptier struct {
	pages        []*s3.ListObjectVersionsOutput
	listCalls    int
	deleted      []s3Types.ObjectIdentifier
	deleteErrors []s3Types.Error
}

func (f *fakeBucketEmptier) ListObjectVersions(_ context.Context, _ *s3.ListObjectVersionsInput, _ ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error) {
	page := f.pages[f.listCalls]
	f.listCalls++
	return page, nil
}

func (f *fakeBucketEmptier) DeleteObjects(_ context.Context, input *s3.DeleteObjectsInput, _ ...func(*s3.Options)) (*s3.DeleteObjectsOutput, error) {
	f.deleted = append(f.deleted, input.Delete.Objects...)
	return &s3.DeleteObjectsOutput{Errors: f.deleteErrors}, nil
}

func objectVersion(key, versionID string) s3Types.ObjectVersion {
	return s3Types.ObjectVersion{Key: aws.String(key), VersionId: aws.String(versionID)}
}

func deleteMarker(key, versionID string) s3Types.DeleteMarkerEntry {
	return s3Types.DeleteMarkerEntry{Key: aws.String(key), VersionId: aws.String(versionID)}
}

func TestEmptyS3BucketDeletesAllVersionsAndDeleteMarkers(t *testing.T) {
	client := &fakeBucketEmptier{pages: []*s3.ListObjectVersionsOutput{
		{
			Versions:            []s3Types.ObjectVersion{objectVersion("a.csv", "v2"), objectVersion("a.csv", "v1")},
			DeleteMarkers:       []s3Types.DeleteMarkerEntry{deleteMarker("b.csv", "m1")},
			IsTruncated:         aws.Bool(true),
			NextKeyMarker:       aws.String("b.csv"),
			NextVersionIdMarker: aws.String("m1"),
		},
		// An empty page in the middle of a listing must not stop the cleanup.
		{
			IsTruncated:         aws.Bool(true),
			NextKeyMarker:       aws.String("b.csv"),
			NextVersionIdMarker: aws.String("m2"),
		},
		{
			Versions:      []s3Types.ObjectVersion{objectVersion("c.csv", "null")},
			DeleteMarkers: []s3Types.DeleteMarkerEntry{deleteMarker("c.csv", "m3")},
			IsTruncated:   aws.Bool(false),
		},
	}}

	if err := emptyS3Bucket(client, "bucket"); err != nil {
		t.Fatalf("emptyS3Bucket returned %v", err)
	}
	if client.listCalls != 3 {
		t.Fatalf("expected 3 list calls, got %d", client.listCalls)
	}

	want := []string{"a.csv@v2", "a.csv@v1", "b.csv@m1", "c.csv@null", "c.csv@m3"}
	if len(client.deleted) != len(want) {
		t.Fatalf("deleted %d identifiers, want %d", len(client.deleted), len(want))
	}
	for i, id := range client.deleted {
		got := aws.ToString(id.Key) + "@" + aws.ToString(id.VersionId)
		if got != want[i] {
			t.Fatalf("deleted[%d] = %s, want %s", i, got, want[i])
		}
	}
}

func TestEmptyS3BucketReportsPerObjectDeleteErrors(t *testing.T) {
	client := &fakeBucketEmptier{
		pages: []*s3.ListObjectVersionsOutput{{
			Versions:    []s3Types.ObjectVersion{objectVersion("a.csv", "v1")},
			IsTruncated: aws.Bool(false),
		}},
		deleteErrors: []s3Types.Error{{
			Key:       aws.String("a.csv"),
			VersionId: aws.String("v1"),
			Code:      aws.String("AccessDenied"),
			Message:   aws.String("Access Denied"),
		}},
	}

	err := emptyS3Bucket(client, "bucket")
	if err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("expected per-object delete error, got %v", err)
	}
}
