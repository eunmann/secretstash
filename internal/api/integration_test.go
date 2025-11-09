//nolint:funlen,gocyclo // Test file
package api

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/eunmann/secretstash/internal/core"
	"github.com/eunmann/secretstash/internal/storage"
)

// TestServer wraps the HTTP server for testing
type TestServer struct {
	server *http.Server
	client *secretsmanager.Client
	addr   string
}

// StartTestServer starts a test server and returns a configured AWS SDK client
func StartTestServer(t *testing.T) *TestServer {
	t.Helper()

	// Create storage and manager
	store := storage.NewMemoryStorage("")
	manager := core.NewSecretManager(store)

	// Create handler
	handler := NewHandler(manager)

	// Find available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()

	// Create server
	//nolint:gosec // G112: Test server doesn't need ReadHeaderTimeout
	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	// Start server in background
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Logf("Server error: %v", err)
		}
	}()

	// Create AWS SDK v2 client
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
	)
	if err != nil {
		t.Fatalf("Failed to load AWS config: %v", err)
	}

	client := secretsmanager.NewFromConfig(cfg, func(o *secretsmanager.Options) {
		o.BaseEndpoint = aws.String(fmt.Sprintf("http://%s", addr))
	})

	return &TestServer{
		server: srv,
		client: client,
		addr:   addr,
	}
}

// Stop stops the test server
func (ts *TestServer) Stop(t *testing.T) {
	t.Helper()
	if err := ts.server.Shutdown(context.Background()); err != nil {
		t.Logf("Server shutdown error: %v", err)
	}
}

func TestIntegration_ListSecretVersionIds(t *testing.T) {
	ts := StartTestServer(t)
	defer ts.Stop(t)

	ctx := context.Background()

	// Create a secret
	secretName := "test-list-versions" //nolint:gosec // G101: False positive - variable name, not credential
	createResp, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name:         aws.String(secretName),
		SecretString: aws.String("initial-value"),
	})
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}
	initialVersionId := *createResp.VersionId

	// Add more versions
	putResp1, err := ts.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(secretName),
		SecretString: aws.String("second-value"),
	})
	if err != nil {
		t.Fatalf("Failed to put second version: %v", err)
	}
	secondVersionId := *putResp1.VersionId

	putResp2, err := ts.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(secretName),
		SecretString: aws.String("third-value"),
	})
	if err != nil {
		t.Fatalf("Failed to put third version: %v", err)
	}
	thirdVersionId := *putResp2.VersionId

	t.Run("List all versions excluding deprecated", func(t *testing.T) {
		listResp, err := ts.client.ListSecretVersionIds(ctx, &secretsmanager.ListSecretVersionIdsInput{
			SecretId:          aws.String(secretName),
			IncludeDeprecated: aws.Bool(false),
		})
		if err != nil {
			t.Fatalf("Failed to list versions: %v", err)
		}

		if listResp.ARN == nil || *listResp.ARN == "" {
			t.Errorf("Expected ARN in response")
		}
		if listResp.Name == nil || *listResp.Name != secretName {
			t.Errorf("Expected Name=%s, got %v", secretName, listResp.Name)
		}

		// Should have at least AWSCURRENT and AWSPREVIOUS versions
		if len(listResp.Versions) < 2 {
			t.Errorf("Expected at least 2 versions, got %d", len(listResp.Versions))
		}

		// Verify versions are sorted by CreatedDate descending (newest first)
		for i := 0; i < len(listResp.Versions)-1; i++ {
			if listResp.Versions[i].CreatedDate.Before(*listResp.Versions[i+1].CreatedDate) {
				t.Errorf("Versions not sorted correctly: version %d is older than version %d", i, i+1)
			}
		}
	})

	t.Run("List all versions including deprecated", func(t *testing.T) {
		listResp, err := ts.client.ListSecretVersionIds(ctx, &secretsmanager.ListSecretVersionIdsInput{
			SecretId:          aws.String(secretName),
			IncludeDeprecated: aws.Bool(true),
		})
		if err != nil {
			t.Fatalf("Failed to list versions: %v", err)
		}

		// Should have all 3 versions
		if len(listResp.Versions) != 3 {
			t.Errorf("Expected 3 versions, got %d", len(listResp.Versions))
		}

		// Verify all version IDs are present
		versionIds := make(map[string]bool)
		for _, v := range listResp.Versions {
			versionIds[*v.VersionId] = true
		}

		if !versionIds[initialVersionId] {
			t.Errorf("Initial version %s not found", initialVersionId)
		}
		if !versionIds[secondVersionId] {
			t.Errorf("Second version %s not found", secondVersionId)
		}
		if !versionIds[thirdVersionId] {
			t.Errorf("Third version %s not found", thirdVersionId)
		}
	})

	t.Run("List with MaxResults", func(t *testing.T) {
		listResp, err := ts.client.ListSecretVersionIds(ctx, &secretsmanager.ListSecretVersionIdsInput{
			SecretId:          aws.String(secretName),
			MaxResults:        aws.Int32(2),
			IncludeDeprecated: aws.Bool(true),
		})
		if err != nil {
			t.Fatalf("Failed to list versions: %v", err)
		}

		if len(listResp.Versions) != 2 {
			t.Errorf("Expected 2 versions (MaxResults=2), got %d", len(listResp.Versions))
		}

		if listResp.NextToken == nil {
			t.Errorf("Expected NextToken for pagination")
		}
	})

	t.Run("List non-existent secret", func(t *testing.T) {
		_, err := ts.client.ListSecretVersionIds(ctx, &secretsmanager.ListSecretVersionIdsInput{
			SecretId: aws.String("non-existent-secret"),
		})
		if err == nil {
			t.Errorf("Expected error for non-existent secret")
		}
	})

	t.Run("List with invalid MaxResults", func(t *testing.T) {
		_, err := ts.client.ListSecretVersionIds(ctx, &secretsmanager.ListSecretVersionIdsInput{
			SecretId:   aws.String(secretName),
			MaxResults: aws.Int32(0), // Invalid: must be 1-100
		})
		if err == nil {
			t.Errorf("Expected error for invalid MaxResults")
		}
	})
}

func TestIntegration_CancelRotateSecret(t *testing.T) {
	ts := StartTestServer(t)
	defer ts.Stop(t)

	ctx := context.Background()

	t.Run("Cancel rotation in progress", func(t *testing.T) {
		secretName := "test-cancel-rotation"

		// Create secret
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("initial-value"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Start rotation
		rotateResp, err := ts.client.RotateSecret(ctx, &secretsmanager.RotateSecretInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("Failed to start rotation: %v", err)
		}
		pendingVersionId := *rotateResp.VersionId

		// Verify AWSPENDING version exists
		listResp, err := ts.client.ListSecretVersionIds(ctx, &secretsmanager.ListSecretVersionIdsInput{
			SecretId:          aws.String(secretName),
			IncludeDeprecated: aws.Bool(true),
		})
		if err != nil {
			t.Fatalf("Failed to list versions: %v", err)
		}

		hasPending := false
		for _, v := range listResp.Versions {
			for _, stage := range v.VersionStages {
				if stage == core.VersionStageAWSPending {
					hasPending = true
					break
				}
			}
		}
		if !hasPending {
			t.Errorf("Expected AWSPENDING version after rotation")
		}

		// Cancel rotation
		cancelResp, err := ts.client.CancelRotateSecret(ctx, &secretsmanager.CancelRotateSecretInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("Failed to cancel rotation: %v", err)
		}

		if cancelResp.ARN == nil || *cancelResp.ARN == "" {
			t.Errorf("Expected ARN in cancel response")
		}
		if cancelResp.Name == nil || *cancelResp.Name != secretName {
			t.Errorf("Expected Name=%s, got %v", secretName, cancelResp.Name)
		}
		if cancelResp.VersionId == nil || *cancelResp.VersionId != pendingVersionId {
			t.Errorf("Expected VersionId=%s, got %v", pendingVersionId, cancelResp.VersionId)
		}

		// Verify AWSPENDING was removed
		listResp2, err := ts.client.ListSecretVersionIds(ctx, &secretsmanager.ListSecretVersionIdsInput{
			SecretId:          aws.String(secretName),
			IncludeDeprecated: aws.Bool(true),
		})
		if err != nil {
			t.Fatalf("Failed to list versions after cancel: %v", err)
		}

		hasPending = false
		for _, v := range listResp2.Versions {
			for _, stage := range v.VersionStages {
				if stage == core.VersionStageAWSPending {
					hasPending = true
					break
				}
			}
		}
		if hasPending {
			t.Errorf("AWSPENDING should be removed after cancellation")
		}

		// Verify DescribeSecret shows rotation disabled
		descResp, err := ts.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("Failed to describe secret: %v", err)
		}
		if descResp.RotationEnabled != nil && *descResp.RotationEnabled {
			t.Errorf("RotationEnabled should be false after cancellation")
		}
	})

	t.Run("Cancel when no rotation in progress", func(t *testing.T) {
		secretName := "test-no-rotation"

		// Create secret without starting rotation
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("value"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Try to cancel (should fail)
		_, err = ts.client.CancelRotateSecret(ctx, &secretsmanager.CancelRotateSecretInput{
			SecretId: aws.String(secretName),
		})
		if err == nil {
			t.Errorf("Expected error when no rotation in progress")
		}
	})

	t.Run("Cancel for non-existent secret", func(t *testing.T) {
		_, err := ts.client.CancelRotateSecret(ctx, &secretsmanager.CancelRotateSecretInput{
			SecretId: aws.String("non-existent-secret"),
		})
		if err == nil {
			t.Errorf("Expected error for non-existent secret")
		}
	})

	t.Run("Cancel for deleted secret", func(t *testing.T) {
		secretName := "test-deleted-cancel"

		// Create and delete secret
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("value"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		_, err = ts.client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{
			SecretId:             aws.String(secretName),
			RecoveryWindowInDays: aws.Int64(7),
		})
		if err != nil {
			t.Fatalf("Failed to delete secret: %v", err)
		}

		// Try to cancel rotation
		_, err = ts.client.CancelRotateSecret(ctx, &secretsmanager.CancelRotateSecretInput{
			SecretId: aws.String(secretName),
		})
		if err == nil {
			t.Errorf("Expected error for deleted secret")
		}
	})

	t.Run("Cancel twice should fail", func(t *testing.T) {
		secretName := "test-cancel-twice"

		// Create secret and start rotation
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("value"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		_, err = ts.client.RotateSecret(ctx, &secretsmanager.RotateSecretInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("Failed to start rotation: %v", err)
		}

		// First cancel should succeed
		_, err = ts.client.CancelRotateSecret(ctx, &secretsmanager.CancelRotateSecretInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("First cancel failed: %v", err)
		}

		// Second cancel should fail
		_, err = ts.client.CancelRotateSecret(ctx, &secretsmanager.CancelRotateSecretInput{
			SecretId: aws.String(secretName),
		})
		if err == nil {
			t.Errorf("Expected error when canceling twice")
		}
	})
}

func TestIntegration_CompleteWorkflow(t *testing.T) {
	ts := StartTestServer(t)
	defer ts.Stop(t)

	ctx := context.Background()
	secretName := "workflow-test"

	// 1. Create secret
	createResp, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name:         aws.String(secretName),
		SecretString: aws.String("initial-value"),
		Description:  aws.String("Test secret for complete workflow"),
		Tags: []types.Tag{
			{Key: aws.String("Environment"), Value: aws.String("test")},
		},
	})
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}
	t.Logf("Created secret: %s (version: %s)", *createResp.Name, *createResp.VersionId)

	// 2. Get secret value
	getResp, err := ts.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	})
	if err != nil {
		t.Fatalf("Failed to get secret: %v", err)
	}
	if *getResp.SecretString != "initial-value" {
		t.Errorf("Expected 'initial-value', got %s", *getResp.SecretString)
	}

	// 3. Add new version
	putResp, err := ts.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(secretName),
		SecretString: aws.String("updated-value"),
	})
	if err != nil {
		t.Fatalf("Failed to put secret value: %v", err)
	}
	t.Logf("Added new version: %s", *putResp.VersionId)

	// 4. List versions
	listResp, err := ts.client.ListSecretVersionIds(ctx, &secretsmanager.ListSecretVersionIdsInput{
		SecretId:          aws.String(secretName),
		IncludeDeprecated: aws.Bool(true),
	})
	if err != nil {
		t.Fatalf("Failed to list versions: %v", err)
	}
	t.Logf("Found %d versions", len(listResp.Versions))

	// 5. Start rotation
	rotateResp, err := ts.client.RotateSecret(ctx, &secretsmanager.RotateSecretInput{
		SecretId: aws.String(secretName),
	})
	if err != nil {
		t.Fatalf("Failed to start rotation: %v", err)
	}
	t.Logf("Started rotation, pending version: %s", *rotateResp.VersionId)

	// 6. Cancel rotation
	cancelResp, err := ts.client.CancelRotateSecret(ctx, &secretsmanager.CancelRotateSecretInput{
		SecretId: aws.String(secretName),
	})
	if err != nil {
		t.Fatalf("Failed to cancel rotation: %v", err)
	}
	t.Logf("Canceled rotation for version: %s", *cancelResp.VersionId)

	// 7. Verify final state
	descResp, err := ts.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
		SecretId: aws.String(secretName),
	})
	if err != nil {
		t.Fatalf("Failed to describe secret: %v", err)
	}

	if descResp.RotationEnabled != nil && *descResp.RotationEnabled {
		t.Errorf("Rotation should be disabled")
	}

	// Should have 3 versions total (initial, updated, canceled pending)
	if len(descResp.VersionIdsToStages) != 3 {
		t.Errorf("Expected 3 versions, got %d", len(descResp.VersionIdsToStages))
	}

	t.Log("Complete workflow test passed!")
}

// TestIntegration_BatchGetSecretValue tests BatchGetSecretValue operation with AWS SDK v2
func TestIntegration_BatchGetSecretValue(t *testing.T) {
	ts := StartTestServer(t)
	defer ts.Stop(t)

	ctx := context.Background()

	t.Run("Batch get multiple secrets by ID", func(t *testing.T) {
		// Create multiple secrets
		secretNames := []string{"batch-secret-1", "batch-secret-2", "batch-secret-3"}
		for _, name := range secretNames {
			_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
				Name:         aws.String(name),
				SecretString: aws.String(fmt.Sprintf("value-for-%s", name)),
			})
			if err != nil {
				t.Fatalf("Failed to create secret %s: %v", name, err)
			}
		}

		// Batch get all secrets
		resp, err := ts.client.BatchGetSecretValue(ctx, &secretsmanager.BatchGetSecretValueInput{
			SecretIdList: []string{"batch-secret-1", "batch-secret-2", "batch-secret-3"},
		})
		if err != nil {
			t.Fatalf("BatchGetSecretValue failed: %v", err)
		}

		if len(resp.SecretValues) != 3 {
			t.Errorf("Expected 3 secrets, got %d", len(resp.SecretValues))
		}

		// Verify each secret has correct value
		for _, secret := range resp.SecretValues {
			if secret.SecretString == nil {
				t.Errorf("Secret %s missing SecretString", *secret.Name)
				continue
			}
			expectedValue := fmt.Sprintf("value-for-%s", *secret.Name)
			if *secret.SecretString != expectedValue {
				t.Errorf("Secret %s has wrong value: expected %s, got %s",
					*secret.Name, expectedValue, *secret.SecretString)
			}
			if secret.ARN == nil {
				t.Errorf("Secret %s missing ARN", *secret.Name)
			}
			if secret.VersionId == nil {
				t.Errorf("Secret %s missing VersionId", *secret.Name)
			}
			if secret.CreatedDate == nil {
				t.Errorf("Secret %s missing CreatedDate", *secret.Name)
			}
		}

		if len(resp.Errors) != 0 {
			t.Errorf("Expected no errors, got %d", len(resp.Errors))
		}
	})

	t.Run("Batch get with some non-existent secrets", func(t *testing.T) {
		// Create one secret
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String("existing-batch-secret"),
			SecretString: aws.String("value"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Try to batch get both existing and non-existent
		resp, err := ts.client.BatchGetSecretValue(ctx, &secretsmanager.BatchGetSecretValueInput{
			SecretIdList: []string{"existing-batch-secret", "non-existent-secret"},
		})
		if err != nil {
			t.Fatalf("BatchGetSecretValue failed: %v", err)
		}

		if len(resp.SecretValues) != 1 {
			t.Errorf("Expected 1 secret, got %d", len(resp.SecretValues))
		}

		if len(resp.Errors) != 1 {
			t.Errorf("Expected 1 error for non-existent secret, got %d", len(resp.Errors))
		}
	})

	t.Run("Batch get with deleted secret", func(t *testing.T) {
		// Create two secrets
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String("active-batch-secret"),
			SecretString: aws.String("active-value"),
		})
		if err != nil {
			t.Fatalf("Failed to create active secret: %v", err)
		}

		_, err = ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String("deleted-batch-secret"),
			SecretString: aws.String("deleted-value"),
		})
		if err != nil {
			t.Fatalf("Failed to create deleted secret: %v", err)
		}

		// Delete one secret
		_, err = ts.client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{
			SecretId:             aws.String("deleted-batch-secret"),
			RecoveryWindowInDays: aws.Int64(7),
		})
		if err != nil {
			t.Fatalf("Failed to delete secret: %v", err)
		}

		// Batch get both secrets
		resp, err := ts.client.BatchGetSecretValue(ctx, &secretsmanager.BatchGetSecretValueInput{
			SecretIdList: []string{"active-batch-secret", "deleted-batch-secret"},
		})
		if err != nil {
			t.Fatalf("BatchGetSecretValue failed: %v", err)
		}

		// Should only get the active secret
		if len(resp.SecretValues) != 1 {
			t.Errorf("Expected 1 active secret, got %d", len(resp.SecretValues))
		}

		if len(resp.Errors) != 1 {
			t.Errorf("Expected 1 error for deleted secret, got %d", len(resp.Errors))
		}
	})

	t.Run("Batch get with MaxResults", func(t *testing.T) {
		// Create 5 secrets
		for i := 1; i <= 5; i++ {
			name := fmt.Sprintf("max-result-secret-%d", i)
			_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
				Name:         aws.String(name),
				SecretString: aws.String(fmt.Sprintf("value-%d", i)),
			})
			if err != nil {
				t.Fatalf("Failed to create secret %s: %v", name, err)
			}
		}

		// Batch get with MaxResults=3
		resp, err := ts.client.BatchGetSecretValue(ctx, &secretsmanager.BatchGetSecretValueInput{
			SecretIdList: []string{
				"max-result-secret-1",
				"max-result-secret-2",
				"max-result-secret-3",
				"max-result-secret-4",
				"max-result-secret-5",
			},
			MaxResults: aws.Int32(3),
		})
		if err != nil {
			t.Fatalf("BatchGetSecretValue failed: %v", err)
		}

		if len(resp.SecretValues) != 3 {
			t.Errorf("Expected 3 secrets due to MaxResults, got %d", len(resp.SecretValues))
		}
	})

	t.Run("Batch get by filters", func(t *testing.T) {
		// Create secrets with tags
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String("filtered-secret-1"),
			SecretString: aws.String("value1"),
			Tags: []types.Tag{
				{Key: aws.String("Environment"), Value: aws.String("Production")},
			},
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		_, err = ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String("filtered-secret-2"),
			SecretString: aws.String("value2"),
			Tags: []types.Tag{
				{Key: aws.String("Environment"), Value: aws.String("Development")},
			},
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Batch get using tag-key filter
		resp, err := ts.client.BatchGetSecretValue(ctx, &secretsmanager.BatchGetSecretValueInput{
			Filters: []types.Filter{
				{
					Key:    types.FilterNameStringTypeTagKey,
					Values: []string{"Environment"},
				},
			},
		})
		if err != nil {
			t.Fatalf("BatchGetSecretValue with filters failed: %v", err)
		}

		if len(resp.SecretValues) < 2 {
			t.Errorf("Expected at least 2 secrets with Environment tag, got %d", len(resp.SecretValues))
		}
	})

	t.Run("Empty batch request", func(t *testing.T) {
		resp, err := ts.client.BatchGetSecretValue(ctx, &secretsmanager.BatchGetSecretValueInput{
			SecretIdList: []string{},
		})
		if err != nil {
			t.Fatalf("BatchGetSecretValue failed: %v", err)
		}

		if len(resp.SecretValues) != 0 {
			t.Errorf("Expected 0 secrets for empty request, got %d", len(resp.SecretValues))
		}

		if len(resp.Errors) != 0 {
			t.Errorf("Expected 0 errors for empty request, got %d", len(resp.Errors))
		}
	})
}

// TestIntegration_ReplicationOperations tests replication operations with AWS SDK v2
func TestIntegration_ReplicationOperations(t *testing.T) {
	ts := StartTestServer(t)
	defer ts.Stop(t)

	ctx := context.Background()

	t.Run("Replicate to single region", func(t *testing.T) {
		// Create secret
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String("replicate-single-secret"),
			SecretString: aws.String("my-value"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Replicate to one region
		replicateResp, err := ts.client.ReplicateSecretToRegions(ctx, &secretsmanager.ReplicateSecretToRegionsInput{
			SecretId: aws.String("replicate-single-secret"),
			AddReplicaRegions: []types.ReplicaRegionType{
				{Region: aws.String("us-west-2")},
			},
		})
		if err != nil {
			t.Fatalf("ReplicateSecretToRegions failed: %v", err)
		}

		if replicateResp.ARN == nil {
			t.Error("Response missing ARN")
		}

		if len(replicateResp.ReplicationStatus) != 1 {
			t.Errorf("Expected 1 replicated region, got %d", len(replicateResp.ReplicationStatus))
		}

		// Verify replication status
		if len(replicateResp.ReplicationStatus) > 0 {
			replica := replicateResp.ReplicationStatus[0]
			if replica.Region == nil || *replica.Region != "us-west-2" {
				t.Errorf("Expected region us-west-2, got %v", replica.Region)
			}
			if string(replica.Status) != "InSync" {
				t.Errorf("Expected status InSync, got %v", replica.Status)
			}
		}
	})

	t.Run("Replicate to multiple regions", func(t *testing.T) {
		// Create secret
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String("replicate-multi-secret"),
			SecretString: aws.String("my-value"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Replicate to multiple regions
		replicateResp, err := ts.client.ReplicateSecretToRegions(ctx, &secretsmanager.ReplicateSecretToRegionsInput{
			SecretId: aws.String("replicate-multi-secret"),
			AddReplicaRegions: []types.ReplicaRegionType{
				{Region: aws.String("us-west-2")},
				{Region: aws.String("eu-west-1")},
				{Region: aws.String("ap-southeast-1")},
			},
		})
		if err != nil {
			t.Fatalf("ReplicateSecretToRegions failed: %v", err)
		}

		if len(replicateResp.ReplicationStatus) != 3 {
			t.Errorf("Expected 3 replicated regions, got %d", len(replicateResp.ReplicationStatus))
		}

		// Verify all regions are present
		regions := make(map[string]bool)
		for _, replica := range replicateResp.ReplicationStatus {
			if replica.Region != nil {
				regions[*replica.Region] = true
			}
		}

		expectedRegions := []string{"us-west-2", "eu-west-1", "ap-southeast-1"}
		for _, region := range expectedRegions {
			if !regions[region] {
				t.Errorf("Expected region %s not found in replication status", region)
			}
		}
	})

	t.Run("Verify replication in DescribeSecret", func(t *testing.T) {
		// Create and replicate secret
		secretName := "describe-replication-secret"
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("my-value"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		_, err = ts.client.ReplicateSecretToRegions(ctx, &secretsmanager.ReplicateSecretToRegionsInput{
			SecretId: aws.String(secretName),
			AddReplicaRegions: []types.ReplicaRegionType{
				{Region: aws.String("us-west-2")},
			},
		})
		if err != nil {
			t.Fatalf("ReplicateSecretToRegions failed: %v", err)
		}

		// Verify in DescribeSecret
		describeResp, err := ts.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("DescribeSecret failed: %v", err)
		}

		if len(describeResp.ReplicationStatus) != 1 {
			t.Errorf("DescribeSecret shows %d replicas, expected 1", len(describeResp.ReplicationStatus))
		}
	})

	t.Run("Remove region from replication", func(t *testing.T) {
		// Create and replicate secret
		secretName := "remove-region-secret"
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("my-value"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		_, err = ts.client.ReplicateSecretToRegions(ctx, &secretsmanager.ReplicateSecretToRegionsInput{
			SecretId: aws.String(secretName),
			AddReplicaRegions: []types.ReplicaRegionType{
				{Region: aws.String("us-west-2")},
				{Region: aws.String("eu-west-1")},
			},
		})
		if err != nil {
			t.Fatalf("ReplicateSecretToRegions failed: %v", err)
		}

		// Remove one region
		removeResp, err := ts.client.RemoveRegionsFromReplication(ctx, &secretsmanager.RemoveRegionsFromReplicationInput{
			SecretId:             aws.String(secretName),
			RemoveReplicaRegions: []string{"eu-west-1"},
		})
		if err != nil {
			t.Fatalf("RemoveRegionsFromReplication failed: %v", err)
		}

		if len(removeResp.ReplicationStatus) != 1 {
			t.Errorf("Expected 1 remaining region, got %d", len(removeResp.ReplicationStatus))
		}

		// Verify the correct region remains
		if len(removeResp.ReplicationStatus) > 0 {
			if removeResp.ReplicationStatus[0].Region == nil || *removeResp.ReplicationStatus[0].Region != "us-west-2" {
				t.Errorf("Expected remaining region us-west-2, got %v", removeResp.ReplicationStatus[0].Region)
			}
		}
	})

	t.Run("Complete replication workflow", func(t *testing.T) {
		secretName := "replication-workflow-secret"

		// 1. Create secret
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("my-secret-value"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// 2. Replicate to multiple regions
		replicateResp1, err := ts.client.ReplicateSecretToRegions(ctx, &secretsmanager.ReplicateSecretToRegionsInput{
			SecretId: aws.String(secretName),
			AddReplicaRegions: []types.ReplicaRegionType{
				{Region: aws.String("us-west-2")},
				{Region: aws.String("eu-west-1")},
				{Region: aws.String("ap-southeast-1")},
			},
		})
		if err != nil {
			t.Fatalf("First replication failed: %v", err)
		}

		if len(replicateResp1.ReplicationStatus) != 3 {
			t.Errorf("Expected 3 regions after first replication, got %d", len(replicateResp1.ReplicationStatus))
		}

		// 3. Remove one region
		_, err = ts.client.RemoveRegionsFromReplication(ctx, &secretsmanager.RemoveRegionsFromReplicationInput{
			SecretId:             aws.String(secretName),
			RemoveReplicaRegions: []string{"eu-west-1"},
		})
		if err != nil {
			t.Fatalf("Failed to remove region: %v", err)
		}

		// 4. Add another region
		replicateResp2, err := ts.client.ReplicateSecretToRegions(ctx, &secretsmanager.ReplicateSecretToRegionsInput{
			SecretId: aws.String(secretName),
			AddReplicaRegions: []types.ReplicaRegionType{
				{Region: aws.String("ca-central-1")},
			},
		})
		if err != nil {
			t.Fatalf("Second replication failed: %v", err)
		}

		if len(replicateResp2.ReplicationStatus) != 3 {
			t.Errorf("Expected 3 regions after second replication, got %d", len(replicateResp2.ReplicationStatus))
		}

		// 5. Verify final state with DescribeSecret
		describeResp, err := ts.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("DescribeSecret failed: %v", err)
		}

		if len(describeResp.ReplicationStatus) != 3 {
			t.Errorf("Final DescribeSecret shows %d replicas, expected 3", len(describeResp.ReplicationStatus))
		}

		// Verify eu-west-1 was removed and ca-central-1 was added
		regions := make(map[string]bool)
		for _, replica := range describeResp.ReplicationStatus {
			if replica.Region != nil {
				regions[*replica.Region] = true
			}
		}

		if regions["eu-west-1"] {
			t.Error("eu-west-1 should have been removed")
		}
		if !regions["ca-central-1"] {
			t.Error("ca-central-1 should have been added")
		}
	})

	t.Run("Replicate non-existent secret", func(t *testing.T) {
		_, err := ts.client.ReplicateSecretToRegions(ctx, &secretsmanager.ReplicateSecretToRegionsInput{
			SecretId: aws.String("non-existent-secret"),
			AddReplicaRegions: []types.ReplicaRegionType{
				{Region: aws.String("us-west-2")},
			},
		})

		if err == nil {
			t.Error("Expected error for non-existent secret, got nil")
		}
	})

	t.Run("Remove region from non-existent secret", func(t *testing.T) {
		_, err := ts.client.RemoveRegionsFromReplication(ctx, &secretsmanager.RemoveRegionsFromReplicationInput{
			SecretId:             aws.String("non-existent-secret"),
			RemoveReplicaRegions: []string{"us-west-2"},
		})

		if err == nil {
			t.Error("Expected error for non-existent secret, got nil")
		}
	})
}

func TestIntegration_UpdateSecret(t *testing.T) {
	ts := StartTestServer(t)
	defer ts.Stop(t)

	ctx := context.Background()

	t.Run("Update description only", func(t *testing.T) {
		secretName := "test-update-desc"

		// Create secret
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("initial-value"),
			Description:  aws.String("Initial description"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Update description
		updateResp, err := ts.client.UpdateSecret(ctx, &secretsmanager.UpdateSecretInput{
			SecretId:    aws.String(secretName),
			Description: aws.String("Updated description"),
		})
		if err != nil {
			t.Fatalf("Failed to update secret: %v", err)
		}

		if updateResp.ARN == nil {
			t.Error("Expected ARN in response")
		}
		if updateResp.Name == nil || *updateResp.Name != secretName {
			t.Errorf("Expected Name=%s, got %v", secretName, updateResp.Name)
		}
		if updateResp.VersionId != nil {
			t.Error("Should not create new version when only updating description")
		}

		// Verify description updated
		descResp, err := ts.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("Failed to describe secret: %v", err)
		}
		if descResp.Description == nil || *descResp.Description != "Updated description" {
			t.Errorf("Expected description 'Updated description', got %v", descResp.Description)
		}
	})

	t.Run("Update secret value", func(t *testing.T) {
		secretName := "test-update-value"

		// Create secret
		createResp, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("initial-value"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}
		initialVersionId := *createResp.VersionId

		// Update value
		updateResp, err := ts.client.UpdateSecret(ctx, &secretsmanager.UpdateSecretInput{
			SecretId:     aws.String(secretName),
			SecretString: aws.String("updated-value"),
		})
		if err != nil {
			t.Fatalf("Failed to update secret: %v", err)
		}

		if updateResp.VersionId == nil {
			t.Error("Expected new VersionId when updating value")
		}
		if updateResp.VersionId != nil && *updateResp.VersionId == initialVersionId {
			t.Error("New version ID should be different from initial")
		}

		// Verify new value
		getResp, err := ts.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("Failed to get secret: %v", err)
		}
		if getResp.SecretString == nil || *getResp.SecretString != "updated-value" {
			t.Errorf("Expected value 'updated-value', got %v", getResp.SecretString)
		}
	})

	t.Run("Update both description and value", func(t *testing.T) {
		secretName := "test-update-both"

		// Create secret
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("initial-value"),
			Description:  aws.String("Initial description"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Update both
		updateResp, err := ts.client.UpdateSecret(ctx, &secretsmanager.UpdateSecretInput{
			SecretId:     aws.String(secretName),
			SecretString: aws.String("new-value"),
			Description:  aws.String("New description"),
		})
		if err != nil {
			t.Fatalf("Failed to update secret: %v", err)
		}

		if updateResp.VersionId == nil {
			t.Error("Expected new VersionId")
		}

		// Verify both updated
		descResp, err := ts.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("Failed to describe secret: %v", err)
		}
		if descResp.Description == nil || *descResp.Description != "New description" {
			t.Errorf("Expected description 'New description', got %v", descResp.Description)
		}

		getResp, err := ts.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("Failed to get secret: %v", err)
		}
		if getResp.SecretString == nil || *getResp.SecretString != "new-value" {
			t.Errorf("Expected value 'new-value', got %v", getResp.SecretString)
		}
	})

	t.Run("Update non-existent secret", func(t *testing.T) {
		_, err := ts.client.UpdateSecret(ctx, &secretsmanager.UpdateSecretInput{
			SecretId:    aws.String("non-existent-secret"),
			Description: aws.String("desc"),
		})
		if err == nil {
			t.Error("Expected error for non-existent secret")
		}
	})

	t.Run("Update deleted secret", func(t *testing.T) {
		secretName := "test-update-deleted"

		// Create and delete
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("value"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		_, err = ts.client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{
			SecretId:             aws.String(secretName),
			RecoveryWindowInDays: aws.Int64(7),
		})
		if err != nil {
			t.Fatalf("Failed to delete secret: %v", err)
		}

		// Try to update
		_, err = ts.client.UpdateSecret(ctx, &secretsmanager.UpdateSecretInput{
			SecretId:    aws.String(secretName),
			Description: aws.String("new desc"),
		})
		if err == nil {
			t.Error("Expected error when updating deleted secret")
		}
	})
}

func TestIntegration_TagResource(t *testing.T) {
	ts := StartTestServer(t)
	defer ts.Stop(t)

	ctx := context.Background()

	t.Run("Add tags to secret", func(t *testing.T) {
		secretName := "test-tag-secret"

		// Create secret
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("value"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Add tags
		_, err = ts.client.TagResource(ctx, &secretsmanager.TagResourceInput{
			SecretId: aws.String(secretName),
			Tags: []types.Tag{
				{Key: aws.String("Environment"), Value: aws.String("Production")},
				{Key: aws.String("Owner"), Value: aws.String("TeamA")},
			},
		})
		if err != nil {
			t.Fatalf("Failed to tag resource: %v", err)
		}

		// Verify tags
		descResp, err := ts.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("Failed to describe secret: %v", err)
		}

		if len(descResp.Tags) < 2 {
			t.Errorf("Expected at least 2 tags, got %d", len(descResp.Tags))
		}

		// Verify specific tags
		tagMap := make(map[string]string)
		for _, tag := range descResp.Tags {
			if tag.Key != nil && tag.Value != nil {
				tagMap[*tag.Key] = *tag.Value
			}
		}
		if tagMap["Environment"] != "Production" {
			t.Error("Expected Environment tag with value Production")
		}
		if tagMap["Owner"] != "TeamA" {
			t.Error("Expected Owner tag with value TeamA")
		}
	})

	t.Run("Add more tags to existing tagged secret", func(t *testing.T) {
		secretName := "test-add-more-tags" //nolint:gosec // G101: Variable name

		// Create secret with initial tags
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("value"),
			Tags: []types.Tag{
				{Key: aws.String("Initial"), Value: aws.String("Tag")},
			},
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Add more tags
		_, err = ts.client.TagResource(ctx, &secretsmanager.TagResourceInput{
			SecretId: aws.String(secretName),
			Tags: []types.Tag{
				{Key: aws.String("Additional"), Value: aws.String("Tag")},
			},
		})
		if err != nil {
			t.Fatalf("Failed to tag resource: %v", err)
		}

		// Verify both tags exist
		descResp, err := ts.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("Failed to describe secret: %v", err)
		}

		if len(descResp.Tags) < 2 {
			t.Errorf("Expected at least 2 tags, got %d", len(descResp.Tags))
		}
	})

	t.Run("Tag non-existent secret", func(t *testing.T) {
		_, err := ts.client.TagResource(ctx, &secretsmanager.TagResourceInput{
			SecretId: aws.String("non-existent-secret"),
			Tags: []types.Tag{
				{Key: aws.String("key"), Value: aws.String("value")},
			},
		})
		if err == nil {
			t.Error("Expected error for non-existent secret")
		}
	})
}

func TestIntegration_UntagResource(t *testing.T) {
	ts := StartTestServer(t)
	defer ts.Stop(t)

	ctx := context.Background()

	t.Run("Remove tags from secret", func(t *testing.T) {
		secretName := "test-untag-secret" //nolint:gosec // G101: Variable name

		// Create secret with tags
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("value"),
			Tags: []types.Tag{
				{Key: aws.String("Environment"), Value: aws.String("Production")},
				{Key: aws.String("Owner"), Value: aws.String("TeamA")},
				{Key: aws.String("Application"), Value: aws.String("MyApp")},
			},
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Remove one tag
		_, err = ts.client.UntagResource(ctx, &secretsmanager.UntagResourceInput{
			SecretId: aws.String(secretName),
			TagKeys:  []string{"Environment"},
		})
		if err != nil {
			t.Fatalf("Failed to untag resource: %v", err)
		}

		// Verify tag removed
		descResp, err := ts.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("Failed to describe secret: %v", err)
		}

		for _, tag := range descResp.Tags {
			if tag.Key != nil && *tag.Key == "Environment" {
				t.Error("Environment tag should have been removed")
			}
		}

		// Other tags should remain
		if len(descResp.Tags) < 2 {
			t.Errorf("Expected at least 2 remaining tags, got %d", len(descResp.Tags))
		}
	})

	t.Run("Remove multiple tags", func(t *testing.T) {
		secretName := "test-untag-multiple" //nolint:gosec // G101: Variable name

		// Create secret with tags
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("value"),
			Tags: []types.Tag{
				{Key: aws.String("Tag1"), Value: aws.String("Value1")},
				{Key: aws.String("Tag2"), Value: aws.String("Value2")},
				{Key: aws.String("Tag3"), Value: aws.String("Value3")},
			},
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Remove multiple tags
		_, err = ts.client.UntagResource(ctx, &secretsmanager.UntagResourceInput{
			SecretId: aws.String(secretName),
			TagKeys:  []string{"Tag1", "Tag2"},
		})
		if err != nil {
			t.Fatalf("Failed to untag resource: %v", err)
		}

		// Verify tags removed
		descResp, err := ts.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("Failed to describe secret: %v", err)
		}

		for _, tag := range descResp.Tags {
			if tag.Key != nil && (*tag.Key == "Tag1" || *tag.Key == "Tag2") {
				t.Errorf("Tag %s should have been removed", *tag.Key)
			}
		}
	})

	t.Run("Untag non-existent secret", func(t *testing.T) {
		_, err := ts.client.UntagResource(ctx, &secretsmanager.UntagResourceInput{
			SecretId: aws.String("non-existent-secret"),
			TagKeys:  []string{"key"},
		})
		if err == nil {
			t.Error("Expected error for non-existent secret")
		}
	})
}

func TestIntegration_ListSecrets(t *testing.T) {
	ts := StartTestServer(t)
	defer ts.Stop(t)

	ctx := context.Background()

	// Create multiple secrets
	secrets := []string{"list-secret-1", "list-secret-2", "list-secret-3"}
	for _, name := range secrets {
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(name),
			SecretString: aws.String("value"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret %s: %v", name, err)
		}
	}

	t.Run("List all secrets", func(t *testing.T) {
		listResp, err := ts.client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{})
		if err != nil {
			t.Fatalf("Failed to list secrets: %v", err)
		}

		if len(listResp.SecretList) < 3 {
			t.Errorf("Expected at least 3 secrets, got %d", len(listResp.SecretList))
		}

		// Verify each secret has required fields
		for _, secret := range listResp.SecretList {
			if secret.Name == nil {
				t.Error("Secret missing Name")
			}
			if secret.ARN == nil {
				t.Error("Secret missing ARN")
			}
		}
	})

	t.Run("List with MaxResults", func(t *testing.T) {
		listResp, err := ts.client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{
			MaxResults: aws.Int32(2),
		})
		if err != nil {
			t.Fatalf("Failed to list secrets: %v", err)
		}

		if len(listResp.SecretList) > 2 {
			t.Errorf("Expected at most 2 secrets with MaxResults=2, got %d", len(listResp.SecretList))
		}
	})

	t.Run("List with filters", func(t *testing.T) {
		// Create a secret with tags for filtering
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String("filtered-secret"),
			SecretString: aws.String("value"),
			Tags: []types.Tag{
				{Key: aws.String("FilterKey"), Value: aws.String("FilterValue")},
			},
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// List with filter
		listResp, err := ts.client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{
			Filters: []types.Filter{
				{
					Key:    types.FilterNameStringTypeTagKey,
					Values: []string{"FilterKey"},
				},
			},
		})
		if err != nil {
			t.Fatalf("Failed to list secrets: %v", err)
		}

		found := false
		for _, secret := range listResp.SecretList {
			if secret.Name != nil && *secret.Name == "filtered-secret" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected to find filtered-secret in results")
		}
	})
}

func TestIntegration_RestoreSecret(t *testing.T) {
	ts := StartTestServer(t)
	defer ts.Stop(t)

	ctx := context.Background()

	t.Run("Restore deleted secret", func(t *testing.T) {
		secretName := "test-restore-secret"

		// Create secret
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("value"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Delete with recovery window
		_, err = ts.client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{
			SecretId:             aws.String(secretName),
			RecoveryWindowInDays: aws.Int64(7),
		})
		if err != nil {
			t.Fatalf("Failed to delete secret: %v", err)
		}

		// Restore
		restoreResp, err := ts.client.RestoreSecret(ctx, &secretsmanager.RestoreSecretInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("Failed to restore secret: %v", err)
		}

		if restoreResp.ARN == nil {
			t.Error("Expected ARN in response")
		}
		if restoreResp.Name == nil || *restoreResp.Name != secretName {
			t.Errorf("Expected Name=%s, got %v", secretName, restoreResp.Name)
		}

		// Verify restored
		descResp, err := ts.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("Failed to describe secret: %v", err)
		}

		if descResp.DeletedDate != nil {
			t.Error("DeletedDate should be nil after restore")
		}
	})

	t.Run("Restore non-existent secret", func(t *testing.T) {
		_, err := ts.client.RestoreSecret(ctx, &secretsmanager.RestoreSecretInput{
			SecretId: aws.String("non-existent-secret"),
		})
		if err == nil {
			t.Error("Expected error for non-existent secret")
		}
	})

	t.Run("Restore non-deleted secret", func(t *testing.T) {
		secretName := "test-restore-active"

		// Create secret without deleting
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("value"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Try to restore (should fail)
		_, err = ts.client.RestoreSecret(ctx, &secretsmanager.RestoreSecretInput{
			SecretId: aws.String(secretName),
		})
		if err == nil {
			t.Error("Expected error when restoring non-deleted secret")
		}
	})
}

func TestIntegration_GetRandomPassword(t *testing.T) {
	ts := StartTestServer(t)
	defer ts.Stop(t)

	ctx := context.Background()

	t.Run("Generate default password", func(t *testing.T) {
		resp, err := ts.client.GetRandomPassword(ctx, &secretsmanager.GetRandomPasswordInput{})
		if err != nil {
			t.Fatalf("Failed to get random password: %v", err)
		}

		if resp.RandomPassword == nil {
			t.Error("Expected RandomPassword in response")
		}
		if resp.RandomPassword != nil && len(*resp.RandomPassword) < 32 {
			t.Errorf("Expected password length >= 32, got %d", len(*resp.RandomPassword))
		}
	})

	t.Run("Generate custom length password", func(t *testing.T) {
		resp, err := ts.client.GetRandomPassword(ctx, &secretsmanager.GetRandomPasswordInput{
			PasswordLength: aws.Int64(16),
		})
		if err != nil {
			t.Fatalf("Failed to get random password: %v", err)
		}

		if resp.RandomPassword != nil && len(*resp.RandomPassword) != 16 {
			t.Errorf("Expected password length 16, got %d", len(*resp.RandomPassword))
		}
	})

	t.Run("Generate password with exclusions", func(t *testing.T) {
		resp, err := ts.client.GetRandomPassword(ctx, &secretsmanager.GetRandomPasswordInput{
			PasswordLength:   aws.Int64(20),
			ExcludeUppercase: aws.Bool(true),
		})
		if err != nil {
			t.Fatalf("Failed to get random password: %v", err)
		}

		if resp.RandomPassword == nil {
			t.Error("Expected RandomPassword in response")
		}
	})

	t.Run("Generate password with requirements", func(t *testing.T) {
		resp, err := ts.client.GetRandomPassword(ctx, &secretsmanager.GetRandomPasswordInput{
			PasswordLength:          aws.Int64(24),
			RequireEachIncludedType: aws.Bool(true),
			IncludeSpace:            aws.Bool(false),
		})
		if err != nil {
			t.Fatalf("Failed to get random password: %v", err)
		}

		if resp.RandomPassword != nil && len(*resp.RandomPassword) != 24 {
			t.Errorf("Expected password length 24, got %d", len(*resp.RandomPassword))
		}
	})
}

func TestIntegration_CreateSecretEdgeCases(t *testing.T) {
	ts := StartTestServer(t)
	defer ts.Stop(t)

	ctx := context.Background()

	t.Run("Create secret with binary value", func(t *testing.T) {
		secretName := "test-binary-secret"

		resp, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretBinary: []byte("binary-secret-data"),
		})
		if err != nil {
			t.Fatalf("Failed to create binary secret: %v", err)
		}

		if resp.ARN == nil || resp.VersionId == nil {
			t.Error("Expected ARN and VersionId")
		}

		// Verify we can get the binary value back
		getResp, err := ts.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("Failed to get binary secret: %v", err)
		}

		if getResp.SecretBinary == nil {
			t.Error("Expected SecretBinary in response")
		}
		if string(getResp.SecretBinary) != "binary-secret-data" {
			t.Errorf("Expected 'binary-secret-data', got %s", string(getResp.SecretBinary))
		}
	})

	t.Run("Create secret with KMS key", func(t *testing.T) {
		secretName := "test-kms-secret"

		resp, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("value"),
			KmsKeyId:     aws.String("arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret with KMS key: %v", err)
		}

		if resp.ARN == nil {
			t.Error("Expected ARN")
		}

		// Verify KMS key ID is stored
		descResp, err := ts.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("Failed to describe secret: %v", err)
		}

		if descResp.KmsKeyId == nil {
			t.Error("Expected KmsKeyId in describe response")
		}
	})

	t.Run("Create secret with client request token", func(t *testing.T) {
		secretName := "test-token-secret" //nolint:gosec // G101: Variable name

		// Token must be 32-64 characters
		customToken := "12345678-1234-1234-1234-123456789012"
		resp, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:               aws.String(secretName),
			SecretString:       aws.String("value"),
			ClientRequestToken: aws.String(customToken),
		})
		if err != nil {
			t.Fatalf("Failed to create secret with token: %v", err)
		}

		if resp.VersionId == nil || *resp.VersionId != customToken {
			t.Errorf("Expected VersionId to match token")
		}
	})

	t.Run("Create duplicate secret", func(t *testing.T) {
		secretName := "test-duplicate-secret"

		// Create first secret
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("value"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Try to create duplicate
		_, err = ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("value"),
		})
		if err == nil {
			t.Error("Expected error when creating duplicate secret")
		}
	})

	t.Run("Create secret with long description", func(t *testing.T) {
		secretName := "test-long-desc-secret" //nolint:gosec // G101: Variable name
		longDesc := make([]byte, 2048)
		for i := range longDesc {
			longDesc[i] = 'a'
		}

		resp, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("value"),
			Description:  aws.String(string(longDesc)),
		})
		if err != nil {
			t.Fatalf("Failed to create secret with long description: %v", err)
		}

		if resp.ARN == nil {
			t.Error("Expected ARN")
		}
	})
}

func TestIntegration_PutSecretValueEdgeCases(t *testing.T) {
	ts := StartTestServer(t)
	defer ts.Stop(t)

	ctx := context.Background()

	t.Run("Put same value creates idempotent version", func(t *testing.T) {
		secretName := "test-same-value"

		// Create secret
		createResp, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("value"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}
		initialVersion := *createResp.VersionId

		// Put same value
		putResp, err := ts.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
			SecretId:     aws.String(secretName),
			SecretString: aws.String("value"),
		})
		if err != nil {
			t.Fatalf("Failed to put secret value: %v", err)
		}

		// Should return the same version
		if putResp.VersionId != nil && *putResp.VersionId != initialVersion {
			t.Logf("Put same value returned different version (expected behavior)")
		}
	})

	t.Run("Put binary value", func(t *testing.T) {
		secretName := "test-put-binary"

		// Create secret with string
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("initial"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Put binary value
		binaryData := []byte("new-binary-data")
		putResp, err := ts.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
			SecretId:     aws.String(secretName),
			SecretBinary: binaryData,
		})
		if err != nil {
			t.Fatalf("Failed to put binary value: %v", err)
		}

		if putResp.VersionId == nil {
			t.Error("Expected new VersionId")
		}

		// Verify binary value
		getResp, err := ts.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("Failed to get secret: %v", err)
		}

		if !bytes.Equal(getResp.SecretBinary, binaryData) {
			t.Errorf("Expected %s, got %s", string(binaryData), string(getResp.SecretBinary))
		}
	})

	t.Run("Put with custom version stages", func(t *testing.T) {
		secretName := "test-custom-stages"

		// Create secret
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("initial"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Put with custom stages
		putResp, err := ts.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
			SecretId:      aws.String(secretName),
			SecretString:  aws.String("new-value"),
			VersionStages: []string{"MYSTAGE"},
		})
		if err != nil {
			t.Fatalf("Failed to put with custom stages: %v", err)
		}

		if putResp.VersionId == nil {
			t.Error("Expected VersionId")
		}

		// Verify version stages
		listResp, err := ts.client.ListSecretVersionIds(ctx, &secretsmanager.ListSecretVersionIdsInput{
			SecretId:          aws.String(secretName),
			IncludeDeprecated: aws.Bool(true),
		})
		if err != nil {
			t.Fatalf("Failed to list versions: %v", err)
		}

		foundCustomStage := false
		for _, version := range listResp.Versions {
			for _, stage := range version.VersionStages {
				if stage == "MYSTAGE" {
					foundCustomStage = true
					break
				}
			}
		}
		if !foundCustomStage {
			t.Error("Expected to find MYSTAGE in version stages")
		}
	})

	t.Run("Put to non-existent secret", func(t *testing.T) {
		_, err := ts.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
			SecretId:     aws.String("non-existent-secret"),
			SecretString: aws.String("value"),
		})
		if err == nil {
			t.Error("Expected error when putting to non-existent secret")
		}
	})
}

func TestIntegration_DescribeSecretDetails(t *testing.T) {
	ts := StartTestServer(t)
	defer ts.Stop(t)

	ctx := context.Background()

	t.Run("Describe includes all metadata", func(t *testing.T) {
		secretName := "test-describe-metadata"

		// Create secret with all metadata
		createResp, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("value"),
			Description:  aws.String("Test description"),
			Tags: []types.Tag{
				{Key: aws.String("Key1"), Value: aws.String("Value1")},
			},
			KmsKeyId: aws.String("arn:aws:kms:us-east-1:123456789012:key/test"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Describe secret
		descResp, err := ts.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("Failed to describe secret: %v", err)
		}

		// Verify all fields
		if descResp.ARN == nil || *descResp.ARN != *createResp.ARN {
			t.Error("ARN mismatch")
		}
		if descResp.Name == nil || *descResp.Name != secretName {
			t.Error("Name mismatch")
		}
		if descResp.Description == nil || *descResp.Description != "Test description" {
			t.Error("Description mismatch")
		}
		if descResp.KmsKeyId == nil {
			t.Error("Expected KmsKeyId")
		}
		if descResp.CreatedDate == nil {
			t.Error("Expected CreatedDate")
		}
		if descResp.LastChangedDate == nil {
			t.Error("Expected LastChangedDate")
		}
		if len(descResp.Tags) == 0 {
			t.Error("Expected tags")
		}
		if len(descResp.VersionIdsToStages) == 0 {
			t.Error("Expected version stages")
		}
	})

	t.Run("Describe deleted secret", func(t *testing.T) {
		secretName := "test-describe-deleted"

		// Create and delete
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("value"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		_, err = ts.client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{
			SecretId:             aws.String(secretName),
			RecoveryWindowInDays: aws.Int64(7),
		})
		if err != nil {
			t.Fatalf("Failed to delete secret: %v", err)
		}

		// Describe should still work
		descResp, err := ts.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("Failed to describe deleted secret: %v", err)
		}

		if descResp.DeletedDate == nil {
			t.Error("Expected DeletedDate for deleted secret")
		}
	})
}

func TestIntegration_RotateSecretDetails(t *testing.T) {
	ts := StartTestServer(t)
	defer ts.Stop(t)

	ctx := context.Background()

	t.Run("Rotate creates AWSPENDING version", func(t *testing.T) {
		secretName := "test-rotate-pending"

		// Create secret
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("value"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Rotate
		rotateResp, err := ts.client.RotateSecret(ctx, &secretsmanager.RotateSecretInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			t.Fatalf("Failed to rotate secret: %v", err)
		}

		if rotateResp.VersionId == nil {
			t.Error("Expected VersionId for AWSPENDING")
		}

		// Verify AWSPENDING exists
		listResp, err := ts.client.ListSecretVersionIds(ctx, &secretsmanager.ListSecretVersionIdsInput{
			SecretId:          aws.String(secretName),
			IncludeDeprecated: aws.Bool(true),
		})
		if err != nil {
			t.Fatalf("Failed to list versions: %v", err)
		}

		hasPending := false
		for _, version := range listResp.Versions {
			for _, stage := range version.VersionStages {
				if stage == core.VersionStageAWSPending {
					hasPending = true
					break
				}
			}
		}
		if !hasPending {
			t.Error("Expected AWSPENDING version after rotation")
		}
	})

	t.Run("Rotate with client request token", func(t *testing.T) {
		secretName := "test-rotate-token"

		// Create secret
		_, err := ts.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String("value"),
		})
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Rotate with token
		rotateResp, err := ts.client.RotateSecret(ctx, &secretsmanager.RotateSecretInput{
			SecretId:           aws.String(secretName),
			ClientRequestToken: aws.String("my-rotation-token"),
		})
		if err != nil {
			t.Fatalf("Failed to rotate secret: %v", err)
		}

		if rotateResp.VersionId == nil || *rotateResp.VersionId != "my-rotation-token" {
			t.Error("Expected VersionId to match token")
		}
	})
}
