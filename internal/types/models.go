//nolint:revive // AWS SDK compatibility requires specific naming
package types

import (
	"encoding/json"
)

// Secret represents a secret stored in the system
// Corresponds to the DescribeSecret response structure
type Secret struct {
	LastChangedDate    *UnixTime                 `json:"LastChangedDate,omitempty"`
	LastAccessedDate   *UnixTime                 `json:"LastAccessedDate,omitempty"`
	Description        *string                   `json:"Description,omitempty"`
	KmsKeyId           *string                   `json:"KmsKeyId,omitempty"`
	Versions           map[string]*SecretVersion `json:"-"`
	RotationLambdaARN  *string                   `json:"RotationLambdaARN,omitempty"`
	CreatedDate        *UnixTime                 `json:"CreatedDate,omitempty"`
	RotationRules      *RotationRulesType        `json:"RotationRules,omitempty"`
	PrimaryRegion      *string                   `json:"PrimaryRegion,omitempty"`
	LastRotatedDate    *UnixTime                 `json:"LastRotatedDate,omitempty"`
	DeletedDate        *UnixTime                 `json:"DeletedDate,omitempty"`
	NextRotationDate   *UnixTime                 `json:"NextRotationDate,omitempty"`
	OwningService      *string                   `json:"OwningService,omitempty"`
	VersionIdsToStages map[string][]string       `json:"VersionIdsToStages"`
	ARN                string                    `json:"ARN"`
	Name               string                    `json:"Name"`
	Tags               []Tag                     `json:"Tags,omitempty"`
	ReplicationStatus  []ReplicationStatusType   `json:"ReplicationStatus,omitempty"`
	RotationEnabled    bool                      `json:"RotationEnabled"`
}

// SecretVersion represents a version of a secret
type SecretVersion struct {
	CreatedDate      UnixTime  `json:"CreatedDate"`
	SecretString     *string   `json:"SecretString,omitempty"`
	LastAccessedDate *UnixTime `json:"LastAccessedDate,omitempty"`
	VersionId        string    `json:"VersionId"`
	SecretBinary     []byte    `json:"SecretBinary,omitempty"`
	VersionStages    []string  `json:"VersionStages"`
	KmsKeyIds        []string  `json:"KmsKeyIds,omitempty"`
}

// Tag represents a key-value pair for resource tagging
type Tag struct {
	Key   *string `json:"Key,omitempty"`
	Value *string `json:"Value,omitempty"`
}

// RotationRulesType defines rotation configuration
type RotationRulesType struct {
	AutomaticallyAfterDays *int64  `json:"AutomaticallyAfterDays,omitempty"`
	Duration               *string `json:"Duration,omitempty"`
	ScheduleExpression     *string `json:"ScheduleExpression,omitempty"`
}

// ReplicationStatusType describes replication to a region
type ReplicationStatusType struct {
	Region           *string   `json:"Region,omitempty"`
	KmsKeyId         *string   `json:"KmsKeyId,omitempty"`
	Status           *string   `json:"Status,omitempty"`
	StatusMessage    *string   `json:"StatusMessage,omitempty"`
	LastAccessedDate *UnixTime `json:"LastAccessedDate,omitempty"`
}

// SecretListEntry is used in ListSecrets response
type SecretListEntry struct {
	LastChangedDate        *UnixTime           `json:"LastChangedDate,omitempty"`
	LastAccessedDate       *UnixTime           `json:"LastAccessedDate,omitempty"`
	Description            *string             `json:"Description,omitempty"`
	KmsKeyId               *string             `json:"KmsKeyId,omitempty"`
	RotationEnabled        *bool               `json:"RotationEnabled,omitempty"`
	RotationLambdaARN      *string             `json:"RotationLambdaARN,omitempty"`
	RotationRules          *RotationRulesType  `json:"RotationRules,omitempty"`
	LastRotatedDate        *UnixTime           `json:"LastRotatedDate,omitempty"`
	Name                   *string             `json:"Name,omitempty"`
	DeletedDate            *UnixTime           `json:"DeletedDate,omitempty"`
	ARN                    *string             `json:"ARN,omitempty"`
	NextRotationDate       *UnixTime           `json:"NextRotationDate,omitempty"`
	PrimaryRegion          *string             `json:"PrimaryRegion,omitempty"`
	SecretVersionsToStages map[string][]string `json:"SecretVersionsToStages,omitempty"`
	OwningService          *string             `json:"OwningService,omitempty"`
	CreatedDate            *UnixTime           `json:"CreatedDate,omitempty"`
	Tags                   []Tag               `json:"Tags,omitempty"`
}

// Filter for ListSecrets
type Filter struct {
	Key    *string   `json:"Key,omitempty"`
	Values []*string `json:"Values,omitempty"`
}

// SecretValueEntry for BatchGetSecretValue
type SecretValueEntry struct {
	ARN           *string   `json:"ARN,omitempty"`
	Name          *string   `json:"Name,omitempty"`
	VersionId     *string   `json:"VersionId,omitempty"`
	SecretString  *string   `json:"SecretString,omitempty"`
	CreatedDate   *UnixTime `json:"CreatedDate,omitempty"`
	SecretBinary  []byte    `json:"SecretBinary,omitempty"`
	VersionStages []*string `json:"VersionStages,omitempty"`
}

// SecretVersionsListEntry for ListSecretVersionIds
type SecretVersionsListEntry struct {
	VersionId        *string   `json:"VersionId,omitempty"`
	VersionStages    []*string `json:"VersionStages,omitempty"`
	LastAccessedDate *UnixTime `json:"LastAccessedDate,omitempty"`
	CreatedDate      *UnixTime `json:"CreatedDate,omitempty"`
	KmsKeyIds        []*string `json:"KmsKeyIds,omitempty"`
}

// APIError represents errors returned by the API
type APIError struct {
	Type    string `json:"__type"`
	Message string `json:"message"`
}

// Error implements the error interface
func (e *APIError) Error() string {
	return e.Message
}

// Helper function to create a pointer to a string
func StringPtr(s string) *string {
	return &s
}

// Helper function to create a pointer to an int64
func Int64Ptr(i int64) *int64 {
	return &i
}

// Helper function to create a pointer to a bool
func BoolPtr(b bool) *bool {
	return &b
}

// Helper function to create a pointer to an int32
func Int32Ptr(i int32) *int32 {
	return &i
}

// UnmarshalJSON for APIError to handle AWS error format
func (e *APIError) UnmarshalJSON(data []byte) error {
	type Alias APIError
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(e),
	}
	return json.Unmarshal(data, &aux)
}

// MarshalJSON for APIError to ensure correct format
func (e APIError) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type    string `json:"__type"`
		Message string `json:"message"`
	}{
		Type:    e.Type,
		Message: e.Message,
	})
}
