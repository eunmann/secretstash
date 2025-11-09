// Package types defines the data types for AWS Secrets Manager operations
package types

import (
	"encoding/json"
	"time"
)

// UnixTime wraps time.Time to marshal/unmarshal as Unix epoch (seconds since 1970)
// AWS Secrets Manager API expects timestamps as Unix epoch numbers, not RFC3339 strings
type UnixTime struct {
	time.Time
}

// MarshalJSON converts the time to Unix epoch seconds
func (t UnixTime) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(t.Unix())
}

// UnmarshalJSON parses Unix epoch seconds into a time
func (t *UnixTime) UnmarshalJSON(data []byte) error {
	var epoch int64
	if err := json.Unmarshal(data, &epoch); err != nil {
		return err
	}
	t.Time = time.Unix(epoch, 0)
	return nil
}

// NewUnixTime creates a UnixTime from a time.Time
func NewUnixTime(t time.Time) *UnixTime {
	if t.IsZero() {
		return nil
	}
	return &UnixTime{t}
}

// NewUnixTimePtr creates a *UnixTime from a *time.Time
func NewUnixTimePtr(t *time.Time) *UnixTime {
	if t == nil || t.IsZero() {
		return nil
	}
	return &UnixTime{*t}
}
