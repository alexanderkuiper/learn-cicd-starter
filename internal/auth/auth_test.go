package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Table-driven tests - idiomatic Go approach
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "Valid API key",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key-123"},
			},
			expectedKey:   "my-secret-key-123",
			expectedError: nil,
		},
		{
			name:          "No authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed header - missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer my-token"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed header - only ApiKey without value",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "test",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)

			// Check the returned key
			if gotKey != tt.expectedKey {
				t.Errorf("GetAPIKey() key = %v, want %v", gotKey, tt.expectedKey)
			}

			// Check the error
			if (gotErr != nil) != (tt.expectedError != nil) {
				t.Errorf("GetAPIKey() error = %v, wantErr %v", gotErr, tt.expectedError)
			}

			// If we expect an error, check the message matches
			if gotErr != nil && tt.expectedError != nil {
				if gotErr.Error() != tt.expectedError.Error() {
					t.Errorf("GetAPIKey() error = %v, wantErr %v", gotErr, tt.expectedError)
				}
			}
		})
	}
}