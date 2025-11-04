package provider

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHandleHealth(t *testing.T) {
	server := &Server{
		port:    "8090",
		timeout: 30 * time.Second,
	}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	server.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got '%s'", response["status"])
	}
}

func TestHandleVerifyMethodNotAllowed(t *testing.T) {
	server := &Server{
		port:    "8090",
		timeout: 30 * time.Second,
	}

	req := httptest.NewRequest(http.MethodGet, "/verify", nil)
	w := httptest.NewRecorder()

	server.handleVerify(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestHandleVerifyInvalidRequest(t *testing.T) {
	server := &Server{
		port:    "8090",
		timeout: 30 * time.Second,
	}

	invalidJSON := []byte(`{"invalid": json}`)
	req := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(invalidJSON))
	w := httptest.NewRecorder()

	server.handleVerify(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestHandleVerifyValidRequest(t *testing.T) {
	// This test requires a mock verifier
	// For now, we'll test the request parsing

	server := &Server{
		port:    "8090",
		timeout: 30 * time.Second,
		verifier: &AttestationVerifier{
			// Mock verifier - in real test would use a proper mock
		},
	}

	providerReq := ProviderRequest{
		APIVersion: "externaldata.gatekeeper.sh/v1beta1",
		Kind:       "ProviderRequest",
		Request: Request{
			Keys: []string{"localhost:5000/test:latest"},
		},
	}

	reqBody, err := json.Marshal(providerReq)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleVerify(w, req)

	// Should get a response (might have errors since we're not using real images)
	if w.Code != http.StatusOK {
		t.Logf("Status code: %d", w.Code)
		t.Logf("Response body: %s", w.Body.String())
	}

	var response ProviderResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.APIVersion != "externaldata.gatekeeper.sh/v1beta1" {
		t.Errorf("Expected API version 'externaldata.gatekeeper.sh/v1beta1', got '%s'", response.APIVersion)
	}

	if response.Kind != "ProviderResponse" {
		t.Errorf("Expected kind 'ProviderResponse', got '%s'", response.Kind)
	}
}

func TestProviderRequestParsing(t *testing.T) {
	testJSON := `{
		"apiVersion": "externaldata.gatekeeper.sh/v1beta1",
		"kind": "ProviderRequest",
		"request": {
			"keys": ["image1:tag1", "image2:tag2"]
		}
	}`

	var req ProviderRequest
	if err := json.Unmarshal([]byte(testJSON), &req); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if req.APIVersion != "externaldata.gatekeeper.sh/v1beta1" {
		t.Errorf("Expected API version 'externaldata.gatekeeper.sh/v1beta1', got '%s'", req.APIVersion)
	}

	if len(req.Request.Keys) != 2 {
		t.Errorf("Expected 2 keys, got %d", len(req.Request.Keys))
	}
}

func TestProviderResponseSerialization(t *testing.T) {
	response := ProviderResponse{
		APIVersion: "externaldata.gatekeeper.sh/v1beta1",
		Kind:       "ProviderResponse",
		Response: Response{
			Items: []Item{
				{
					Key:   "test:latest",
					Value: `{"test": "data"}`,
				},
			},
		},
	}

	data, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Failed to marshal response: %v", err)
	}

	var decoded ProviderResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if decoded.Response.Items[0].Key != "test:latest" {
		t.Errorf("Expected key 'test:latest', got '%s'", decoded.Response.Items[0].Key)
	}
}
