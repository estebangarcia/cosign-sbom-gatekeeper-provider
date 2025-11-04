package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// Server implements the external data provider HTTP server
type Server struct {
	port     string
	verifier *AttestationVerifier
	timeout  time.Duration
	tlsCert  string
	tlsKey   string
}

// NewServer creates a new provider server
func NewServer(port string, verifier *AttestationVerifier, timeout time.Duration, tlsCert, tlsKey string) *Server {
	return &Server{
		port:     port,
		verifier: verifier,
		timeout:  timeout,
		tlsCert:  tlsCert,
		tlsKey:   tlsKey,
	}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	http.HandleFunc("/verify", s.handleVerify)
	http.HandleFunc("/health", s.handleHealth)

	addr := fmt.Sprintf(":%s", s.port)

	// Start with TLS if certificates are provided
	if s.tlsCert != "" && s.tlsKey != "" {
		log.Printf("Starting SBOM provider server on %s (HTTPS)", addr)
		return http.ListenAndServeTLS(addr, s.tlsCert, s.tlsKey, nil)
	}

	// Fallback to HTTP (not recommended for production)
	log.Printf("Starting SBOM provider server on %s (HTTP - not recommended for production)", addr)
	return http.ListenAndServe(addr, nil)
}

// handleVerify handles the verification and SBOM extraction request
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "Failed to read request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Parse provider request
	var providerReq ProviderRequest
	if err := json.Unmarshal(body, &providerReq); err != nil {
		log.Printf("Error parsing request: %v", err)
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	log.Printf("Received request with %d keys", len(providerReq.Request.Keys))

	// Process each image reference
	items := make([]Item, 0, len(providerReq.Request.Keys))
	for _, imageRef := range providerReq.Request.Keys {
		item := s.processImageRef(imageRef)
		items = append(items, item)
	}

	// Build response
	response := ProviderResponse{
		APIVersion: "externaldata.gatekeeper.sh/v1beta1",
		Kind:       "ProviderResponse",
		Response: Response{
			Items: items,
		},
	}

	// Log response summary
	errorCount := 0
	for _, item := range items {
		if item.Error != "" {
			errorCount++
			log.Printf("Error for %s: %s", item.Key, item.Error)
		}
	}
	log.Printf("Processed %d images (%d errors, %d successful)", len(items), errorCount, len(items)-errorCount)

	// Send response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// processImageRef processes a single image reference
// The imageRef format is: image|secrets|certIdentity|certOidcIssuer
func (s *Server) processImageRef(imageRef string) Item {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	// Parse the key to extract verification parameters
	parts := strings.Split(imageRef, "|")
	certIdentity := ""
	certOidcIssuer := ""
	if len(parts) >= 4 {
		certIdentity = parts[2]
		certOidcIssuer = parts[3]
	}

	// Verify attestation and extract SBOM
	sbomData, err := s.verifier.VerifyAndExtractSBOMWithParams(ctx, imageRef, certIdentity, certOidcIssuer)
	if err != nil {
		return Item{
			Key:   imageRef,
			Error: fmt.Sprintf("Failed to verify attestation or extract SBOM: %v", err),
		}
	}

	// Convert SBOM to JSON string
	sbomJSON, err := json.Marshal(sbomData)
	if err != nil {
		return Item{
			Key:   imageRef,
			Error: fmt.Sprintf("Failed to marshal SBOM: %v", err),
		}
	}

	log.Printf("Successfully extracted SBOM for %s (%d bytes)", parts[0], len(sbomJSON))
	return Item{
		Key:   imageRef,
		Value: string(sbomJSON),
	}
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}
