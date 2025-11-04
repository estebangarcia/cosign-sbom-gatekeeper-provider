package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/yourusername/sbom-gatekeeper-provider/pkg/provider"
)

func main() {
	// Parse command-line flags
	port := flag.String("port", getEnv("PORT", "8090"), "Server port")
	timeout := flag.Duration("timeout", getEnvDuration("TIMEOUT", 30*time.Second), "Verification timeout")
	tlsCert := flag.String("tls-cert", getEnv("TLS_CERT", ""), "Path to TLS certificate")
	tlsKey := flag.String("tls-key", getEnv("TLS_KEY", ""), "Path to TLS private key")

	flag.Parse()

	// Create attestation verifier
	verifier, err := provider.NewAttestationVerifier()
	if err != nil {
		log.Fatal(err)
	}

	// Create and start server
	server := provider.NewServer(*port, verifier, *timeout, *tlsCert, *tlsKey)

	log.Printf("Configuration:")
	log.Printf("  Port: %s", *port)
	log.Printf("  TLS Enabled: %v", *tlsCert != "" && *tlsKey != "")
	log.Printf("  Timeout: %v", *timeout)

	if err := server.Start(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// getEnv gets an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvDuration gets a duration environment variable or returns a default value
func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}
