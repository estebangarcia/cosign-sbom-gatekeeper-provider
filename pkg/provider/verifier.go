package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	k8schain "github.com/google/go-containerregistry/pkg/authn/kubernetes"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/sigstore-go/pkg/root"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// AttestationVerifier handles in-toto attestation verification
type AttestationVerifier struct {
	useReferrers bool
	keychain     authn.Keychain
	trustedRoot  root.TrustedMaterial // Cached trusted root
}

// NewAttestationVerifier creates a new attestation verifier
func NewAttestationVerifier() (*AttestationVerifier, error) {
	// Check if referrers API should be used
	useReferrers := os.Getenv("USE_REFERRERS_API") == "true"

	// Set up authentication keychain
	// This will use:
	// 1. Service account imagePullSecrets mounted at /var/run/secrets/kubernetes.io/serviceaccount
	// 2. Docker config from ~/.docker/config.json
	// 3. Environment variables (DOCKER_CONFIG, etc.)
	ctx := context.Background()
	keychains := []authn.Keychain{authn.DefaultKeychain}

	inClusterKeychain, err := k8schain.NewInCluster(ctx, k8schain.Options{})
	if err != nil {
		log.Printf("Warning: Failed to create in-cluster keychain: %v, falling back to default keychain only", err)
	} else {
		keychains = append(keychains, inClusterKeychain)
	}

	keychain := authn.NewMultiKeychain(keychains...)

	// Pre-fetch trusted root if using Fulcio to avoid fetching it on every request
	log.Printf("Pre-fetching Sigstore trusted root ...")
	tr, err := root.FetchTrustedRoot()
	if err != nil {
		return nil, err
	}

	return &AttestationVerifier{
		useReferrers: useReferrers,
		keychain:     keychain,
		trustedRoot:  tr,
	}, nil
}

// VerifyAndExtractSBOMWithParams verifies attestation and extracts SBOM with custom parameters
// Key format: "image|[\"secret1\",\"secret2\"]|certIdentity|certOidcIssuer"
func (v *AttestationVerifier) VerifyAndExtractSBOMWithParams(ctx context.Context, key string, certIdentity, certOidcIssuer string) (interface{}, error) {
	// Parse the key to extract image reference and imagePullSecrets
	// Key format: image|secrets|certIdentity|certOidcIssuer
	parts := strings.SplitN(key, "|", 4)
	imageRef := parts[0]
	var secretNames []string

	if len(parts) >= 2 && parts[1] != "" {
		if err := json.Unmarshal([]byte(parts[1]), &secretNames); err != nil {
			log.Printf("Warning: Failed to parse imagePullSecrets from key: %v, using default keychain", err)
		}
	}

	// Extract identity/issuer from key if not provided as parameters
	if certIdentity == "" && len(parts) >= 3 {
		certIdentity = parts[2]
	}
	if certOidcIssuer == "" && len(parts) >= 4 {
		certOidcIssuer = parts[3]
	}

	log.Printf("Verifying attestation for image: %s (secrets: %d, identity: %s, issuer: %s)",
		imageRef, len(secretNames), certIdentity, certOidcIssuer)

	// Create keychain with secrets from the pod being evaluated
	keychain, err := v.createKeychainWithSecrets(ctx, secretNames)
	if err != nil {
		log.Printf("Warning: Failed to create keychain with secrets: %v, using default", err)
		keychain = v.keychain // Fall back to default
	}

	// Parse image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference: %w", err)
	}

	// Set up cosign check options
	checkOpts := &cosign.CheckOpts{
		RegistryClientOpts: []ociremote.Option{
			ociremote.WithRemoteOptions(remote.WithAuthFromKeychain(keychain), remote.WithContext(ctx)),
		},
		ClaimVerifier:     cosign.IntotoSubjectClaimVerifier, // Verify in-toto attestations
		IgnoreTlog:        false,                             // Always check transparency log for attestations
		IgnoreSCT:         true,                              // SCT is for certificates, not needed for attestations
		ExperimentalOCI11: v.useReferrers,
		RekorPubKeys:      nil, // Use default Rekor public keys
		CTLogPubKeys:      nil, // Not needed for attestations
		NewBundleFormat:   true,
	}

	// Add identity constraints if provided
	if certIdentity != "" || certOidcIssuer != "" {
		checkOpts.Identities = []cosign.Identity{{
			Issuer:  certOidcIssuer,
			Subject: certIdentity,
		}}
	}

	// Use cached trusted root (fetched at startup)
	checkOpts.TrustedMaterial = v.trustedRoot
	checkOpts.SigVerifier = nil

	// Fetch and verify attestations - try OCI 1.1 first, fallback to legacy
	attestations, _, fetchErr := cosign.VerifyImageAttestations(ctx, ref, checkOpts)
	if fetchErr != nil {
		// Fallback to legacy tag method
		checkOpts.ExperimentalOCI11 = false
		checkOpts.NewBundleFormat = false
		attestations, _, fetchErr = cosign.VerifyImageAttestations(ctx, ref, checkOpts)
	}

	if fetchErr != nil {
		return nil, fmt.Errorf("failed to fetch/verify attestations: %w", fetchErr)
	}

	if len(attestations) == 0 {
		return nil, fmt.Errorf("no attestations found")
	}

	// Extract SBOM from attestations
	for _, att := range attestations {
		payload, err := att.Payload()
		if err != nil {
			continue
		}

		sbom, err := v.extractSBOMFromAttestation(payload)
		if err != nil {
			continue
		}

		if sbom != nil {
			return sbom, nil
		}
	}

	return nil, fmt.Errorf("no SBOM found in attestations")
}

// createKeychainWithSecrets creates a keychain using the specified imagePullSecrets
func (v *AttestationVerifier) createKeychainWithSecrets(ctx context.Context, secretNames []string) (authn.Keychain, error) {
	if len(secretNames) == 0 {
		return v.keychain, nil
	}

	// Get in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get in-cluster config: %w", err)
	}

	// Create Kubernetes client
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	// Get the namespace from the service account
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}

	// Fetch the secrets
	var secrets []corev1.Secret
	for _, secretName := range secretNames {
		secret, err := clientset.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			log.Printf("Warning: Failed to get secret %s: %v", secretName, err)
			continue
		}
		secrets = append(secrets, *secret)
	}

	if len(secrets) == 0 {
		return v.keychain, nil
	}

	// Create keychain from the secrets
	secretKeychain, err := k8schain.NewFromPullSecrets(ctx, secrets)
	if err != nil {
		return nil, fmt.Errorf("failed to create keychain from secrets: %w", err)
	}

	// Combine with default keychain
	return authn.NewMultiKeychain(secretKeychain, v.keychain), nil
}

// extractSBOMFromAttestation extracts SBOM data from an attestation
func (v *AttestationVerifier) extractSBOMFromAttestation(attestation []byte) (interface{}, error) {
	// Check if this is a DSSE envelope (contains base64-encoded payload)
	var envelope struct {
		Payload     string        `json:"payload"`
		PayloadType string        `json:"payloadType"`
		Signatures  []interface{} `json:"signatures"`
	}

	if err := json.Unmarshal(attestation, &envelope); err == nil && envelope.Payload != "" {
		decodedPayload, err := base64.StdEncoding.DecodeString(envelope.Payload)
		if err != nil {
			return nil, fmt.Errorf("failed to decode DSSE payload: %w", err)
		}
		attestation = decodedPayload
	}

	// Parse the in-toto statement
	var statement struct {
		Type          string          `json:"_type"`
		PredicateType string          `json:"predicateType"`
		Predicate     json.RawMessage `json:"predicate"`
	}

	if err := json.Unmarshal(attestation, &statement); err != nil {
		return nil, fmt.Errorf("failed to parse attestation statement: %w", err)
	}

	// Extract SBOM based on predicate type
	switch statement.PredicateType {
	case "https://spdx.dev/Document", "https://spdx.dev/Document/v2.3", "spdx":
		return v.extractAndNormalizeSPDX(statement.Predicate)
	case "https://cyclonedx.org/bom", "https://cyclonedx.org/schema", "cyclonedx":
		return v.extractAndNormalizeCycloneDX(statement.Predicate)
	default:
		return nil, nil
	}
}

// extractAndNormalizeSPDX extracts and normalizes SPDX SBOM data
func (v *AttestationVerifier) extractAndNormalizeSPDX(predicate json.RawMessage) (*UnifiedSBOM, error) {
	var sbom SPDXDocument
	if err := json.Unmarshal(predicate, &sbom); err != nil {
		return nil, fmt.Errorf("failed to parse SPDX SBOM: %w", err)
	}

	unified := &UnifiedSBOM{
		Format:   "spdx",
		Packages: make([]UnifiedPackage, 0, len(sbom.Packages)),
	}

	for _, pkg := range sbom.Packages {
		license := pkg.LicenseConcluded
		if license == "" {
			license = pkg.LicenseDeclared
		}

		unified.Packages = append(unified.Packages, UnifiedPackage{
			Name:    pkg.Name,
			Version: pkg.VersionInfo,
			License: license,
		})
	}

	return unified, nil
}

// extractAndNormalizeCycloneDX extracts and normalizes CycloneDX SBOM data
func (v *AttestationVerifier) extractAndNormalizeCycloneDX(predicate json.RawMessage) (*UnifiedSBOM, error) {
	var sbom CycloneDXBOM
	if err := json.Unmarshal(predicate, &sbom); err != nil {
		return nil, fmt.Errorf("failed to parse CycloneDX SBOM: %w", err)
	}

	unified := &UnifiedSBOM{
		Format:   "cyclonedx",
		Packages: make([]UnifiedPackage, 0, len(sbom.Components)),
	}

	for _, comp := range sbom.Components {
		license := ""
		if len(comp.Licenses) > 0 {
			if comp.Licenses[0].License.ID != "" {
				license = comp.Licenses[0].License.ID
			} else if comp.Licenses[0].License.Name != "" {
				license = comp.Licenses[0].License.Name
			}
		}

		unified.Packages = append(unified.Packages, UnifiedPackage{
			Name:    comp.Name,
			Version: comp.Version,
			License: license,
			PURL:    comp.Purl,
		})
	}

	return unified, nil
}
