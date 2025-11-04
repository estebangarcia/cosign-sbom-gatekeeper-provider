package provider

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestExtractSBOMFromAttestation_DSSE(t *testing.T) {
	// Create a simple in-toto statement
	statement := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://spdx.dev/Document/v2.3",
		"predicate": map[string]interface{}{
			"SPDXID":            "SPDXRef-DOCUMENT",
			"spdxVersion":       "SPDX-2.3",
			"name":              "test",
			"dataLicense":       "CC0-1.0",
			"documentNamespace": "https://example.com/test",
			"creationInfo": map[string]interface{}{
				"created":  "2024-01-01T00:00:00Z",
				"creators": []string{"Tool: test"},
			},
			"packages": []map[string]interface{}{
				{
					"SPDXID":           "SPDXRef-Package",
					"name":             "test-package",
					"versionInfo":      "1.0.0",
					"licenseConcluded": "MIT",
				},
			},
		},
	}

	statementJSON, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("Failed to marshal statement: %v", err)
	}

	// Wrap in DSSE envelope
	envelope := map[string]interface{}{
		"payload":     base64.StdEncoding.EncodeToString(statementJSON),
		"payloadType": "application/vnd.in-toto+json",
		"signatures":  []interface{}{},
	}

	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("Failed to marshal envelope: %v", err)
	}

	verifier := &AttestationVerifier{}
	sbom, err := verifier.extractSBOMFromAttestation(envelopeJSON)
	if err != nil {
		t.Fatalf("Failed to extract SBOM: %v", err)
	}

	if sbom == nil {
		t.Fatal("Expected SBOM, got nil")
	}

	unified, ok := sbom.(*UnifiedSBOM)
	if !ok {
		t.Fatal("Expected UnifiedSBOM type")
	}

	if unified.Format != "spdx" {
		t.Errorf("Expected format 'spdx', got '%s'", unified.Format)
	}

	if len(unified.Packages) != 1 {
		t.Errorf("Expected 1 package, got %d", len(unified.Packages))
	}

	if unified.Packages[0].Name != "test-package" {
		t.Errorf("Expected package name 'test-package', got '%s'", unified.Packages[0].Name)
	}
}

func TestExtractSBOMFromAttestation_PlainSPDX(t *testing.T) {
	// Create a plain in-toto statement (not DSSE wrapped)
	statement := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://spdx.dev/Document",
		"predicate": map[string]interface{}{
			"SPDXID":            "SPDXRef-DOCUMENT",
			"spdxVersion":       "SPDX-2.3",
			"name":              "test",
			"dataLicense":       "CC0-1.0",
			"documentNamespace": "https://example.com/test",
			"creationInfo": map[string]interface{}{
				"created":  "2024-01-01T00:00:00Z",
				"creators": []string{"Tool: test"},
			},
			"packages": []map[string]interface{}{
				{
					"SPDXID":          "SPDXRef-Package",
					"name":            "curl",
					"versionInfo":     "7.68.0",
					"licenseDeclared": "Apache-2.0",
				},
			},
		},
	}

	statementJSON, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("Failed to marshal statement: %v", err)
	}

	verifier := &AttestationVerifier{}
	sbom, err := verifier.extractSBOMFromAttestation(statementJSON)
	if err != nil {
		t.Fatalf("Failed to extract SBOM: %v", err)
	}

	unified, ok := sbom.(*UnifiedSBOM)
	if !ok {
		t.Fatal("Expected UnifiedSBOM type")
	}

	if len(unified.Packages) != 1 {
		t.Errorf("Expected 1 package, got %d", len(unified.Packages))
	}

	pkg := unified.Packages[0]
	if pkg.Name != "curl" {
		t.Errorf("Expected package name 'curl', got '%s'", pkg.Name)
	}

	if pkg.License != "Apache-2.0" {
		t.Errorf("Expected license 'Apache-2.0', got '%s'", pkg.License)
	}
}

func TestExtractSBOMFromAttestation_CycloneDX(t *testing.T) {
	statement := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://cyclonedx.org/bom",
		"predicate": map[string]interface{}{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.4",
			"version":     1,
			"components": []map[string]interface{}{
				{
					"type":    "library",
					"name":    "express",
					"version": "4.18.2",
					"purl":    "pkg:npm/express@4.18.2",
					"licenses": []map[string]interface{}{
						{
							"license": map[string]interface{}{
								"id": "MIT",
							},
						},
					},
				},
			},
		},
	}

	statementJSON, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("Failed to marshal statement: %v", err)
	}

	verifier := &AttestationVerifier{}
	sbom, err := verifier.extractSBOMFromAttestation(statementJSON)
	if err != nil {
		t.Fatalf("Failed to extract SBOM: %v", err)
	}

	unified, ok := sbom.(*UnifiedSBOM)
	if !ok {
		t.Fatal("Expected UnifiedSBOM type")
	}

	if unified.Format != "cyclonedx" {
		t.Errorf("Expected format 'cyclonedx', got '%s'", unified.Format)
	}

	if len(unified.Packages) != 1 {
		t.Errorf("Expected 1 package, got %d", len(unified.Packages))
	}

	pkg := unified.Packages[0]
	if pkg.Name != "express" {
		t.Errorf("Expected package name 'express', got '%s'", pkg.Name)
	}

	if pkg.License != "MIT" {
		t.Errorf("Expected license 'MIT', got '%s'", pkg.License)
	}

	if pkg.PURL != "pkg:npm/express@4.18.2" {
		t.Errorf("Expected PURL 'pkg:npm/express@4.18.2', got '%s'", pkg.PURL)
	}
}

func TestExtractSBOMFromAttestation_UnsupportedType(t *testing.T) {
	statement := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://example.com/unknown",
		"predicate":     map[string]interface{}{},
	}

	statementJSON, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("Failed to marshal statement: %v", err)
	}

	verifier := &AttestationVerifier{}
	sbom, err := verifier.extractSBOMFromAttestation(statementJSON)

	// Should not return an error, but should return nil
	if err != nil {
		t.Errorf("Expected no error for unsupported type, got: %v", err)
	}

	if sbom != nil {
		t.Errorf("Expected nil SBOM for unsupported type, got: %v", sbom)
	}
}

func TestExtractAndNormalizeSPDX_LicenseFallback(t *testing.T) {
	// Test that licenseDeclared is used when licenseConcluded is empty
	spdx := SPDXDocument{
		SPDXID:      "SPDXRef-DOCUMENT",
		SPDXVersion: "SPDX-2.3",
		Name:        "test",
		Packages: []SPDXPackage{
			{
				Name:             "pkg1",
				VersionInfo:      "1.0.0",
				LicenseConcluded: "",
				LicenseDeclared:  "BSD-3-Clause",
			},
			{
				Name:             "pkg2",
				VersionInfo:      "2.0.0",
				LicenseConcluded: "Apache-2.0",
				LicenseDeclared:  "MIT",
			},
		},
	}

	spdxJSON, err := json.Marshal(spdx)
	if err != nil {
		t.Fatalf("Failed to marshal SPDX: %v", err)
	}

	verifier := &AttestationVerifier{}
	unified, err := verifier.extractAndNormalizeSPDX(spdxJSON)
	if err != nil {
		t.Fatalf("Failed to normalize SPDX: %v", err)
	}

	if len(unified.Packages) != 2 {
		t.Fatalf("Expected 2 packages, got %d", len(unified.Packages))
	}

	// pkg1 should use licenseDeclared
	if unified.Packages[0].License != "BSD-3-Clause" {
		t.Errorf("Expected license 'BSD-3-Clause', got '%s'", unified.Packages[0].License)
	}

	// pkg2 should use licenseConcluded
	if unified.Packages[1].License != "Apache-2.0" {
		t.Errorf("Expected license 'Apache-2.0', got '%s'", unified.Packages[1].License)
	}
}

func TestExtractAndNormalizeCycloneDX_LicenseExtraction(t *testing.T) {
	// Test license extraction from CycloneDX
	cdx := CycloneDXBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.4",
		Version:     1,
		Components: []CycloneDXComponent{
			{
				Name:    "pkg-with-id",
				Version: "1.0.0",
				Licenses: []CycloneDXLicense{
					{
						License: CycloneDXLicenseInfo{
							ID:   "MIT",
							Name: "MIT License",
						},
					},
				},
			},
			{
				Name:    "pkg-with-name",
				Version: "2.0.0",
				Licenses: []CycloneDXLicense{
					{
						License: CycloneDXLicenseInfo{
							ID:   "",
							Name: "Custom License",
						},
					},
				},
			},
			{
				Name:     "pkg-no-license",
				Version:  "3.0.0",
				Licenses: []CycloneDXLicense{},
			},
		},
	}

	cdxJSON, err := json.Marshal(cdx)
	if err != nil {
		t.Fatalf("Failed to marshal CycloneDX: %v", err)
	}

	verifier := &AttestationVerifier{}
	unified, err := verifier.extractAndNormalizeCycloneDX(cdxJSON)
	if err != nil {
		t.Fatalf("Failed to normalize CycloneDX: %v", err)
	}

	if len(unified.Packages) != 3 {
		t.Fatalf("Expected 3 packages, got %d", len(unified.Packages))
	}

	// Should prefer ID over Name
	if unified.Packages[0].License != "MIT" {
		t.Errorf("Expected license 'MIT', got '%s'", unified.Packages[0].License)
	}

	// Should use Name when ID is empty
	if unified.Packages[1].License != "Custom License" {
		t.Errorf("Expected license 'Custom License', got '%s'", unified.Packages[1].License)
	}

	// Should be empty when no licenses
	if unified.Packages[2].License != "" {
		t.Errorf("Expected empty license, got '%s'", unified.Packages[2].License)
	}
}
