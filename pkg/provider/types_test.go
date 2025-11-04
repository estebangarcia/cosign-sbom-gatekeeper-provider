package provider

import (
	"encoding/json"
	"testing"
)

func TestSPDXDocumentParsing(t *testing.T) {
	spdxJSON := `{
		"SPDXID": "SPDXRef-DOCUMENT",
		"spdxVersion": "SPDX-2.3",
		"creationInfo": {
			"created": "2024-01-01T00:00:00Z",
			"creators": ["Tool: syft"]
		},
		"name": "test-package",
		"dataLicense": "CC0-1.0",
		"documentNamespace": "https://example.com/test",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package-curl",
				"name": "curl",
				"versionInfo": "7.68.0",
				"supplier": "Organization: curl",
				"downloadLocation": "https://curl.se",
				"filesAnalyzed": false,
				"licenseConcluded": "MIT",
				"licenseDeclared": "MIT"
			}
		]
	}`

	var doc SPDXDocument
	if err := json.Unmarshal([]byte(spdxJSON), &doc); err != nil {
		t.Fatalf("Failed to parse SPDX document: %v", err)
	}

	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("Expected SPDXID 'SPDXRef-DOCUMENT', got '%s'", doc.SPDXID)
	}

	if len(doc.Packages) != 1 {
		t.Errorf("Expected 1 package, got %d", len(doc.Packages))
	}

	pkg := doc.Packages[0]
	if pkg.Name != "curl" {
		t.Errorf("Expected package name 'curl', got '%s'", pkg.Name)
	}

	if pkg.VersionInfo != "7.68.0" {
		t.Errorf("Expected version '7.68.0', got '%s'", pkg.VersionInfo)
	}

	if pkg.LicenseConcluded != "MIT" {
		t.Errorf("Expected license 'MIT', got '%s'", pkg.LicenseConcluded)
	}
}

func TestCycloneDXBOMParsing(t *testing.T) {
	cdxJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"version": 1,
		"metadata": {
			"timestamp": "2024-01-01T00:00:00Z"
		},
		"components": [
			{
				"type": "library",
				"name": "express",
				"version": "4.18.2",
				"purl": "pkg:npm/express@4.18.2",
				"licenses": [
					{
						"license": {
							"id": "MIT"
						}
					}
				]
			}
		]
	}`

	var bom CycloneDXBOM
	if err := json.Unmarshal([]byte(cdxJSON), &bom); err != nil {
		t.Fatalf("Failed to parse CycloneDX BOM: %v", err)
	}

	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("Expected BOMFormat 'CycloneDX', got '%s'", bom.BOMFormat)
	}

	if len(bom.Components) != 1 {
		t.Errorf("Expected 1 component, got %d", len(bom.Components))
	}

	component := bom.Components[0]
	if component.Name != "express" {
		t.Errorf("Expected component name 'express', got '%s'", component.Name)
	}

	if component.Version != "4.18.2" {
		t.Errorf("Expected version '4.18.2', got '%s'", component.Version)
	}
}

func TestInTotoStatementParsing(t *testing.T) {
	// Simulate an in-toto attestation statement with SPDX predicate
	statementJSON := `{
		"_type": "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://spdx.dev/Document/v2.3",
		"subject": [
			{
				"name": "localhost:5000/test",
				"digest": {
					"sha256": "abc123"
				}
			}
		],
		"predicate": {
			"SPDXID": "SPDXRef-DOCUMENT",
			"spdxVersion": "SPDX-2.3",
			"creationInfo": {
				"created": "2024-01-01T00:00:00Z",
				"creators": ["Tool: syft"]
			},
			"name": "test",
			"dataLicense": "CC0-1.0",
			"documentNamespace": "https://example.com/test",
			"packages": []
		}
	}`

	var statement struct {
		Type          string          `json:"_type"`
		PredicateType string          `json:"predicateType"`
		Predicate     json.RawMessage `json:"predicate"`
	}

	if err := json.Unmarshal([]byte(statementJSON), &statement); err != nil {
		t.Fatalf("Failed to parse statement: %v", err)
	}

	if statement.Type != "https://in-toto.io/Statement/v0.1" {
		t.Errorf("Expected type 'https://in-toto.io/Statement/v0.1', got '%s'", statement.Type)
	}

	if statement.PredicateType != "https://spdx.dev/Document/v2.3" {
		t.Errorf("Expected predicate type 'https://spdx.dev/Document/v2.3', got '%s'", statement.PredicateType)
	}

	// Parse the predicate
	var doc SPDXDocument
	if err := json.Unmarshal(statement.Predicate, &doc); err != nil {
		t.Fatalf("Failed to parse SPDX predicate: %v", err)
	}

	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("Expected SPDXID 'SPDXRef-DOCUMENT', got '%s'", doc.SPDXID)
	}
}
