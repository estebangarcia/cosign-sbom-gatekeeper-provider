package provider

// ProviderRequest is the API request for the external data provider
type ProviderRequest struct {
	APIVersion string  `json:"apiVersion"`
	Kind       string  `json:"kind"`
	Request    Request `json:"request"`
}

// Request contains the keys to be looked up
type Request struct {
	Keys []string `json:"keys"`
}

// ProviderResponse is the API response from the external data provider
type ProviderResponse struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Response   Response `json:"response"`
}

// Response contains the items returned by the provider
type Response struct {
	Items      []Item `json:"items,omitempty"`
	SystemError string `json:"systemError,omitempty"`
}

// Item represents a single key-value pair
type Item struct {
	Key   string `json:"key"`
	Value string `json:"value,omitempty"`
	Error string `json:"error,omitempty"`
}

// UnifiedSBOM represents a normalized SBOM structure that works for both SPDX and CycloneDX
type UnifiedSBOM struct {
	Format   string          `json:"format"`   // "spdx" or "cyclonedx"
	Packages []UnifiedPackage `json:"packages"` // Normalized packages from either format
}

// UnifiedPackage represents a normalized package structure
type UnifiedPackage struct {
	Name     string `json:"name"`
	Version  string `json:"versionInfo"`
	License  string `json:"licenseConcluded"` // Normalized license info
	PURL     string `json:"purl,omitempty"`
}

// SPDXDocument represents a simplified SPDX SBOM structure
type SPDXDocument struct {
	SPDXID           string        `json:"SPDXID"`
	SPDXVersion      string        `json:"spdxVersion"`
	CreationInfo     CreationInfo  `json:"creationInfo"`
	Name             string        `json:"name"`
	DataLicense      string        `json:"dataLicense"`
	DocumentNamespace string       `json:"documentNamespace"`
	Packages         []SPDXPackage `json:"packages"`
}

// CreationInfo contains SPDX document creation metadata
type CreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

// SPDXPackage represents a package in the SBOM
type SPDXPackage struct {
	SPDXID             string   `json:"SPDXID"`
	Name               string   `json:"name"`
	VersionInfo        string   `json:"versionInfo,omitempty"`
	Supplier           string   `json:"supplier,omitempty"`
	DownloadLocation   string   `json:"downloadLocation,omitempty"`
	FilesAnalyzed      bool     `json:"filesAnalyzed"`
	LicenseConcluded   string   `json:"licenseConcluded,omitempty"`
	LicenseDeclared    string   `json:"licenseDeclared,omitempty"`
	CopyrightText      string   `json:"copyrightText,omitempty"`
	ExternalRefs       []ExtRef `json:"externalRefs,omitempty"`
}

// ExtRef represents an external reference for a package
type ExtRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// CycloneDXBOM represents a CycloneDX SBOM structure
type CycloneDXBOM struct {
	BOMFormat    string              `json:"bomFormat"`
	SpecVersion  string              `json:"specVersion"`
	Version      int                 `json:"version"`
	Metadata     CycloneDXMetadata   `json:"metadata,omitempty"`
	Components   []CycloneDXComponent `json:"components,omitempty"`
}

// CycloneDXMetadata contains BOM metadata
type CycloneDXMetadata struct {
	Timestamp string `json:"timestamp,omitempty"`
}

// CycloneDXComponent represents a component in CycloneDX
type CycloneDXComponent struct {
	Type       string              `json:"type"`
	Name       string              `json:"name"`
	Version    string              `json:"version,omitempty"`
	Purl       string              `json:"purl,omitempty"`
	Licenses   []CycloneDXLicense  `json:"licenses,omitempty"`
	Hashes     []CycloneDXHash     `json:"hashes,omitempty"`
}

// CycloneDXLicense represents a license
type CycloneDXLicense struct {
	License CycloneDXLicenseInfo `json:"license,omitempty"`
}

// CycloneDXLicenseInfo contains license details
type CycloneDXLicenseInfo struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// CycloneDXHash represents a hash value
type CycloneDXHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}
