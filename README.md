# SBOM Gatekeeper Provider

> **⚠️ PROOF OF CONCEPT - NOT FOR PRODUCTION USE**
>
> This is a proof-of-concept implementation to demonstrate how OPA Gatekeeper's external data feature can be used to ingest SBOM (Software Bill of Materials) data for policy enforcement. **This project is not intended for production use and users assume all risks if deployed in production environments.**
>
> **Known Limitations:**
> - Only supports keyless OIDC signing verified via Sigstore transparency log
> - Requires increased webhook timeouts (attestation verification can exceed default 3s timeout)
> - Limited error handling and retry logic
> - No rate limiting or DoS protection
> - Minimal logging and observability

## Overview

An OPA Gatekeeper external data provider that verifies Sigstore in-toto attestations and extracts SBOM data for use in admission control policies.

### What It Does

1. **Verifies Attestations**: Uses Sigstore/cosign to verify keyless OIDC-signed attestations via Rekor transparency log
2. **Extracts SBOMs**: Parses SPDX 2.3 and CycloneDX SBOM formats from in-toto attestations
3. **Enables Policy Decisions**: Makes SBOM data available to Rego policies for admission control

### Features

- ✅ Keyless verification using Sigstore (Fulcio certificates + Rekor transparency log)
- ✅ OCI 1.1 Referrers API support with automatic fallback to legacy tag discovery
- ✅ SPDX 2.3 and CycloneDX SBOM format support
- ✅ Unified package/license data model for both formats
- ✅ Private registry authentication using pod imagePullSecrets
- ✅ Configurable identity/issuer verification per-constraint
- ✅ TLS support for secure communication

## Prerequisites

- Kubernetes cluster (v1.23+)
- OPA Gatekeeper v3.10+ with external data feature enabled
- Container images with Sigstore keyless attestations
- **Increased Gatekeeper webhook timeout** (recommended: 10s or higher)

## Quick Start

### 1. Configure Gatekeeper Webhook Timeout

**IMPORTANT**: The default Gatekeeper admission webhook timeout is 3 seconds, which is often insufficient for fetching and verifying attestations. Increase it to at least 10 seconds:

```bash
kubectl patch validatingwebhookconfiguration gatekeeper-validating-webhook-configuration \
  --type='json' \
  -p='[{"op": "replace", "path": "/webhooks/0/timeoutSeconds", "value": 10}]'
```

### 2. Deploy the Provider

```bash
# Deploy provider, RBAC, and service
kubectl apply -f manifest/deployment.yaml
kubectl apply -f manifest/rbac.yaml
kubectl apply -f manifest/service.yaml

# Register provider with Gatekeeper
kubectl apply -f manifest/provider.yaml
```

### 3. Apply Policy Template and Constraint

```bash
# Apply the constraint template
kubectl apply -f policy/template.yaml

# Apply example constraint
kubectl apply -f policy/constraint.yaml
```

### 4. Test the Provider

```bash
# Try deploying a pod with a signed image
kubectl apply -f test-deployment.yaml
```

## Configuration

### Environment Variables

Configure the provider via deployment environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8090` | HTTP server port |
| `TIMEOUT` | `30s` | Verification timeout per image |
| `USE_REFERRERS_API` | `true` | Enable OCI 1.1 Referrers API (fallback to legacy if unsupported) |
| `POD_NAMESPACE` | - | **Required**: Provider pod namespace (set via downward API) |
| `TLS_CERT` | `/certs/tls.crt` | Path to TLS certificate |
| `TLS_KEY` | `/certs/tls.key` | Path to TLS private key |

### Constraint Parameters

The `K8sSBOMValidation` constraint supports the following parameters:

#### Required Parameters

- **`provider`** (string): Name of the external data provider (typically `"sbom-provider"`)

#### Verification Parameters

- **`certIdentity`** (string): Certificate identity (subject) to verify (e.g., `"user@example.com"`, SPIFFE ID)
- **`certOidcIssuer`** (string): OIDC issuer URL to verify (e.g., `"https://github.com/login/oauth"`, `"https://token.actions.githubusercontent.com"`)

#### Policy Parameters

- **`prohibitedPackages`** (array): List of packages to block
  ```yaml
  prohibitedPackages:
    - name: "log4j-core"
      version: "2.14.1"  # Block specific version
    - name: "malicious-pkg"
      version: "*"       # Block all versions
  ```

- **`prohibitedLicenses`** (array): List of licenses to block (substring match)
  ```yaml
  prohibitedLicenses:
    - "GPL-3.0"
    - "AGPL"
  ```

- **`requiredLicenses`** (array): Allowlist of acceptable licenses (packages without these are blocked)
  ```yaml
  requiredLicenses:
    - "Apache-2.0"
    - "MIT"
    - "BSD"
  ```

### Example Constraint

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sSBOMValidation
metadata:
  name: block-vulnerable-packages
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
      - apiGroups: ["apps"]
        kinds: ["Deployment", "StatefulSet", "DaemonSet"]
  parameters:
    provider: sbom-provider

    # Verification identity constraints
    certIdentity: "user@example.com"
    certOidcIssuer: "https://github.com/login/oauth"

    # Block specific vulnerable packages
    prohibitedPackages:
      - name: "log4j-core"
        version: "2.14.1"

    # Require approved licenses
    requiredLicenses:
      - "Apache-2.0"
      - "MIT"
      - "BSD-3-Clause"
```

## How It Works

### Keyless Verification Flow

1. **Extract identity from key**: Gatekeeper sends image reference with identity/issuer parameters
2. **Fetch attestations**: Provider discovers attestations via OCI Referrers API (or legacy tags)
3. **Verify signatures**: Cosign verifies attestations using:
   - Fulcio certificate verification (checks identity/issuer)
   - Rekor transparency log verification
   - Sigstore trusted root bundle
4. **Extract SBOM**: Parse in-toto attestation predicate (SPDX or CycloneDX)
5. **Normalize data**: Convert to unified package format
6. **Return to policy**: Gatekeeper evaluates Rego policy with SBOM data

### Response Format

The provider returns SBOM data in a normalized format accessible in Rego:

```json
{
  "format": "spdx",
  "packages": [
    {
      "name": "curl",
      "versionInfo": "7.68.0",
      "licenseConcluded": "MIT",
      "purl": "pkg:golang/curl@7.68.0"
    }
  ]
}
```

## Creating Attestations

### Keyless Signing (GitHub Actions)

```bash
# Generate SBOM
syft myimage:tag -o spdx-json > sbom.spdx.json

# Sign with keyless (requires OIDC token)
cosign attest --predicate sbom.spdx.json \
  --type spdx \
  myimage:tag
```

### Keyless Signing (Manual with OIDC)

```bash
# Authenticate with OIDC provider
export COSIGN_EXPERIMENTAL=1

# Generate and attach attestation
syft myimage:tag -o cyclonedx-json > sbom.cdx.json
cosign attest --predicate sbom.cdx.json \
  --type cyclonedx \
  myimage:tag
```

### Using OCI Referrers API

Modern registries (GitHub, Google Artifact Registry, Azure ACR, Harbor 2.8+) support the OCI 1.1 Referrers API. The provider automatically uses it when `USE_REFERRERS_API=true` and falls back to legacy tags if unsupported.

## Troubleshooting

### Common Issues

#### 1. Webhook Timeout Errors

**Symptom**: Pods are created despite violations, or errors like `context deadline exceeded`

**Solution**: Increase Gatekeeper webhook timeout:
```bash
kubectl patch validatingwebhookconfiguration gatekeeper-validating-webhook-configuration \
  --type='json' \
  -p='[{"op": "replace", "path": "/webhooks/0/timeoutSeconds", "value": 15}]'
```

#### 2. "Failed to verify attestation" Errors

**Causes**:
- Image has no attestations
- Identity/issuer mismatch (check `certIdentity` and `certOidcIssuer` in constraint)
- Attestation signed with different identity than expected
- Network issues reaching Rekor transparency log

**Debug**: Check provider logs:
```bash
kubectl logs -n gatekeeper-system deployment/sbom-provider
```

#### 3. "Failed to get secret" Errors

**Cause**: Provider cannot read imagePullSecrets

**Solution**: Verify RBAC permissions:
```bash
kubectl get clusterrole sbom-provider -o yaml
# Should include permissions to get/list secrets
```

#### 4. Private Registry Authentication

**Symptom**: 401 Unauthorized errors

**Solution**: Ensure pod spec includes imagePullSecrets:
```yaml
spec:
  imagePullSecrets:
    - name: my-registry-secret
```

The provider automatically uses secrets from the pod being evaluated (not its own secrets).

## Development

### Building

```bash
# Build binary
go build -o sbom-provider ./cmd/provider

# Build container image
docker build -t sbom-provider:latest .

# Run tests
go test ./...
```

### Local Testing

```bash
# Run provider locally
./sbom-provider --port 8090

# Test with curl
curl -X POST http://localhost:8090/verify \
  -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "externaldata.gatekeeper.sh/v1beta1",
    "kind": "ProviderRequest",
    "request": {
      "keys": ["ghcr.io/myorg/myimage:v1.0.0|[]|user@example.com|https://github.com/login/oauth"]
    }
  }'
```

### Adding Custom Policies

Extend the Rego template in `policy/template.yaml` to add custom validation logic:

```rego
violation[{"msg": msg}] {
  # Your custom logic here
  sbom_data := responses_data[key]
  sbom := json.unmarshal(sbom_data)

  # Example: Check for packages without licenses
  pkg := sbom.packages[_]
  pkg.licenseConcluded == ""

  msg := sprintf("Package %v has no license", [pkg.name])
}
```

## Limitations

- **Keyless only**: Does not support verification with static public keys
- **No caching**: Fetches and verifies attestations on every admission request
- **Single SBOM per image**: Only processes the first valid SBOM attestation found
- **Limited error details**: Error messages may not provide full context for debugging
- **No metrics**: No Prometheus metrics or observability integrations

## Security Considerations

⚠️ **This is a proof-of-concept. Use at your own risk.**

- Attestation verification relies on Sigstore public infrastructure
- No rate limiting - vulnerable to DoS attacks
- TLS is configured but certificate management is manual
- Secrets are accessed in-cluster (requires RBAC review)
- No audit logging of policy decisions
- SBOM data is trusted once attestation is verified

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Kubernetes API Server                     │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ Admission Request
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   Gatekeeper Webhook                         │
│  ┌───────────────────────────────────────────────────────┐  │
│  │             Rego Policy Evaluation                     │  │
│  │  - Check SBOM via external_data()                     │  │
│  │  - Evaluate package/license rules                     │  │
│  └─────────────────────┬─────────────────────────────────┘  │
└────────────────────────┼────────────────────────────────────┘
                         │ External Data Request
                         │ (image|secrets|identity|issuer)
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    SBOM Provider                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  1. Parse request key                                  │  │
│  │  2. Create keychain from pod's imagePullSecrets       │  │
│  │  3. Fetch attestations (OCI 1.1 / legacy)            │  │
│  │  4. Verify with Sigstore (Fulcio + Rekor)            │  │
│  │  5. Extract & normalize SBOM                          │  │
│  │  6. Return unified package data                       │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                         │
                         │ SBOM Data Response
                         ▼
                   Rego Policy Evaluation
                   (Allow/Deny Decision)
```

## License

Apache 2.0

## Contributing

This is a proof-of-concept project. Contributions are welcome for educational purposes, but please note this is not maintained for production use.

For production-ready alternatives, consider:
- [Ratify](https://github.com/deislabs/ratify) - A more mature verification framework
- [Kyverno](https://kyverno.io/) - Policy engine with built-in image verification
- [Sigstore Policy Controller](https://docs.sigstore.dev/policy-controller/overview/) - Admission controller can be used to enforce policy on a Kubernetes cluster based on verifiable supply-chain metadata from cosign