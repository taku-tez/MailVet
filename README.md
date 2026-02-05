# DNSVet 🔐

DNS and email security scanner - validates SPF, DKIM, DMARC, DNSSEC, MTA-STS, TLS-RPT, BIMI, and more.

## Features

### Email Security
- **SPF Validation**: RFC 7208 compliant, recursive lookup counting
- **DKIM Detection**: Scan common selectors, key strength validation (RSA/ed25519)
- **DMARC Analysis**: Policy, reporting, subdomain settings
- **BIMI Check**: Logo URL, VMC certificate validation

### DNS Security
- **DNSSEC Validation**: DS/DNSKEY records, algorithm strength, chain of trust
- **MX Inspection**: Mail servers, provider detection, Null MX support

### Transport Security
- **MTA-STS**: Policy mode (enforce/testing), MX consistency
- **TLS-RPT**: Reporting endpoints, mailto/https validation
- **ARC Readiness**: Signing capability assessment

### Multi-Cloud Support
- AWS Route53
- Google Cloud DNS (organization-wide scanning)
- Azure DNS
- Cloudflare

## Installation

```bash
npm install -g dnsvet
```

## Usage

### Single Domain Check

```bash
# Basic check
dnsvet check example.com

# JSON output
dnsvet check example.com --json

# Verbose mode with all issues
dnsvet check example.com --verbose

# Custom DKIM selectors
dnsvet check example.com --selectors google,selector1,custom

# Verify TLS-RPT endpoints
dnsvet check example.com --verify-tlsrpt-endpoints
```

### Bulk Scanning

```bash
# From file
dnsvet scan --file domains.txt

# From stdin
cat domains.txt | dnsvet scan --stdin

# JSON output
dnsvet scan --file domains.txt --json -o results.json
```

### Cloud Provider Scanning

```bash
# AWS Route53
dnsvet scan --aws
dnsvet scan --aws --aws-profile production

# Google Cloud DNS
dnsvet scan --gcp --gcp-project my-project
dnsvet scan --gcp --gcp-org 123456789  # Organization-wide

# Azure DNS
dnsvet scan --azure
dnsvet scan --azure --azure-subscription xxx-xxx

# Cloudflare
dnsvet scan --cloudflare --cloudflare-token $CF_TOKEN
```

### List Cloud Domains (sources)

```bash
dnsvet sources --aws
dnsvet sources --gcp --gcp-org 123456789
dnsvet sources --cloudflare --json
```

### Selective Checks

```bash
# Skip specific checks (faster scans)
dnsvet check example.com --skip bimi,arc,dnssec

# Run only specific checks
dnsvet check example.com --only spf,dkim,dmarc

# Custom DNS resolver
dnsvet check example.com --resolver 8.8.8.8
```

## Output Example

```
📧 example.com - Grade: A (95/100)

SPF      ✅ Found
   Record: v=spf1 include:_spf.google.com -all
   ✅ Mechanism: -all
   ✅ DNS lookups: 3/10

DKIM     ✅ Found
   ✅ google._domainkey (2048-bit rsa)
   ✅ selector1._domainkey (2048-bit rsa)

DMARC    ✅ Found
   ✅ Policy: p=reject
   ✅ Reporting: enabled

MX       ✅ Found
   ✅ aspmx.l.google.com (pri: 1)
   ℹ️ Email provider detected: Google Workspace

DNSSEC   ✅ Found
   ✅ Chain of trust: Valid
   ℹ️ DS: Algorithm 13 (ECDSAP256SHA256)
   ℹ️ DNSKEY: 1 KSK + 1 ZSK

MTA-STS  ✅ Found
   ✅ Mode: enforce

TLS-RPT  ✅ Found
   ✅ Reporting: 1 endpoint(s)

Recommendations:
  1. ✨ [オプション] BIMIを設定すると、対応メールクライアントでロゴが表示されます
```

## Grading System

| Grade | Score | Requirements |
|-------|-------|--------------|
| A | 90-100 | SPF (-all) + DKIM (2048-bit) + DMARC (reject) |
| B | 75-89 | SPF + DKIM + DMARC (quarantine) |
| C | 50-74 | SPF + DMARC (any policy) |
| D | 25-49 | SPF only |
| F | 0-24 | Major issues or missing records |

### Bonus Points (up to +15)
- DNSSEC enabled: +5
- BIMI with VMC: +5
- MTA-STS enforce: +4
- TLS-RPT: +3
- ARC ready: +3

## Exit Codes

- `0`: Grade A-D (passing)
- `1`: Grade F (failing)

## Environment Variables

```bash
# AWS
AWS_PROFILE=default
AWS_ACCESS_KEY_ID=xxx
AWS_SECRET_ACCESS_KEY=xxx

# GCP
GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json

# Azure
AZURE_CLIENT_ID=xxx
AZURE_CLIENT_SECRET=xxx
AZURE_TENANT_ID=xxx

# Cloudflare
CLOUDFLARE_API_TOKEN=xxx
# or
CLOUDFLARE_EMAIL=xxx
CLOUDFLARE_API_KEY=xxx
```

## Prerequisites

- **Node.js** 18+ (required)
- **dig** (bind-utils/dnsutils) - Required for DNSSEC checks. Without it, DNSSEC validation will report a warning but other checks work normally.
- **aws** CLI - Required for `--aws` source
- **gcloud** CLI - Required for `--gcp` source
- **az** CLI - Required for `--azure` source

## License

MIT

## Related Tools

Part of the **xxVet** security tool series:
- [AgentVet](https://github.com/taku-tez/agentvet) - AI agent security scanner
- [PermitVet](https://github.com/taku-tez/PermitVet) - Cloud IAM analyzer
- [SubVet](https://github.com/taku-tez/SubVet) - Subdomain takeover scanner
- [ExtVet](https://github.com/taku-tez/ExtVet) - Browser extension scanner
