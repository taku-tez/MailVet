# MailVet 📧

Email security configuration scanner - validates SPF, DKIM, DMARC, and MX records.

## Features

- **SPF Validation**: Check sender policy framework configuration
- **DKIM Detection**: Scan common DKIM selectors and validate key strength
- **DMARC Analysis**: Verify policy, reporting, and subdomain settings
- **MX Inspection**: Identify mail servers and email providers
- **Grading System**: A-F grades based on security configuration
- **Recommendations**: Actionable suggestions to improve email security

## Installation

```bash
npm install -g mailvet
```

## Usage

### Single Domain Check

```bash
# Basic check
mailvet check example.com

# JSON output
mailvet check example.com --json

# Verbose mode
mailvet check example.com --verbose

# Custom DKIM selectors
mailvet check example.com --selectors google,selector1,custom
```

### Bulk Scanning

```bash
# From file
mailvet scan -f domains.txt

# From stdin
cat domains.txt | mailvet scan --stdin

# Output to file
mailvet scan -f domains.txt -o results.json --json

# Control concurrency
mailvet scan -f domains.txt -c 10
```

### Cloud Provider Integration

```bash
# AWS Route53
mailvet scan --aws
mailvet scan --aws --aws-profile production
mailvet scan --aws --aws-region us-east-1

# Google Cloud DNS
mailvet scan --gcp
mailvet scan --gcp --gcp-project my-project
mailvet scan --gcp --gcp-key-file /path/to/service-account.json
mailvet scan --gcp --gcp-impersonate sa@project.iam.gserviceaccount.com

# Azure DNS
mailvet scan --azure
mailvet scan --azure --azure-subscription xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
mailvet scan --azure --azure-client-id xxx --azure-client-secret xxx --azure-tenant-id xxx

# Cloudflare
mailvet scan --cloudflare                              # uses CLOUDFLARE_API_TOKEN
mailvet scan --cloudflare --cloudflare-token xxx       # explicit token
mailvet scan --cloudflare --cloudflare-email x@y --cloudflare-key xxx  # Global API Key

# Combine multiple sources
mailvet scan --aws --gcp --cloudflare -o results.json --json
```

### Authentication Methods

| Provider | Methods |
|----------|---------|
| **AWS** | Profile (`--aws-profile`), Env vars (`AWS_ACCESS_KEY_ID`), IAM role, SSO |
| **GCP** | Key file (`--gcp-key-file`), `gcloud auth`, Impersonation, Compute Engine SA |
| **Azure** | Service principal (`--azure-client-id/secret/tenant`), `az login`, Managed Identity |
| **Cloudflare** | API Token (`--cloudflare-token` or `CLOUDFLARE_API_TOKEN`), Global API Key |

### List Domains from Providers

```bash
# List all domains without scanning
mailvet sources --aws --gcp --cloudflare
mailvet sources --aws --json
```

## Output Example

```
📧 example.com - Grade: A (100/100)

SPF      ✅ Found
         Record: v=spf1 include:_spf.google.com -all
         ✅ Mechanism: -all
         ✅ DNS lookups: 4/10

DKIM     ✅ Found
         ✅ google._domainkey (2048-bit)
         ✅ selector1._domainkey (2048-bit)

DMARC    ✅ Found
         Record: v=DMARC1; p=reject; rua=mailto:dmarc@example.com
         ✅ Policy: p=reject
         ✅ Reporting: enabled

MX       ✅ Found
         ✅ aspmx.l.google.com (pri: 1)
         ℹ️ Email provider detected: Google Workspace

BIMI     ✅ Found
         ✅ Logo: https://example.com/logo.svg
         ✅ VMC: configured

MTA-STS  ✅ Found
         ✅ Mode: enforce
         ℹ️ Max age: 7 days

TLS-RPT  ✅ Found
         ✅ Reporting: 1 endpoint(s)

ARC      ✅ Ready
         ✅ Can sign ARC headers

Recommendations:
  (none - perfect configuration!)
```

## Grading Criteria

| Grade | Score | Requirements |
|-------|-------|--------------|
| **A** | 90-100 | SPF (-all) + DKIM (2048-bit) + DMARC (reject) |
| **B** | 75-89 | SPF + DKIM + DMARC (quarantine) |
| **C** | 50-74 | SPF + DMARC (any policy) |
| **D** | 25-49 | SPF only |
| **F** | 0-24 | Missing critical records |

## Checks Performed

### Core Checks

#### SPF (Sender Policy Framework)
- Record existence
- Mechanism strength (-all > ~all > ?all > +all)
- DNS lookup count (max 10)
- Deprecated mechanisms (ptr)
- Multiple record detection

#### DKIM (DomainKeys Identified Mail)
- Common selector detection (google, selector1, default, etc.)
- Key length validation (≥2048-bit recommended)
- Multiple selector support

#### DMARC (Domain-based Message Authentication)
- Record existence
- Policy strength (reject > quarantine > none)
- Subdomain policy (sp=)
- Reporting configuration (rua/ruf)
- Percentage coverage (pct=)

#### MX (Mail Exchange)
- Record existence
- Priority configuration
- Redundancy check
- Email provider identification

### Advanced Checks

#### BIMI (Brand Indicators for Message Identification)
- Logo URL validation (HTTPS required)
- SVG Tiny PS format recommendation
- VMC (Verified Mark Certificate) detection
- Prerequisite check (requires DMARC p=quarantine or reject)

#### MTA-STS (Mail Transfer Agent Strict Transport Security)
- DNS record validation (_mta-sts.domain)
- Policy file fetch (https://mta-sts.domain/.well-known/mta-sts.txt)
- Mode validation (enforce > testing > none)
- MX host matching
- Max age recommendations

#### TLS-RPT (SMTP TLS Reporting)
- DNS record validation (_smtp._tls.domain)
- Reporting endpoint validation (mailto: or https:)
- Multiple endpoint support

#### ARC (Authenticated Received Chain) Readiness
- Prerequisites check (DKIM required)
- Key strength validation for ARC signing
- DMARC dependency check
- Note: ARC is header-based, this checks signing readiness

## Programmatic Usage

```typescript
import { analyzeDomain, analyzeMultiple } from 'mailvet';

// Single domain
const result = await analyzeDomain('example.com');
console.log(result.grade); // 'A', 'B', 'C', 'D', or 'F'
console.log(result.score); // 0-100
console.log(result.recommendations);

// Multiple domains
const results = await analyzeMultiple([
  'example.com',
  'test.org'
], { concurrency: 5 });
```

## Exit Codes

- `0` - All domains have grade D or better
- `1` - At least one domain has grade F

## Related Projects

Part of the **xxVet** security tool series:
- [AgentVet](https://github.com/taku-tez/agentvet) - AI Agent Security Scanner
- [PermitVet](https://github.com/taku-tez/PermitVet) - Cloud IAM Scanner
- [SubVet](https://github.com/taku-tez/SubVet) - Subdomain Takeover Scanner
- [ReachVet](https://github.com/taku-tez/ReachVet) - Supply Chain Reachability

## License

MIT
