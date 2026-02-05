#!/usr/bin/env node

/**
 * DNSVet CLI - Email security configuration scanner
 */

import { Command } from 'commander';
import fs from 'node:fs/promises';
import readline from 'node:readline';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeDomain, analyzeMultiple } from './core/index.js';
import { formatResult, formatSummary } from './output.js';
import { getRoute53Domains } from './sources/aws.js';
import { getCloudDNSDomains, getCloudDNSDomainsOrg } from './sources/gcp.js';
import { getAzureDNSDomains } from './sources/azure.js';
import { getCloudflareDomains } from './sources/cloudflare.js';
import { normalizeDomain } from './types.js';
import { isValidDomain } from './utils/domain.js';
import { DEFAULT_CHECK_TIMEOUT_MS, DEFAULT_CONCURRENCY } from './constants.js';
import type { ScanOptions } from './types.js';

/**
 * Parse integer with fallback to default value
 */
function parseIntOrDefault(value: string, defaultValue: number): number {
  const parsed = parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : defaultValue;
}

/**
 * Validate domain and exit with error if invalid
 */
function validateDomainOrExit(domain: string): string {
  const normalized = normalizeDomain(domain);
  if (!isValidDomain(normalized)) {
    console.error(`Error: Invalid domain format: "${domain}"`);
    console.error('Domain must be a valid hostname (e.g., example.com)');
    process.exit(1);
  }
  return normalized;
}

const ALL_CHECKS = ['spf', 'dkim', 'dmarc', 'mx', 'bimi', 'mta-sts', 'tls-rpt', 'arc', 'dnssec'] as const;
const normalizeCheckName = (name: string): string => name.replace(/-/g, '').toLowerCase();
const keyMap: Record<string, keyof NonNullable<ScanOptions['checks']>> = {
  'spf': 'spf',
  'dkim': 'dkim',
  'dmarc': 'dmarc',
  'mx': 'mx',
  'bimi': 'bimi',
  'mtasts': 'mtaSts',
  'tlsrpt': 'tlsRpt',
  'arc': 'arc',
  'dnssec': 'dnssec',
};
const normalizedChecks = new Set(ALL_CHECKS.map(check => normalizeCheckName(check)));

function parseCheckList(value?: string): string[] {
  return value ? value.split(',').map(s => s.trim()).filter(Boolean) : [];
}

function validateCheckNamesOrExit(names: string[], label: string): void {
  const unknown = names.filter(name => !normalizedChecks.has(normalizeCheckName(name)));
  if (unknown.length > 0) {
    console.error(`Error: Unknown ${label} check(s): ${unknown.join(', ')}`);
    console.error(`Available checks: ${ALL_CHECKS.join(', ')}`);
    process.exit(1);
  }
}

/**
 * Parse --skip/--only CLI options into CheckOptions
 */
function parseCheckOptions(skip?: string, only?: string): ScanOptions['checks'] {
  const normalize = (name: string): string => normalizeCheckName(name);

  if (only) {
    // Only run specified checks
    const onlyList = parseCheckList(only);
    validateCheckNamesOrExit(onlyList, 'only');
    const enabledSet = new Set(onlyList.map(normalize));
    const checks: Record<string, boolean> = {};
    for (const c of ALL_CHECKS) {
      const key = keyMap[normalize(c)];
      if (key) checks[key] = enabledSet.has(normalize(c));
    }
    return checks;
  }

  if (skip) {
    // Skip specified checks
    const skipList = parseCheckList(skip);
    validateCheckNamesOrExit(skipList, 'skip');
    const skipSet = new Set(skipList.map(normalize));
    const checks: Record<string, boolean> = {};
    for (const c of ALL_CHECKS) {
      const key = keyMap[normalize(c)];
      if (key && skipSet.has(normalize(c))) checks[key] = false;
    }
    return checks;
  }

  return undefined;
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(await fs.readFile(path.join(__dirname, '..', 'package.json'), 'utf-8'));

const program = new Command();

program
  .name('dnsvet')
  .description('DNS and email security scanner - SPF/DKIM/DMARC/DNSSEC/MTA-STS')
  .version(pkg.version);

program
  .command('check <domain>')
  .description('Check email security configuration for a single domain')
  .option('--json', 'Output as JSON')
  .option('-v, --verbose', 'Show detailed information')
  .option('-t, --timeout <ms>', 'Timeout per check in milliseconds', '10000')
  .option('--selectors <selectors>', 'Custom DKIM selectors (comma-separated)')
  .option('--verify-tlsrpt-endpoints', 'Verify TLS-RPT endpoint reachability')
  .option('--resolver <ip>', 'Custom DNS resolver (e.g., 8.8.8.8)')
  .option('--skip <checks>', 'Skip specific checks (comma-separated: spf,dkim,dmarc,mx,bimi,mta-sts,tls-rpt,arc,dnssec)')
  .option('--only <checks>', 'Run only specific checks (comma-separated: spf,dkim,dmarc,mx,bimi,mta-sts,tls-rpt,arc,dnssec)')
  .action(async (domain: string, options) => {
    // Normalize and validate domain
    const normalizedDomain = validateDomainOrExit(domain);

    const scanOptions: ScanOptions = {
      dkimSelectors: options.selectors?.split(',').map((s: string) => s.trim()).filter(Boolean),
      verbose: options.verbose,
      timeout: parseIntOrDefault(options.timeout, DEFAULT_CHECK_TIMEOUT_MS),
      verifyTlsRptEndpoints: options.verifyTlsrptEndpoints,
      resolver: options.resolver,
      checks: parseCheckOptions(options.skip, options.only),
    };

    const result = await analyzeDomain(normalizedDomain, scanOptions);

    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(formatResult(result, options.verbose));
    }

    process.exit(result.grade === 'F' ? 1 : 0);
  });

program
  .command('scan')
  .description('Scan multiple domains from file, stdin, or cloud providers')
  .option('-f, --file <path>', 'Read domains from file')
  .option('--stdin', 'Read domains from stdin')
  .option('--aws', 'Scan all AWS Route53 hosted zones')
  .option('--aws-profile <profile>', 'AWS profile to use')
  .option('--aws-region <region>', 'AWS region')
  .option('--aws-role-arn <arn>', 'AWS IAM role to assume')
  .option('--gcp', 'Scan all Google Cloud DNS zones')
  .option('--gcp-org', 'Scan all projects in GCP organization')
  .option('--gcp-org-id <id>', 'GCP organization ID (optional with --gcp-org)')
  .option('--gcp-project <project>', 'GCP project ID (single project)')
  .option('--gcp-key-file <path>', 'GCP service account key file')
  .option('--gcp-impersonate <account>', 'GCP service account to impersonate')
  .option('--azure', 'Scan all Azure DNS zones')
  .option('--azure-subscription <id>', 'Azure subscription ID')
  .option('--azure-client-id <id>', 'Azure service principal client ID')
  .option('--azure-client-secret <secret>', 'Azure service principal client secret')
  .option('--azure-tenant-id <id>', 'Azure tenant ID')
  .option('--cloudflare', 'Scan all Cloudflare zones')
  .option('--cloudflare-token <token>', 'Cloudflare API token')
  .option('--cloudflare-email <email>', 'Cloudflare account email (with --cloudflare-key)')
  .option('--cloudflare-key <key>', 'Cloudflare Global API key')
  .option('-o, --output <path>', 'Write results to file')
  .option('--json', 'Output as JSON')
  .option('-c, --concurrency <n>', 'Concurrent checks', '5')
  .option('-t, --timeout <ms>', 'Timeout per check in milliseconds', '10000')
  .option('--selectors <selectors>', 'Custom DKIM selectors (comma-separated)')
  .option('--verify-tlsrpt-endpoints', 'Verify TLS-RPT endpoint reachability')
  .option('--skip <checks>', 'Skip specific checks (comma-separated: spf,dkim,dmarc,mx,bimi,mta-sts,tls-rpt,arc,dnssec)')
  .option('--only <checks>', 'Run only specific checks (comma-separated: spf,dkim,dmarc,mx,bimi,mta-sts,tls-rpt,arc,dnssec)')
  .action(async (options) => {
    let domains: string[] = [];
    const sources: string[] = [];

    // Collect domains from all specified sources
    if (options.file) {
      const content = await fs.readFile(options.file, 'utf-8');
      const fileDomains = content
        .split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'));
      domains.push(...fileDomains);
      sources.push(`file (${fileDomains.length})`);
    }

    if (options.stdin) {
      const stdinDomains = await readStdin();
      domains.push(...stdinDomains);
      sources.push(`stdin (${stdinDomains.length})`);
    }

    if (options.aws) {
      console.error('Fetching domains from AWS Route53...');
      try {
        const awsDomains = await getRoute53Domains({ 
          profile: options.awsProfile,
          region: options.awsRegion,
          roleArn: options.awsRoleArn,
        });
        domains.push(...awsDomains);
        sources.push(`AWS Route53 (${awsDomains.length})`);
      } catch (err) {
        console.error(`AWS Error: ${(err as Error).message}`);
      }
    }

    if (options.gcp || options.gcpOrg) {
      const gcpOpts = {
        project: options.gcpProject,
        keyFile: options.gcpKeyFile,
        impersonateServiceAccount: options.gcpImpersonate,
      };

      if (options.gcpOrg || !options.gcpProject) {
        // Org-wide scan
        console.error('Fetching domains from GCP organization (scanning all projects)...');
        try {
          const result = await getCloudDNSDomainsOrg({
            ...gcpOpts,
            orgId: options.gcpOrgId,
            verbose: true,
          });
          domains.push(...result.domains);
          sources.push(`GCP Cloud DNS (${result.domains.length} domains from ${result.projectsWithZones.length} projects)`);
        } catch (err) {
          console.error(`GCP Error: ${(err as Error).message}`);
        }
      } else {
        // Single project scan
        console.error('Fetching domains from Google Cloud DNS...');
        try {
          const gcpDomains = await getCloudDNSDomains(gcpOpts);
          domains.push(...gcpDomains);
          sources.push(`GCP Cloud DNS (${gcpDomains.length})`);
        } catch (err) {
          console.error(`GCP Error: ${(err as Error).message}`);
        }
      }
    }

    if (options.azure) {
      console.error('Fetching domains from Azure DNS...');
      try {
        const azureDomains = await getAzureDNSDomains({ 
          subscription: options.azureSubscription,
          clientId: options.azureClientId,
          clientSecret: options.azureClientSecret,
          tenantId: options.azureTenantId,
        });
        domains.push(...azureDomains);
        sources.push(`Azure DNS (${azureDomains.length})`);
      } catch (err) {
        console.error(`Azure Error: ${(err as Error).message}`);
      }
    }

    if (options.cloudflare) {
      console.error('Fetching domains from Cloudflare...');
      try {
        const cfDomains = await getCloudflareDomains({
          apiToken: options.cloudflareToken,
          email: options.cloudflareEmail,
          apiKey: options.cloudflareKey,
        });
        domains.push(...cfDomains);
        sources.push(`Cloudflare (${cfDomains.length})`);
      } catch (err) {
        console.error(`Cloudflare Error: ${(err as Error).message}`);
      }
    }

    // Normalize and deduplicate domains
    const normalizedDomains = [...new Set(domains.map(d => normalizeDomain(d)).filter(d => d.length > 0))];
    
    // Validate domains and filter out invalid ones
    const validDomains: string[] = [];
    const invalidDomains: string[] = [];
    for (const domain of normalizedDomains) {
      if (isValidDomain(domain)) {
        validDomains.push(domain);
      } else {
        invalidDomains.push(domain);
      }
    }
    
    if (invalidDomains.length > 0) {
      console.error(`Warning: Skipping ${invalidDomains.length} invalid domain(s):`);
      for (const invalid of invalidDomains.slice(0, 10)) {
        console.error(`  - ${invalid}`);
      }
      if (invalidDomains.length > 10) {
        console.error(`  ... and ${invalidDomains.length - 10} more`);
      }
    }
    
    domains = validDomains;

    if (domains.length === 0) {
      console.error('Error: No valid domains to scan');
      console.error('Specify at least one source: --file, --stdin, --aws, --gcp, --azure, or --cloudflare');
      process.exit(1);
    }

    if (sources.length > 0) {
      console.error(`Sources: ${sources.join(', ')}`);
    }
    console.error(`Scanning ${domains.length} valid domains...`);

    const scanOptions: ScanOptions = {
      concurrency: parseIntOrDefault(options.concurrency, DEFAULT_CONCURRENCY),
      dkimSelectors: options.selectors?.split(',').map((s: string) => s.trim()).filter(Boolean),
      timeout: parseIntOrDefault(options.timeout, DEFAULT_CHECK_TIMEOUT_MS),
      verifyTlsRptEndpoints: options.verifyTlsrptEndpoints,
      checks: parseCheckOptions(options.skip, options.only),
    };

    const results = await analyzeMultiple(domains, scanOptions);

    if (options.json || options.output) {
      const output = JSON.stringify(results, null, 2);
      if (options.output) {
        await fs.writeFile(options.output, output);
        console.error(`Results written to ${options.output}`);
      } else {
        console.log(output);
      }
    } else {
      // Print summary
      console.log(formatSummary(results));
    }

    const hasFailures = results.some(r => r.grade === 'F');
    process.exit(hasFailures ? 1 : 0);
  });

// Sources subcommand to list domains from cloud providers
program
  .command('sources')
  .description('List domains from cloud DNS providers')
  .option('--aws', 'List AWS Route53 hosted zones')
  .option('--aws-profile <profile>', 'AWS profile to use')
  .option('--aws-region <region>', 'AWS region')
  .option('--aws-role-arn <arn>', 'AWS IAM role to assume')
  .option('--gcp', 'List Google Cloud DNS zones')
  .option('--gcp-org', 'List zones from all GCP projects')
  .option('--gcp-org-id <id>', 'GCP organization ID')
  .option('--gcp-project <project>', 'GCP project ID')
  .option('--gcp-key-file <path>', 'GCP service account key file')
  .option('--gcp-impersonate <account>', 'GCP service account to impersonate')
  .option('--azure', 'List Azure DNS zones')
  .option('--azure-subscription <id>', 'Azure subscription ID')
  .option('--azure-client-id <id>', 'Azure service principal client ID')
  .option('--azure-client-secret <secret>', 'Azure service principal secret')
  .option('--azure-tenant-id <id>', 'Azure tenant ID')
  .option('--cloudflare', 'List Cloudflare zones')
  .option('--cloudflare-token <token>', 'Cloudflare API token')
  .option('--cloudflare-email <email>', 'Cloudflare account email')
  .option('--cloudflare-key <key>', 'Cloudflare Global API key')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    const allDomains: Record<string, string[]> = {};

    if (options.aws) {
      try {
        allDomains['aws'] = await getRoute53Domains({ 
          profile: options.awsProfile,
          region: options.awsRegion,
          roleArn: options.awsRoleArn,
        });
      } catch (err) {
        console.error(`AWS: ${(err as Error).message}`);
        allDomains['aws'] = [];
      }
    }

    if (options.gcp || options.gcpOrg) {
      try {
        const gcpOpts = {
          project: options.gcpProject,
          keyFile: options.gcpKeyFile,
          impersonateServiceAccount: options.gcpImpersonate,
        };

        if (options.gcpOrg || !options.gcpProject) {
          console.error('Scanning all GCP projects...');
          const result = await getCloudDNSDomainsOrg({
            ...gcpOpts,
            orgId: options.gcpOrgId,
            verbose: true,
          });
          allDomains['gcp'] = result.domains;
          console.error(`Found ${result.domains.length} domains in ${result.projectsWithZones.length} projects`);
        } else {
          allDomains['gcp'] = await getCloudDNSDomains(gcpOpts);
        }
      } catch (err) {
        console.error(`GCP: ${(err as Error).message}`);
        allDomains['gcp'] = [];
      }
    }

    if (options.azure) {
      try {
        allDomains['azure'] = await getAzureDNSDomains({ 
          subscription: options.azureSubscription,
          clientId: options.azureClientId,
          clientSecret: options.azureClientSecret,
          tenantId: options.azureTenantId,
        });
      } catch (err) {
        console.error(`Azure: ${(err as Error).message}`);
        allDomains['azure'] = [];
      }
    }

    if (options.cloudflare) {
      try {
        allDomains['cloudflare'] = await getCloudflareDomains({
          apiToken: options.cloudflareToken,
          email: options.cloudflareEmail,
          apiKey: options.cloudflareKey,
        });
      } catch (err) {
        console.error(`Cloudflare: ${(err as Error).message}`);
        allDomains['cloudflare'] = [];
      }
    }

    if (Object.keys(allDomains).length === 0) {
      console.error('Specify at least one provider: --aws, --gcp, --azure, or --cloudflare');
      process.exit(1);
    }

    if (options.json) {
      console.log(JSON.stringify(allDomains, null, 2));
    } else {
      for (const [provider, domains] of Object.entries(allDomains)) {
        console.log(`\n${provider.toUpperCase()} (${domains.length} domains):`);
        for (const domain of domains) {
          console.log(`  ${domain}`);
        }
      }
    }
  });

// Default action: check single domain
program
  .argument('[domain]')
  .option('--json', 'Output as JSON')
  .option('-v, --verbose', 'Show detailed information')
  .option('-t, --timeout <ms>', 'Timeout per check in milliseconds', '10000')
  .option('--selectors <selectors>', 'Custom DKIM selectors (comma-separated)')
  .option('--verify-tlsrpt-endpoints', 'Verify TLS-RPT endpoint reachability')
  .option('--skip <checks>', 'Skip specific checks (comma-separated: spf,dkim,dmarc,mx,bimi,mta-sts,tls-rpt,arc,dnssec)')
  .option('--only <checks>', 'Run only specific checks (comma-separated: spf,dkim,dmarc,mx,bimi,mta-sts,tls-rpt,arc,dnssec)')
  .action(async (domain: string | undefined, options) => {
    if (!domain) {
      program.help();
      return;
    }

    // Normalize and validate domain (same as check command)
    const normalizedDomain = validateDomainOrExit(domain);

    const scanOptions: ScanOptions = {
      dkimSelectors: options.selectors?.split(',').map((s: string) => s.trim()).filter(Boolean),
      verbose: options.verbose,
      timeout: parseIntOrDefault(options.timeout, DEFAULT_CHECK_TIMEOUT_MS),
      verifyTlsRptEndpoints: options.verifyTlsrptEndpoints,
      checks: parseCheckOptions(options.skip, options.only),
    };

    const result = await analyzeDomain(normalizedDomain, scanOptions);

    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(formatResult(result, options.verbose));
    }

    process.exit(result.grade === 'F' ? 1 : 0);
  });

async function readStdin(): Promise<string[]> {
  const rl = readline.createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
  });

  const domains: string[] = [];
  for await (const line of rl) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#')) {
      domains.push(trimmed);
    }
  }
  return domains;
}

program.parse();
