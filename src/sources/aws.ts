/**
 * AWS Route53 domain source
 * 
 * Authentication methods (in order of precedence):
 * 1. Explicit credentials (accessKeyId + secretAccessKey)
 * 2. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
 * 3. AWS profile (--aws-profile or AWS_PROFILE)
 * 4. IAM role (EC2 instance profile, ECS task role, Lambda)
 * 5. AWS SSO / aws configure sso
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { CloudSource } from '../types.js';

const execFileAsync = promisify(execFile);

export interface AWSOptions {
  profile?: string;
  region?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  sessionToken?: string;
  roleArn?: string;
}

export class AWSSource implements CloudSource {
  name = 'AWS Route53';
  private options: AWSOptions;

  constructor(options: AWSOptions = {}) {
    this.options = options;
  }

  async getDomains(): Promise<string[]> {
    return getRoute53Domains(this.options);
  }
}

/**
 * Build environment variables for AWS CLI authentication
 */
function buildAWSEnv(options: AWSOptions): Record<string, string> {
  const env: Record<string, string> = {};

  if (options.accessKeyId) {
    env.AWS_ACCESS_KEY_ID = options.accessKeyId;
  }
  if (options.secretAccessKey) {
    env.AWS_SECRET_ACCESS_KEY = options.secretAccessKey;
  }
  if (options.sessionToken) {
    env.AWS_SESSION_TOKEN = options.sessionToken;
  }

  return env;
}

/**
 * Build CLI arguments array for AWS commands (safe from injection)
 */
function buildAWSArgs(options: AWSOptions): string[] {
  const args: string[] = [];

  if (options.profile) {
    args.push('--profile', options.profile);
  }
  if (options.region) {
    args.push('--region', options.region);
  }

  return args;
}

/**
 * Assume an IAM role and get temporary credentials
 */
export async function assumeRole(
  roleArn: string,
  sessionName = 'mailvet-session',
  options: AWSOptions = {}
): Promise<AWSOptions> {
  const envVars = buildAWSEnv(options);
  const baseArgs = buildAWSArgs(options);

  try {
    const args = [
      'sts', 'assume-role',
      '--role-arn', roleArn,
      '--role-session-name', sessionName,
      ...baseArgs,
      '--output', 'json'
    ];

    const { stdout } = await execFileAsync('aws', args, {
      env: { ...process.env, ...envVars }
    });

    const data = JSON.parse(stdout);
    const creds = data.Credentials;

    return {
      accessKeyId: creds.AccessKeyId,
      secretAccessKey: creds.SecretAccessKey,
      sessionToken: creds.SessionToken,
    };
  } catch (err) {
    throw new Error(`Failed to assume role ${roleArn}: ${(err as Error).message}`);
  }
}

/**
 * Get all domains from AWS Route53 hosted zones
 */
export async function getRoute53Domains(options: AWSOptions = {}): Promise<string[]> {
  let effectiveOptions = options;

  // If roleArn is specified, assume the role first
  if (options.roleArn) {
    try {
      const assumedCreds = await assumeRole(options.roleArn, 'mailvet-session', options);
      effectiveOptions = { ...options, ...assumedCreds };
    } catch (err) {
      throw new Error(`Failed to assume role ${options.roleArn}: ${(err as Error).message}`);
    }
  }

  const envVars = buildAWSEnv(effectiveOptions);
  const baseArgs = buildAWSArgs(effectiveOptions);

  try {
    const args = [
      'route53', 'list-hosted-zones',
      ...baseArgs,
      '--output', 'json'
    ];

    const { stdout } = await execFileAsync('aws', args, {
      env: { ...process.env, ...envVars }
    });

    const data = JSON.parse(stdout);
    const zones: Array<{ Name: string; Id: string; Config?: { PrivateZone?: boolean } }> = 
      data.HostedZones || [];

    // Filter out private zones and extract domain names
    const domains = zones
      .filter(zone => !zone.Config?.PrivateZone)
      .map(zone => zone.Name.replace(/\.$/, '')); // Remove trailing dot

    return domains;
  } catch (err) {
    const error = err as Error & { stderr?: string };
    if (error.stderr?.includes('Unable to locate credentials') || error.message?.includes('credentials')) {
      throw new Error('AWS credentials not configured. Run "aws configure" or set AWS_PROFILE');
    }
    if (error.stderr?.includes('could not be found') || error.message?.includes('ENOENT')) {
      throw new Error('AWS CLI not found. Install with: pip install awscli');
    }
    throw new Error(`Failed to list Route53 zones: ${error.message}`);
  }
}

/**
 * Get domains from a specific hosted zone
 */
export async function getRoute53ZoneDomains(
  zoneId: string, 
  options: AWSOptions = {}
): Promise<string[]> {
  const envVars = buildAWSEnv(options);
  const baseArgs = buildAWSArgs(options);

  try {
    const args = [
      'route53', 'list-resource-record-sets',
      '--hosted-zone-id', zoneId,
      ...baseArgs,
      '--output', 'json'
    ];

    const { stdout } = await execFileAsync('aws', args, {
      env: { ...process.env, ...envVars }
    });

    const data = JSON.parse(stdout);
    const records: Array<{ Name: string; Type: string }> = data.ResourceRecordSets || [];

    // Get unique domain names (excluding subdomains for now)
    const domains = new Set<string>();
    for (const record of records) {
      if (record.Type === 'SOA' || record.Type === 'NS') {
        const domain = record.Name.replace(/\.$/, '');
        domains.add(domain);
      }
    }

    return Array.from(domains);
  } catch (err) {
    throw new Error(`Failed to list zone records: ${(err as Error).message}`);
  }
}
