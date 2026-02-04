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

import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import type { CloudSource } from '../types.js';

const execAsync = promisify(exec);

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

  // Explicit credentials take precedence
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
 * Build CLI arguments for AWS commands
 */
function buildAWSArgs(options: AWSOptions): string {
  const args: string[] = [];

  if (options.profile) {
    args.push(`--profile ${options.profile}`);
  }
  if (options.region) {
    args.push(`--region ${options.region}`);
  }

  return args.join(' ');
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
  const args = buildAWSArgs(options);

  try {
    const { stdout } = await execAsync(
      `aws sts assume-role --role-arn ${roleArn} --role-session-name ${sessionName} ${args} --output json`,
      { env: { ...process.env, ...envVars } }
    );

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
  const envVars = buildAWSEnv(options);
  const args = buildAWSArgs(options);

  try {
    // List all hosted zones
    const { stdout } = await execAsync(
      `aws route53 list-hosted-zones ${args} --output json`,
      { env: { ...process.env, ...envVars } }
    );

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
    if (error.stderr?.includes('Unable to locate credentials')) {
      throw new Error('AWS credentials not configured. Run "aws configure" or set AWS_PROFILE');
    }
    if (error.stderr?.includes('could not be found')) {
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
  const args = buildAWSArgs(options);

  try {
    const { stdout } = await execAsync(
      `aws route53 list-resource-record-sets --hosted-zone-id ${zoneId} ${args} --output json`,
      { env: { ...process.env, ...envVars } }
    );

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
