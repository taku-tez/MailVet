/**
 * Google Cloud DNS domain source
 * 
 * Authentication methods (in order of precedence):
 * 1. Service account key file (--gcp-key-file or GOOGLE_APPLICATION_CREDENTIALS)
 * 2. gcloud auth (gcloud auth login / gcloud auth application-default login)
 * 3. Compute Engine default service account
 * 4. Workload Identity (GKE)
 */

import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import type { CloudSource } from '../types.js';

const execAsync = promisify(exec);

export interface GCPOptions {
  project?: string;
  account?: string;
  keyFile?: string;
  impersonateServiceAccount?: string;
}

export class GCPSource implements CloudSource {
  name = 'Google Cloud DNS';
  private options: GCPOptions;

  constructor(options: GCPOptions = {}) {
    this.options = options;
  }

  async getDomains(): Promise<string[]> {
    return getCloudDNSDomains(this.options);
  }
}

/**
 * Build CLI arguments and environment for GCP commands
 */
function buildGCPConfig(options: GCPOptions): { args: string; env: Record<string, string> } {
  const args: string[] = [];
  const env: Record<string, string> = {};

  if (options.project) {
    args.push(`--project=${options.project}`);
  }
  if (options.account) {
    args.push(`--account=${options.account}`);
  }
  if (options.impersonateServiceAccount) {
    args.push(`--impersonate-service-account=${options.impersonateServiceAccount}`);
  }
  if (options.keyFile) {
    env.GOOGLE_APPLICATION_CREDENTIALS = options.keyFile;
  }

  return { args: args.join(' '), env };
}

/**
 * Get all domains from Google Cloud DNS managed zones
 */
export async function getCloudDNSDomains(options: GCPOptions = {}): Promise<string[]> {
  const { args, env } = buildGCPConfig(options);

  try {
    // List all managed zones
    const { stdout } = await execAsync(
      `gcloud dns managed-zones list ${args} --format=json`,
      { env: { ...process.env, ...env } }
    );

    const zones: Array<{ 
      name: string; 
      dnsName: string; 
      visibility?: string;
    }> = JSON.parse(stdout) || [];

    // Filter out private zones and extract domain names
    const domains = zones
      .filter(zone => zone.visibility !== 'private')
      .map(zone => zone.dnsName.replace(/\.$/, '')); // Remove trailing dot

    return domains;
  } catch (err) {
    const error = err as Error & { stderr?: string };
    if (error.stderr?.includes('not logged in') || error.stderr?.includes('credentials')) {
      throw new Error('GCP credentials not configured. Run "gcloud auth login"');
    }
    if (error.stderr?.includes('not found') || error.stderr?.includes('command not found')) {
      throw new Error('gcloud CLI not found. Install from: https://cloud.google.com/sdk/install');
    }
    if (error.stderr?.includes('project')) {
      throw new Error('GCP project not set. Use --gcp-project or run "gcloud config set project PROJECT_ID"');
    }
    throw new Error(`Failed to list Cloud DNS zones: ${error.message}`);
  }
}

/**
 * Get all projects with Cloud DNS enabled
 */
export async function listGCPProjects(): Promise<string[]> {
  try {
    const { stdout } = await execAsync(
      `gcloud projects list --format="value(projectId)"`
    );

    return stdout.trim().split('\n').filter(Boolean);
  } catch {
    return [];
  }
}

/**
 * Get domains from multiple GCP projects
 */
export async function getCloudDNSDomainsMultiProject(
  projects?: string[]
): Promise<string[]> {
  const projectList = projects || await listGCPProjects();
  const allDomains: string[] = [];

  for (const project of projectList) {
    try {
      const domains = await getCloudDNSDomains({ project });
      allDomains.push(...domains);
    } catch {
      // Skip projects without Cloud DNS or access
    }
  }

  return [...new Set(allDomains)]; // Deduplicate
}
