/**
 * Azure DNS domain source
 * 
 * Authentication methods:
 * 1. Service principal (--azure-client-id, --azure-client-secret, --azure-tenant-id)
 * 2. Environment variables (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
 * 3. az login (interactive or device code)
 * 4. Managed Identity (Azure VM, AKS, App Service)
 * 5. Azure CLI cached credentials
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { CloudSource } from '../types.js';

const execFileAsync = promisify(execFile);
const CLI_TIMEOUT_MS = 30000;

export interface AzureOptions {
  subscription?: string;
  resourceGroup?: string;
  clientId?: string;
  clientSecret?: string;
  tenantId?: string;
  useManagedIdentity?: boolean;
}

export class AzureSource implements CloudSource {
  name = 'Azure DNS';
  private options: AzureOptions;

  constructor(options: AzureOptions = {}) {
    this.options = options;
  }

  async getDomains(): Promise<string[]> {
    return getAzureDNSDomains(this.options);
  }
}

/**
 * Login with service principal if credentials provided
 */
async function ensureAzureAuth(options: AzureOptions): Promise<void> {
  if (options.clientId && options.clientSecret && options.tenantId) {
    try {
      await execFileAsync('az', [
        'login',
        '--service-principal',
        '-u', options.clientId,
        '-p', options.clientSecret,
        '--tenant', options.tenantId,
        '--output', 'none'
      ], { timeout: CLI_TIMEOUT_MS });
    } catch (err) {
      throw new Error(`Azure service principal login failed: ${(err as Error).message}`);
    }
  } else if (options.useManagedIdentity) {
    try {
      await execFileAsync('az', ['login', '--identity', '--output', 'none'], { timeout: CLI_TIMEOUT_MS });
    } catch (err) {
      throw new Error(`Azure managed identity login failed: ${(err as Error).message}`);
    }
  }
  // Otherwise rely on existing az login session
}

/**
 * Get all domains from Azure DNS zones
 */
export async function getAzureDNSDomains(options: AzureOptions = {}): Promise<string[]> {
  // Handle service principal or managed identity auth
  await ensureAzureAuth(options);

  const args = ['network', 'dns', 'zone', 'list'];
  
  if (options.subscription) {
    args.push('--subscription', options.subscription);
  }
  if (options.resourceGroup) {
    args.push('-g', options.resourceGroup);
  }
  
  args.push('--output', 'json');

  try {
    // List all DNS zones
    const { stdout } = await execFileAsync('az', args, { timeout: CLI_TIMEOUT_MS });

    const zones: Array<{ 
      name: string; 
      zoneType?: string;
    }> = JSON.parse(stdout) || [];

    // Filter public zones only
    const domains = zones
      .filter(zone => zone.zoneType !== 'Private')
      .map(zone => zone.name);

    return domains;
  } catch (err) {
    const error = err as Error & { stderr?: string; message?: string };
    const errorMsg = error.stderr || error.message || '';
    if (errorMsg.includes('login') || errorMsg.includes('credentials')) {
      throw new Error('Azure credentials not configured. Run "az login"');
    }
    if (errorMsg.includes('ENOENT') || errorMsg.includes('command not found')) {
      throw new Error('Azure CLI not found. Install from: https://docs.microsoft.com/cli/azure/install-azure-cli');
    }
    if (errorMsg.includes('subscription')) {
      throw new Error('Azure subscription not set. Use --azure-subscription or run "az account set -s SUBSCRIPTION_ID"');
    }
    throw new Error(`Failed to list Azure DNS zones: ${error.message}`);
  }
}

/**
 * List Azure subscriptions
 */
export async function listAzureSubscriptions(options: AzureOptions = {}): Promise<string[]> {
  await ensureAzureAuth(options);

  try {
    const { stdout } = await execFileAsync('az', [
      'account', 'list',
      '--output', 'json'
    ], { timeout: CLI_TIMEOUT_MS });

    const subscriptions: Array<{ id: string; name: string }> = JSON.parse(stdout) || [];
    return subscriptions.map(s => s.id);
  } catch {
    return [];
  }
}

/**
 * Get domains from all Azure subscriptions
 */
export async function getAzureDNSDomainsAllSubscriptions(
  options: AzureOptions = {}
): Promise<string[]> {
  const subscriptions = await listAzureSubscriptions(options);
  const allDomains: string[] = [];

  for (const subscription of subscriptions) {
    try {
      const domains = await getAzureDNSDomains({ ...options, subscription });
      allDomains.push(...domains);
    } catch {
      // Skip subscriptions without access
    }
  }

  return [...new Set(allDomains)];
}
