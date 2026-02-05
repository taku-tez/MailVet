/**
 * CLI dependency preflight checks
 * Verify cloud CLI tools are available before attempting operations
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export interface PreflightResult {
  available: boolean;
  version?: string;
  error?: string;
}

/**
 * Check if a CLI tool is available and return its version
 */
async function checkCLI(command: string, versionArgs: string[]): Promise<PreflightResult> {
  try {
    const { stdout } = await execFileAsync(command, versionArgs, { timeout: 5000 });
    return { available: true, version: stdout.trim().split('\n')[0] };
  } catch (err) {
    const error = err as NodeJS.ErrnoException;
    if (error.code === 'ENOENT') {
      return { available: false, error: `${command} not found. Install it from the official documentation.` };
    }
    return { available: false, error: error.message };
  }
}

export async function checkAWSCLI(): Promise<PreflightResult> {
  return checkCLI('aws', ['--version']);
}

export async function checkGCloudCLI(): Promise<PreflightResult> {
  return checkCLI('gcloud', ['--version']);
}

export async function checkAzureCLI(): Promise<PreflightResult> {
  return checkCLI('az', ['--version']);
}

export async function checkDigCommand(): Promise<PreflightResult> {
  return checkCLI('dig', ['-v']);
}

/**
 * Run preflight checks for the specified cloud providers
 */
export async function runPreflightChecks(options: {
  aws?: boolean;
  gcp?: boolean;
  azure?: boolean;
  dnssec?: boolean;
}): Promise<Map<string, PreflightResult>> {
  const results = new Map<string, PreflightResult>();
  const checks: Promise<void>[] = [];

  if (options.aws) {
    checks.push(checkAWSCLI().then(r => { results.set('aws', r); }));
  }
  if (options.gcp) {
    checks.push(checkGCloudCLI().then(r => { results.set('gcloud', r); }));
  }
  if (options.azure) {
    checks.push(checkAzureCLI().then(r => { results.set('az', r); }));
  }
  if (options.dnssec) {
    checks.push(checkDigCommand().then(r => { results.set('dig', r); }));
  }

  await Promise.all(checks);
  return results;
}
