import dns from 'node:dns/promises';
import net from 'node:net';
import { logSsrfAttempt } from './logger.js';

// Security configuration - single source of truth
export const allowlistHosts = new Set([
  'example.com',
  'api.example.com',
  'httpbin.org',
]);

export const blockedHosts = new Set([
  '169.254.169.254', // AWS metadata IP
  'metadata.google.internal',
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
]);

export const blockedPathPatterns = [/^\/latest\/meta-data/i, /^\/computeMetadata\/v1/i];

// Request timeout in milliseconds
export const REQUEST_TIMEOUT_MS = 5000;

// Private IP validation functions - exported for reuse
export function isPrivateIPv4(address) {
  const octets = address.split('.').map(Number);
  if (octets.length !== 4 || octets.some(Number.isNaN)) return false;
  const [a, b] = octets;
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 127) return true; // localhost
  if (a === 169 && b === 254) return true; // link-local
  return false;
}

export function isPrivateIPv6(address) {
  const lower = address.toLowerCase();
  if (lower === '::1') return true; // loopback
  if (lower.startsWith('fd') || lower.startsWith('fc')) return true; // unique local
  if (lower.startsWith('fe80')) return true; // link-local
  return false;
}

export function isPrivateIp(address, family) {
  if (family === 4 || net.isIP(address) === 4) return isPrivateIPv4(address);
  if (family === 6 || net.isIP(address) === 6) return isPrivateIPv6(address);
  return false;
}

export async function resolveHost(hostname) {
  const result = await dns.lookup(hostname, { verbatim: true });
  const { address, family } = result;
  return { address, family, isPrivate: isPrivateIp(address, family) };
}

/**
 * Validates and fetches a URL with SSRF protection
 * @param {string} url - The URL to validate and fetch
 * @param {string} endpoint - The endpoint name for logging
 * @returns {Promise<{status: number, body: string}>} - The fetch result
 * @throws {Error} - Validation errors with specific error messages
 */
export async function validateAndFetch(url, endpoint) {
  // Parse and validate URL
  let parsed;
  try {
    parsed = new URL(url);
  } catch (err) {
    logSsrfAttempt({ endpoint, url, blocked: true, reason: 'invalid url' });
    throw new Error('invalid url');
  }

  // Only allow http and https protocols
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    logSsrfAttempt({ endpoint, url, blocked: true, reason: 'protocol not allowed' });
    throw new Error('only http/https allowed');
  }

  // Check hostname allowlist
  if (!allowlistHosts.has(parsed.hostname)) {
    logSsrfAttempt({ endpoint, url, blocked: true, reason: 'host not allowlisted' });
    throw new Error('host not allowlisted');
  }

  // Check blocked hosts
  if (blockedHosts.has(parsed.hostname) || blockedPathPatterns.some((re) => re.test(parsed.pathname))) {
    logSsrfAttempt({ endpoint, url, blocked: true, reason: 'blocked host/path' });
    throw new Error('blocked target');
  }

  // Resolve DNS and check for private IPs
  let resolved;
  try {
    resolved = await resolveHost(parsed.hostname);
  } catch (err) {
    logSsrfAttempt({ endpoint, url, blocked: true, reason: `dns error: ${err.message}` });
    throw new Error('dns resolution failed');
  }

  if (resolved.isPrivate) {
    logSsrfAttempt({ endpoint, url, blocked: true, reason: `private ip ${resolved.address}` });
    throw new Error('private address blocked');
  }

  // Perform fetch with timeout and redirect protection
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    // Use redirect: 'manual' to prevent automatic redirects to private IPs
    const upstream = await fetch(parsed.toString(), { 
      signal: controller.signal,
      redirect: 'manual' // Don't follow redirects automatically
    });
    
    // Handle redirects manually (3xx status codes)
    if (upstream.status >= 300 && upstream.status < 400) {
      const location = upstream.headers.get('location');
      if (location) {
        logSsrfAttempt({ endpoint, url, blocked: true, reason: `redirect detected to ${location}` });
        throw new Error('redirects not allowed');
      }
    }
    
    const body = await upstream.text();
    logSsrfAttempt({ endpoint, url, blocked: false, status: upstream.status });
    return { status: upstream.status, body };
  } catch (err) {
    const reason = err.name === 'AbortError' ? 'timeout' : err.message;
    logSsrfAttempt({ endpoint, url, blocked: false, status: 'error', reason });
    throw err;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Helper function to handle validation errors and send appropriate HTTP responses
 * @param {Error} err - The error object
 * @param {import('express').Response} res - Express response object
 */
export function handleValidationError(err, res) {
  const validationErrors = [
    'invalid url',
    'only http/https allowed',
    'host not allowlisted',
    'blocked target',
    'dns resolution failed',
    'private address blocked',
    'redirects not allowed'
  ];

  if (validationErrors.includes(err.message)) {
    res.status(400).json({ error: err.message });
  } else {
    res.status(500).json({ error: 'fetch failed' });
  }
}

/**
 * Registers the secure POST /fetch-secure route
 * @param {import('express').Express} app - Express app instance
 */
export function registerSecureRoute(app) {
  app.post('/fetch-secure', async (req, res) => {
    const { url } = req.body || {};
    if (!url) {
      res.status(400).json({ error: 'url required' });
      return;
    }

    try {
      const result = await validateAndFetch(url, '/fetch-secure');
      res.status(result.status).send(result.body);
    } catch (err) {
      handleValidationError(err, res);
    }
  });
}
