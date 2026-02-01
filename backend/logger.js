export function logSsrfAttempt({ endpoint, url, blocked = false, reason = 'none', status = 'unknown' }) {
  const entry = {
    ts: new Date().toISOString(),
    endpoint,
    url,
    blocked,
    status,
    reason,
  };

  // Logging in console
  console.log(JSON.stringify(entry));
}
