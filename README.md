# SSRF Demo Project

This is a simple demo project I put together to show how SSRF (Server-Side Request Forgery) vulnerabilities work and how to fix them. It's got both a vulnerable version and a secure version so you can see the difference side-by-side.

## What's SSRF anyway?

SSRF happens when your server makes HTTP requests based on user input without proper validation. An attacker can trick your server into making requests to internal services it shouldn't have access to - like cloud metadata endpoints, internal APIs, or other services behind your firewall.

The classic example is hitting AWS metadata endpoints (`169.254.169.254`) to grab IAM credentials, but it can be used for port scanning, accessing internal services, or bypassing network restrictions.

## What's in here

- `backend/server-vulnerable.js` - The bad one (runs on port 3000). Shows what happens when you trust user input.
- `backend/server-secure.js` - The good one (runs on port 4000). Shows how to do it right.
- `backend/secure_route.js` - All the validation logic lives here. This is the single source of truth for SSRF protection.
- `backend/logger.js` - Simple logging for tracking SSRF attempts
- `backend/scripts/ssrf-tests.sh` - Bash script to test both servers

## Getting started

First, install the dependencies:

```bash
cd backend
npm install
```

Then run both servers. You'll need two terminals:

**Terminal 1 - vulnerable server:**
```bash
cd backend
node server-vulnerable.js
```

**Terminal 2 - secure server:**
```bash
cd backend
node server-secure.js
```

Once both are running, you can test them:

```bash
cd backend
chmod +x scripts/ssrf-tests.sh
./scripts/ssrf-tests.sh
```

## The vulnerable version

Here's what the vulnerable endpoint looks like:

```javascript
app.get('/fetch', async (req, res) => {
  const { url } = req.query;
  const upstream = await fetch(url);  // ⚠️ Yikes, no validation!
  const body = await upstream.text();
  res.status(upstream.status).send(body);
});
```

Yeah, that's it. No checks, no validation, just fetch whatever the user gives you. You can see why that's a problem:

```bash
curl "http://localhost:3000/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials"
```

This will actually work on the vulnerable server and return fake AWS credentials (I simulate the metadata endpoint for demo purposes).

## The secure version

The secure implementation does a bunch of things to prevent SSRF attacks. All the validation logic is in `secure_route.js` so it can be reused:

1. **URL parsing and validation** - Makes sure it's actually a valid URL
2. **Protocol whitelist** - Only allows `http://` and `https://` (no `file://`, `gopher://`, etc.)
3. **Host allowlist** - Only specific trusted hosts are allowed (currently `example.com`, `api.example.com`, and `httpbin.org`)
4. **Blocked hosts** - Explicitly blocks known dangerous hosts like metadata services and localhost
5. **DNS resolution** - Resolves the hostname and checks the actual IP address
6. **Private IP blocking** - Blocks all private IP ranges:
   - `10.0.0.0/8`
   - `172.16.0.0/12`
   - `192.168.0.0/16`
   - `127.0.0.0/8` (localhost)
   - `169.254.0.0/16` (link-local, includes AWS metadata IP)
7. **Path pattern blocking** - Blocks dangerous paths like `/latest/meta-data`
8. **Redirect protection** - Doesn't automatically follow redirects (prevents redirect-based SSRF)
9. **Request timeout** - 5 second timeout to prevent resource exhaustion

Try the same attack on the secure server:

```bash
curl "http://localhost:4000/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials"
# Returns: {"error":"host not allowlisted"}
```

But legitimate requests work fine:

```bash
curl "http://localhost:4000/fetch?url=http://httpbin.org/get"
```

## Architecture

The secure server uses `secure_route.js` as the single source of truth for all validation logic. Both the GET `/fetch` endpoint and POST `/fetch-secure` endpoint use the same `validateAndFetch()` function, so there's no code duplication and any improvements benefit both endpoints.

## Endpoints

**Vulnerable server (port 3000):**
- `GET /` - Just a status message
- `GET /fetch?url=<URL>` - The vulnerable endpoint (fetches anything)
- `GET /aws-metadata/latest/meta-data/iam/security-credentials` - Fake AWS metadata for testing

**Secure server (port 4000):**
- `GET /` - Status message
- `GET /fetch?url=<URL>` - Secure endpoint with all the validation
- `POST /fetch-secure` - Same thing but POST (send JSON: `{"url": "..."}`)
- `GET /aws-metadata/latest/meta-data/iam/security-credentials` - Fake AWS metadata for testing

## Testing

The test script runs through a few scenarios:
- Shows the vulnerable server getting exploited
- Shows the same attack being blocked on the secure server
- Shows legitimate requests working
- Tests private IP blocking
- Tests localhost blocking

Run it with both servers up and you'll see the difference.

## Notes

This is just for educational purposes. The fake AWS metadata endpoint is there to simulate what would happen in a real attack, but obviously it's not returning real credentials.

If you're building something real, you'd probably want to add rate limiting, better logging, maybe a config file for the allowlist, and proper error handling. But this should give you a good starting point for understanding SSRF and how to prevent it.
