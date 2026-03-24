# Root Cause Analysis

## the bug in one sentence

`validateDownloadUrl()` checks if a hostname is a literal private IP string but never resolves DNS, so any domain pointing to a private IP bypasses it entirely.

## the code

```typescript
// packages/provider-utils/src/validate-download-url.ts

export function validateDownloadUrl(url: string): void {
  let parsed = new URL(url);

  // only http/https allowed
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw ...

  const hostname = parsed.hostname;

  // block literal localhost strings
  if (hostname === 'localhost' ||
      hostname.endsWith('.local') ||
      hostname.endsWith('.localhost')) throw ...

  // block literal IPv4 private addresses
  if (isIPv4(hostname)) {
    if (isPrivateIPv4(hostname)) throw ...   // catches 127.x, 10.x, 192.168.x etc
  }

  // block literal IPv6 private addresses
  if (hostname.startsWith('[') && hostname.endsWith(']')) {
    if (isPrivateIPv6(ipv6)) throw ...       // catches ::1, fe80::, fc00:: etc
  }

  // thats it. no dns resolution. hostname "evil.com" passes everything above
  // even when evil.com has an A record pointing to 127.0.0.1
}
```

## why string matching fails

the security boundary for SSRF is at the network layer (DNS resolution + TCP connection), not at the URL parsing layer. a hostname is just a label. what matters is what IP address it resolves to when the OS actually makes the connection.

```
hostname: "ssrf.attacker.com"   → string check says: not localhost, not an IP → PASS
DNS resolution:                 → 127.0.0.1
TCP connection:                 → connects to localhost
```

the check and the connection operate on completely different representations of the same target. this is fundamentally why string-level SSRF protections dont work.

## where it gets called

`validateDownloadUrl()` is called from two places that matter:

1. `downloadBlob()` in `packages/provider-utils/src/download-blob.ts`
   - used by image generation providers (openai, deepinfra, openai-compatible)
   - returns full response body to caller

2. `download()` in `packages/ai/src/util/download/download.ts`
   - called from `convertToLanguageModelPrompt()` via `downloadAssets()`
   - automatically downloads image/file URLs from user messages
   - this is the path where user input directly reaches the vulnerable code

## the correct fix

three things need to happen:

1. resolve the hostname to IP addresses via `dns.lookup()`
2. check the resolved IPs against private ranges
3. pin the resolved IPs to the fetch connection so DNS cant change between check and connect

```typescript
import { lookup } from 'dns/promises';

// step 1+2: resolve and check
const records = await lookup(hostname, { family: 0, all: true });
for (const record of records) {
  if (isPrivateIPv4(record.address) || isPrivateIPv6(record.address)) {
    throw new DownloadError({ url, message: 'resolved to private IP' });
  }
}

// step 3: pin to validated IPs (prevents TOCTOU/DNS rebinding)
const res = await fetch(href, {
  dispatcher: new undici.Agent({
    connect: {
      lookup: (_hostname, _opts, cb) => {
        cb(null, records.map(r => ({ address: r.address, family: r.family })));
      }
    }
  })
});
```

without step 3 you fix the no-resolution problem but open a TOCTOU race condition where DNS can change between the check and the actual connection. this is the exact bug that exists in the Next.js image optimizer (separate vuln, separate codebase).

## this pattern is everywhere

the same string-matching-instead-of-DNS-resolution mistake has been found in:

| project | advisory | year |
|---------|----------|------|
| pydantic-ai | GHSA-2jrp-274c-jhv3 | 2025 |
| mindsdb | GHSA-4jcv-vp96-94xr | 2024 |
| esm.sh | GHSA-p2v6-84h2-5x4r | 2024 |
| vLLM | CVE-2026-24779 | 2026 |
| vercel AI SDK | #13510 | 2026 |

if your SSRF protection doesnt resolve DNS, it doesnt protect against SSRF.
