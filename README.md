# aws-waf-java4shell-base64-guard

[日本語](README.ja.md)

An AWS WAF CloudFormation sample that **counts** (or blocks) requests carrying a malformed Base64 token, the input shape that triggers Java4Shell (CVE-2026-114938). It is for detection and for reading WAF metrics while you patch.

**This is not a fix.** Patch the JDK, or start the JVM with `-XX:-UseBASE64Intrinsics`. Wiz says WAF rules are unlikely to cover every code path that reaches the decoder, and never cover home-grown applications completely: https://www.wiz.io/blog/cve-2026-114938-rce-java4shell-openjdk

> **Status (2026-11-18):** deployed once to a test ALB (fixed 200 response, HTTP) in ap-northeast-1 in Count mode. AWS WAF accepted the expressions, and the WAF logs show each of the four fields counted as intended. Block mode, HTTPS, bodies over 8 KB, CloudFront and API Gateway are **not tested**, and nothing was run against a real vulnerable JVM. See "What is and is not verified".

## What Java4Shell is (short)

- A heap out-of-bounds write in the x86-64 Base64 decode intrinsic of OpenJDK HotSpot. A malformed string with trailing `=` makes the output length underflow, and the intrinsic writes 64 bytes. Java throws `IllegalArgumentException` afterwards, but the write has already happened.
- Trigger input: `A` x 64 + `=` (OpenJDK 17: `A` x 128 + `=`).
- Affected: OpenJDK 17.0.6 and later, 21, 25, 27, and downstream builds, on x86-64 CPUs with AVX-512 VBMI (Intel Ice Lake or newer, AMD Zen 4 or newer). ARM64 is not affected. Standard Java 8 and 11 are not affected; Oracle lists its Java 8 Performance Pack build `8u511b33-perf`.
- Sources: [Calif write-up](https://calif.io/java4shell/), [OpenJDK advisory](https://openjdk.org/groups/vulnerability/advisories/2026-11-17), [CISA alert](https://www.cisa.gov/news-events/alerts/2026/11/17/critical-java-vulnerability-requires-immediate-patching), [Wiz](https://www.wiz.io/blog/cve-2026-114938-rce-java4shell-openjdk), [Upwind](https://www.upwind.io/blog/java4shell-what-we-know-now-and-what-comes-next).

## Interim measures, in priority order

1. **JVM flag `-XX:-UseBASE64Intrinsics`.** Needs no application change and stops the vulnerable code. You can pass it with the `JAVA_TOOL_OPTIONS` environment variable, without rebuilding. Recreate containers so the setting reaches the running process. `-XX:UseAVX=2` also works on x86-64, but an ARM JVM does not recognize it and fails to start, so avoid it in mixed fleets. Do not use `-XX:DisableIntrinsic=_base64_decodeBlock` alone: Upwind reports the JVM then fails to start.
2. **Patch.** Oracle's fixed builds end in `.1` according to Upwind (17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1). I could not confirm these numbers on Oracle's advisory; check your vendor.
3. **This web ACL**, starting in Count mode.
4. **Inventory.** The same image can be exposed on one node and safe on another, depending on the CPU. To check a Linux host (from Calif):
   ```bash
   grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' | grep -E '^(avx512f|avx512bw|avx512vbmi|bmi2)$'
   ```
   If all four flags are printed, the host runs the vulnerable hardware path.

## What the web ACL does

One web ACL with four rules (default action Allow). All four reference one regex pattern set.

| Priority | Rule | Inspects |
|---|---|---|
| 10 | `MalformedBase64-AuthorizationHeader` | `Authorization` header |
| 20 | `MalformedBase64-CookieValues` | All cookie values |
| 30 | `MalformedBase64-QueryString` | Query string, raw and URL-decoded |
| 40 | `MalformedBase64-Body` | Body (first 8 KB on an ALB) |

A value matches when it contains a token that:

- starts at the beginning of the value or after a character outside `A-Za-z0-9+/_-`,
- has 32 or more characters of that alphabet (Upwind's detection hint; Calif's trigger is 64 or more, 128 or more on OpenJDK 17), and
- ends with one or more `=` that do **not** form valid padding. Valid padding is two alphabet characters plus `==`, or three plus `=`, after groups of four.

So `A` x 64 + `=` matches, while a validly padded value such as `...AA==` or an unpadded value (JWT segments) does not. The regular expressions are derived from the pseudocode in Calif's write-up. The exact trigger condition is my inference, so treat a non-match as "not seen", not as "safe".

## Deploy

```bash
aws cloudformation deploy \
  --stack-name waf-java4shell-base64 \
  --template-file template.yaml \
  --region ap-northeast-1 \
  --parameter-overrides \
      Scope=REGIONAL \
      RuleAction=Count \
      AssociateResourceArn=arn:aws:elasticloadbalancing:REGION:ACCOUNT_ID:loadbalancer/app/NAME/ID
```

Start with `RuleAction=Count`, watch the CloudWatch metrics and sampled requests, and switch to `Block` only when no legitimate traffic is counted. Delete the stack to remove everything it created.

### Parameters

| Name | Default | Notes |
|---|---|---|
| `Scope` | `REGIONAL` | `REGIONAL` (ALB, API Gateway, AppSync, ...) or `CLOUDFRONT`. CloudFront must be deployed in `us-east-1`. |
| `RuleAction` | `Count` | `Count` or `Block`. |
| `WebAclName` | `java4shell-base64-count` | Also the metric name prefix. |
| `EnableLogging` | `false` | `true` creates a CloudWatch Logs log group `aws-waf-logs-<WebAclName>` and sends web ACL logs to it. The `Authorization` and `Cookie` header values are redacted. The request URI and query string are not, so a token in the query string is logged. |
| `LogRetentionInDays` | `7` | Retention of that log group. |
| `AssociateResourceArn` | (empty) | Empty creates the web ACL only. A resource has one web ACL, so associating **replaces** the one already attached. Check first. For CloudFront, set the web ACL ID on the distribution instead. |

If you already have a web ACL, add the four rules and the pattern set to it instead of attaching this one.

## Limits you should know

- **Not every path goes through WAF.** Internal calls, queue messages, S3 events and listeners without a web ACL are not inspected.
- **Body inspection is bounded.** An ALB passes the first 8 KB (fixed). CloudFront and API Gateway default to 16 KB, up to 64 KB with the web ACL `AssociationConfig`. The body rule uses `OversizeHandling: CONTINUE`, so a token past the limit is not seen. Switching to `MATCH` with `Block` would reject every large upload.
- **Other encodings slip past.** URL-encoded values inside a body, JSON escapes (`\u003d`), gzip, and multipart parts are not decoded. Only the query string is checked URL-decoded.
- **Base64 inside other values** (a JWT in a cookie, Basic credentials split across fields) is only found if the malformed token starts and ends as described above.
- **Request streaming.** Calif says some chains need partial request bodies, so a proxy that buffers the whole body (nginx does by default) breaks those, but not all (its Elasticsearch chain works from one complete request).
- **Attribution.** Count mode shows which rule matched, not whether the request was an attack.
- **Cost.** AWS WAF charges for web ACLs, rules and requests. See the AWS pricing page.

## What is and is not verified

Test on 2026-11-18: an ALB (HTTP 80, fixed response 200) in ap-northeast-1, this web ACL attached with `RuleAction=Count` and `EnableLogging=true`, requests sent with `test/curl_checks.sh` from one workstation. Every request returned 200, as expected in Count mode. In the WAF logs (`nonTerminatingMatchingRules`):

| Request | Counted by |
|---|---|
| `Authorization: Basic` + `A` x 64 + `=` | `MalformedBase64-AuthorizationHeader` |
| `Cookie: session=` + `A` x 64 + `=` | `MalformedBase64-CookieValues` |
| `?t=` + `A` x 64 + `=`, and the same with `%3D` | `MalformedBase64-QueryString` |
| POST body with the token (`text/plain`, `application/x-www-form-urlencoded`, `application/json`; token alone, `token=...`, `{"t":"..."}`, `x <token> y`) | `MalformedBase64-Body` |
| GET without a token, `-u user:pass`, a validly padded 36-character value, a 20-character malformed token, a JWT-like cookie | not counted |

The `Authorization` and `Cookie` values were recorded as `REDACTED`; the rule match was still recorded.

Also verified: `cfn-lint` passes, and `python3 test/test_patterns.py` passes (13 inputs that must match, 10 that must not).

Not explained: of the first 13 requests, 2 (a `text/plain` POST with `token=<token>` and a JSON POST) did not appear in the WAF log. The same shapes sent later with an `?id=` marker (6 requests) were all logged and counted. I did not find the cause.

Not tested:
- Block mode and the response it returns.
- HTTPS listeners, CloudFront and API Gateway.
- Bodies over 8 KB, and the `OversizeHandling: CONTINUE` behavior.
- The CloudWatch metric values (`CountedRequests`). Sampled requests showed the Authorization, Cookie and query string matches.
- False positives on real traffic.
- Behavior against a real vulnerable JVM. The test ALB returns a fixed response, so no Java ran.
- Acceptance by AWS WAF is confirmed for ap-northeast-1 only.

## Test

Local, no AWS needed:

```bash
python3 test/test_patterns.py
```

On AWS, with a test ALB you own (`test/alb-fixed-response.yaml` creates one: HTTP 80, fixed 200, open to one CIDR only):

```bash
aws cloudformation deploy --stack-name j4s-test-alb --template-file test/alb-fixed-response.yaml \
  --parameter-overrides VpcId=vpc-xxxx SubnetIds=subnet-aaaa,subnet-bbbb AllowedCidr=<your-ip>/32
aws cloudformation deploy --stack-name j4s-test-waf --template-file template.yaml \
  --parameter-overrides RuleAction=Count EnableLogging=true AssociateResourceArn=<alb-arn>
bash test/curl_checks.sh <alb-dns-name>
# then read the log group aws-waf-logs-java4shell-base64-count (nonTerminatingMatchingRules)
```

`curl_checks.sh` sends a malformed string only. Do not point it at a real Java service that decodes Base64 on an AVX-512 VBMI host without `-XX:-UseBASE64Intrinsics`: on an affected JVM it can trigger the out-of-bounds write Calif describes. Delete both stacks when done; they cost money while they run.

## License

MIT. See [LICENSE](LICENSE).
