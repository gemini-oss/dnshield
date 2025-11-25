# DNS Response Parsing Architecture

The Network Extension uses `DNSPacket` (`dnshield/Extension/DNSPacket.{h,m}`) to parse every incoming
query and every upstream response. The parser feeds the caching layer, telemetry, and the synthetic
response builders that live in `ProxyProvider/FlowManagement.m`. The implementation focuses on
strict bounds checking so malformed packets never crash the proxy.

## Responsibilities

`DNSPacket` exposes a few core helpers:

- `parseQuery:` - Validates UDP DNS queries, extracts the domain/type/class, and surfaces protocol
  errors via `NSError`.
- `parseResponse:` - Parses upstream answers, collects TTLs and answer records, and returns a
  `DNSResponse` object used by the cache.
- `extractTTLFromResponse:` / `updateTTLInResponse:` - Allow `DNSCache` to clamp TTLs before storing
  entries.
- Builders: `createBlockedAResponse:`, `createBlockedAAAAResponse:`, `createNXDOMAINResponse:`,
  `createServerFailureResponse:`, and `createFormatErrorResponse:` cover every synthetic packet the
  extension returns.
- Helper utilities resolve compression pointers and generate RFC-compliant RDATA payloads.

## Query Parsing Pipeline

1. **Packet Guard**  
   UDP DNS queries must be between 12 and 512 bytes. Anything outside that range is dropped.

2. **Header Validation**  
   The parser ensures the QR bit is unset (queries only) and at least one question (`QDCOUNT > 0`)
   exists.

3. **Label Decoding**  
   The question name is consumed label-by-label with RFC-compliant safeguards:
   - Each label length is <= 63 bytes.
   - Total domain length <= 253 bytes and <= 127 labels.
   - Compression pointers are rejected in the question (per RFC 1035).
   - UTF-8 decoding is attempted first, falling back to ASCII for legacy encodings.

4. **Type/Class Extraction**  
   The last four bytes of the question encode the query type (A, AAAA, etc.) and class (IN). These
   values drive rule evaluation and response synthesis later in the pipeline.

Any validation failure produces an `NSError` describing the problem and the proxy responds with
`FORMERR`.

## Response Parsing Pipeline

1. **Header Fields**  
   The QR bit must be set. The parser records the transaction ID, response code, and the
   question/answer counts.

2. **Question Replay**  
   To associate the upstream answer with the original query, the parser rebuilds the domain name from
   the question. Compression pointers are allowed here and resolved with a recursive helper that caps
   the number of jumps (prevents loops).

3. **Answer Processing**  
   For each answer record (`ANCOUNT`):
   - The parser skips the owner name (respecting compression pointers).
   - Reads the type, class, TTL, and RDATA length.
   - Tracks the **minimum TTL** across all answers so the cache can honor the most restrictive value.
   - Extracts A (IPv4) and AAAA (IPv6) addresses, converting them into printable strings via
     `inet_ntop`. Unknown record types are skipped safely.

4. **Result Object**  
   The resulting `DNSResponse` contains:
   - `domain` / `queryType` of the question.
   - `transactionID` (used to match responses back to outstanding flows).
   - `responseCode`.
   - `ttl` (minimum TTL, defaulting to 300 seconds if absent).
   - `answers` array (printable IP addresses).
   - A pointer to the original packet for logging or TTL rewriting.

## TTL Management and Caching

`DNSCache` (`dnshield/Extension/DNSCache.m`) clamps TTLs between 30 and 300 seconds. When a response
is cacheable:

```objc
NSData *updated = [DNSPacket updateTTLInResponse:responseData newTTL:clampedTTL];
[self.dnsCache cacheResponse:updated
                    forDomain:response.domain
                    queryType:response.queryType
                          ttl:clampedTTL];
```

`updateTTLInResponse:` walks the first answer section and rewrites the TTL field so the response sent
back to the client matches what the cache uses. This prevents the proxy from serving a cached packet
with an expired TTL.

## Synthetic Responses

When DNShield blocks a domain or needs to return an error, it relies on the builders inside
`DNSPacket`:

- `createBlockedAResponse:` returns a no-op A record pointing to `127.0.0.1`.
- `createBlockedAAAAResponse:` returns an empty AAAA response (or `::1` loopback if needed).
- `createNXDOMAINResponse:` and `createServerFailureResponse:` reuse the question and adjust the
  header bits to signal the error condition.

These helpers ensure the proxy produces well-formed packets that clients accept without retry storms.

## Observability

Parser activity shows up under the `dns` log category (LoggingManager registers the handle as
lowercase). Use `--info` because most messages are logged at the Info level:

```bash
log show --predicate 'subsystem == "com.dnshield.extension" && category == "dns"' \
         --last 5m --info | grep "DNS response"
```

Example entries:

```
DNShield[Extension] DNS response size 112 exceeds standard UDP limit, may need TCP
DNShield[Extension] Upstream response for intranet.local (A) from 100.95.0.251: TTL 120, answers=1
```

Those logs originate from `ProxyProvider/FlowManagement.m`, which calls `DNSPacket` to decode the
packet before taking action.

## How to Test in the Field

1. **Enable verbose DNS logging (optional)**  
   ```bash
   sudo defaults write /Library/Preferences/com.dnshield.app LogLevel -int 2
   sudo dnshield-ctl restart
   ```

2. **Trigger traffic**  
   Resolve a domain (ideally both public and internal) from the client and watch the log stream.

3. **Verify TTL Handling**  
   Check that the log lines show the upstream TTL and compare it with the cached value if you clear
   the cache and re-query. Cached hits should report the clamped TTL.

4. **Send Malformed Packets (optional)**  
   The parser should reject deliberately truncated packets without affecting flow handling. Use a
   quick Python snippet to send a short UDP payload to whichever resolver you normally target (the
   network extension intercepts the flow before it leaves the host):
   ```bash
   python3 - <<'PY'
   import os, socket

   bad_query = b'\xaa\xbb' + os.urandom(5)  # shorter than the 12-byte DNS header
   with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
       sock.sendto(bad_query, ("1.1.1.1", 53))
   PY
   ```
   Replace `1.1.1.1` with an appropriate server if your environment blocks that IP. You should see a
   `Not a query packet` or `Packet too short` message in the `dns` log stream.

5. **Reset Log Level**  
   ```bash
   sudo defaults delete /Library/Preferences/com.dnshield.app LogLevel
   sudo dnshield-ctl restart
   ```

By following these steps, you can confirm that the parser is enforcing the DNS protocol strictly,
feeding the cache accurate TTL data, and generating compliant synthetic responses when the product
blocks traffic.
