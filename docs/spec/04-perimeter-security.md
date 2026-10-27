# Section 4 — Perimeter Security & Access Specifications (v2)

This section defines the network perimeter: the single-source-of-truth IP
allowlist, the WAF rule layer that gates both hostnames, and the
rate-limiting rules that protect downstream serverless cost. It assumes
IP-only access (no Cloudflare Access / SSO layer), with audit logging into
the `audit_log` D1 table (Section 3.1.1) as the per-request accountability
mechanism.

---

## 4.1 Single-Source-of-Truth IP Allowlist

### 4.1.1 Storage mechanism

A single Cloudflare **IP List** named `corp_authorized_sources` is the
canonical authority. It is referenced by every WAF rule and rate-limit rule
described below; no rule embeds raw CIDRs inline.

- Created and managed via the Cloudflare Rulesets API (account-scoped).
- Same list referenced by both production and staging WAF rules. (Staging
  is identical to production in network posture — there is no "test" IP
  range that is more permissive.)
- IP List capacity: 10,000 entries per list on Workers Paid; we expect <100.

### 4.1.2 Entry metadata convention

Cloudflare's IP List API only supports an IP/CIDR value and a single string `description` field. To store the structured metadata while keeping `docs/network/whitelist-ledger.md` as the authoritative Git-managed store, we serialize the attributes into the entry's `description` field as a semicolon-separated key-value string:

`owner=<slack_or_email>;purpose=<reason>;expires=<YYYY-MM-DD>;ticket=<ticket_ref>`

| Field        | Required | Description / Format in Serialized String |
|--------------|----------|-------------------------------------------|
| `cidr`       | yes      | Placed in Cloudflare's `ip` field (e.g. `203.0.113.0/24` or `2001:db8::/64`) |
| `owner`      | yes      | `owner=<value>` (e.g. Slack handle or email of the requester) |
| `purpose`    | yes      | `purpose=<value>` (e.g. `corp-hq`, `vpn-eu-1`, `dev-laptop-jdoe`) |
| `expires`    | yes      | `expires=<YYYY-MM-DD>` (ISO 8601 date, max 1 year from creation) |
| `ticket`     | no       | `ticket=<value>` (Reference to the access-request ticket) |

Example serialized description: `owner=jdoe;purpose=vpn-eu-1;expires=2027-05-22;ticket=SEC-101`

### 4.1.3 Lifecycle

- Additions and removals are tracked in `docs/network/whitelist-ledger.md`
  as a flat list. Every change is a PR; no out-of-band edits.
- A scheduled worker (`pruning` cron `0 4 * * *`, on the ingest worker as
  an additional cron entry — to be added in Phase 1) calls the Rulesets API
  and retrieves all list entries. It parses the `expires=<YYYY-MM-DD>` metadata
  value from each entry's `description` field. If the parsed date is before today,
  the worker deletes the entry from the Cloudflare IP List. The pruning run
  writes a result row to the `audit_log` table with `action = 'PRUNE'`.
- A weekly summary of the IP List size is written to `cve_metrics_daily`
  under the key `iplist.entry_count` for trend visibility.

### 4.1.4 Bootstrap entries (initial seed)

Phase 1 seeds the IP List with the following placeholder entries:

- One CIDR per corporate office.
- One CIDR per VPN egress.
- Static IPs for designated developer machines that build / deploy.

The actual CIDR values are recorded in `docs/spec/RESOURCES.md` (not in
this public spec file, so the network topology is not committed in the
clear).

---

## 4.2 Unified WAF Rule Layer

### 4.2.1 Hostnames in scope

- `threatlens.<corp>.com` — the SvelteKit app worker (`threat-lens-app`).
- `api.threatlens.<corp>.com` — the same worker, separate hostname so that
  rate-limit rules can target API paths without parsing URI patterns.

The ingest worker has no hostname. It is not internet-routable; cron and
queue triggers are its only invocation paths and they bypass the public
edge entirely. WAF rules therefore have no surface on `threat-lens-ingest`.

### 4.2.2 Rule ordering (lowest priority number evaluated first)

| Priority | Phase        | Rule name             | Action  | Expression                                                                                  |
|----------|--------------|-----------------------|---------|---------------------------------------------------------------------------------------------|
| 100      | `http_request_firewall_custom` | `allow_method_safe`        | `skip`  | `(http.request.method in {"GET" "POST" "OPTIONS"}) and (ip.src in $corp_authorized_sources)` |
| 200      | `http_request_firewall_custom` | `block_method_unexpected`  | `block` | `not (http.request.method in {"GET" "POST" "OPTIONS"})`                                      |
| 300      | `http_request_firewall_custom` | `block_offlist_traffic`    | `block` | `not (ip.src in $corp_authorized_sources)`                                                   |

Notes:

- The v1 spec contained a "skip rules for `/healthz` from Cloudflare
  health-check ranges" entry. That rule was incoherent (a Workers-only
  deployment has no external origin Cloudflare needs to probe). It is
  removed entirely.
- The `allow_method_safe` rule short-circuits the common-path traffic so
  the block rules never evaluate further on valid requests.
- Block actions return a **custom JSON response** matching the error
  envelope in Section 5.2, with HTTP 403 and `code = "FORBIDDEN_NETWORK"`
  for the off-list block, and HTTP 405 with `code = "METHOD_NOT_ALLOWED"`
  for the unexpected-method block.

### 4.2.3 Bot management

- **Super Bot Fight Mode** is enabled in the dashboard for both hostnames,
  with the "Definitely automated" disposition set to `block`.
- Verified bots (search engines) do not need access to a private SOC tool;
  they are also blocked because the IP allowlist excludes them.
- The bot management score is logged into `audit_log.detail_json` for any
  request that gets through, for incident review.

### 4.2.4 TLS posture

- Minimum TLS version: 1.3 (set per zone).
- HSTS enabled with a 12-month `max-age` and `includeSubDomains`.
- Cloudflare's "Authenticated Origin Pulls" is irrelevant (no origin) but
  the equivalent guarantee — that only Cloudflare can reach the worker —
  is the platform default.

---

## 4.3 Cost-Control Rate Limiting

All rate-limit rules evaluate the **true client IP** via `cf.connecting_ip`
(equivalent to the `CF-Connecting-IP` header). VPN egress IPs are not
aggregated; each distinct egress address gets its own bucket.

### 4.3.1 Rule catalogue (edge — Cloudflare WAF)

The Business zone plan provides the custom rate-limiting rule capacity used
at the edge. We keep edge throttling to short-window volumetric controls:

| Rule name                      | Scope                                          | Characteristic                          | Action                                                | Notes                                       |
|--------------------------------|------------------------------------------------|-----------------------------------------|-------------------------------------------------------|---------------------------------------------|
| `rl_per_ip_general`            | `(http.request.uri.path matches "^/(search\|api/)") and not (http.request.uri.path starts_with "/api/admin/")` | 30 requests / 60 s per `cf.connecting_ip` | Block 60 s, HTTP 429 with envelope                    | General volumetric throttle; admin API excluded |
| `rl_per_ip_admin`              | `http.request.uri.path starts_with "/api/admin/"` | 60 requests / 60 s per `cf.connecting_ip` | Block 300 s, HTTP 429                                  | Admin endpoints — modest burst, sharp clamp |

Longer-window quotas (per-IP hourly AI cap, org-wide daily AI cap) are
enforced **inside the worker** via D1 ledger tables, not at the WAF edge.
This is intentional: Pro-plan WAF rate-limiting caps counting periods at
60 seconds, and Business caps at 10 minutes — neither supports the 1-hour
or 24-hour windows our AI cost controls need. The application-level
ledger pattern (Section 5.3.7) gives unlimited window granularity at the
cost of one D1 write per `/api/search` call, which is trivially cheap.

### 4.3.2 Application-level quota controls (Section 5.3.7)

| Control                        | Limit                                     | Storage                       | Returns                          |
|--------------------------------|-------------------------------------------|-------------------------------|----------------------------------|
| Per-IP hourly AI cap           | 500 requests / hour per `cf-connecting-ip` | `search_quota_ip_ledger`      | `429 RATE_LIMITED`               |
| Org-wide daily AI cap          | 50,000 requests / day across all IPs       | `search_quota_ledger`         | `503 GLOBAL_QUOTA_EXHAUSTED`     |

### 4.3.3 Why these specific numbers

- **30 req / min** general (WAF) — enough for a power user running
  concurrent search-refine cycles, far below scripted-scraper rates.
- **60 req / min admin** (WAF) — admin pages refresh sparingly; this
  number catches a misconfigured polling loop without impeding humans.
- **500 req / hour AI** (app-level) — bounds Workers AI Neuron
  consumption and Vectorize query units per IP. At 500 q/hr × 8 working
  hours × 20 working days × 30 users = 2.4 M queries/month maximum
  achievable, fits comfortably in Workers Paid tier.
- **50 k req / day org-wide AI** (app-level) — circuit breaker that
  trips well before the monthly Workers AI or Vectorize spend exceeds
  the approved budget. When this fires it is a signal of either
  compromise or runaway client behaviour, both of which warrant operator
  intervention.

These numbers are starting points. They are revised in Phase 5 once real
usage telemetry is in place; the edge values live in the Rulesets
configuration and the app-level values live as named constants in
`apps/app/src/lib/server/queries/searchCves.ts`.

### 4.3.4 Rate-limit response envelope

Every 429 (and the application-level daily search limit 503) returns:

```json
{
  "error": {
    "code": "RATE_LIMITED" | "GLOBAL_QUOTA_EXHAUSTED",
    "message": "<human-readable>",
    "retryAfterSeconds": <integer>,
    "requestId": "<cf-ray>"
  }
}
```

The `Retry-After` HTTP header carries the same number for clients that
honour it without parsing the body.

### 4.3.5 Interaction with the WAF block

WAF blocks (Section 4.2) execute **before** rate-limit rules. An off-list
request never increments any rate-limit counter. This protects rate-limit
counter capacity from being burned by hostile scanning.

---

## 4.4 Audit Logging Integration

Every request that passes the WAF and the rate-limit layer reaches the app
worker. The worker writes one row to `audit_log` per request that touches
a security-relevant route. Routes are classified as:

| Route                  | Logged? | Action label    |
|------------------------|---------|-----------------|
| `/`                    | no      | —               |
| `/search` GET (UI)     | no      | —               |
| `/api/search` POST     | yes     | `SEARCH`        |
| `/api/cve/:id` GET     | yes     | `VIEW`          |
| `/api/affected-products` GET | yes | `LIST_PRODUCTS` |
| `/api/threat-intel/*` GET    | yes | `LIST_THREATS`  |
| `/api/metrics/:window` GET   | no  | —               |
| `/api/admin/*`         | yes     | `ADMIN_*`       |

The write is **asynchronous** (`ctx.waitUntil`) and never blocks the
response. A D1 write failure on `audit_log` is logged via `console.error`
but does not propagate to the user — losing one audit row is preferable to
serving 500 errors when D1 is briefly unavailable.

`audit_log.detail_json` carries:

- For `SEARCH`: `{query: string, filterCount: number, resultCount: number}`
  — the query text is logged verbatim because it is the entire point of the
  audit trail.
- For `VIEW`: `{cveId: string}`.
- For `LIST_PRODUCTS`: `{vendor?: string, product?: string}`.
- For `LIST_THREATS`: `{panel: 'kev' | 'epss'}`.
- For `ADMIN_*`: `{view: string}`.

A weekly job purges `audit_log` rows older than 90 days.

---

## 4.5 Ingestion Path Security

The ingest worker is **not internet-reachable**. Its security model is:

- `workers_dev = false` in `wrangler.toml` — no `*.workers.dev` URL exists.
- No custom hostnames bound — the only invocation paths are Cron Triggers
  and the Queue consumer.
- Outbound calls (to NVD, MITRE GitHub, CISA KEV, FIRST EPSS) use HTTPS
  with strict certificate validation (the Workers runtime default).
- Source API keys (e.g. `NVD_API_KEY`) are Wrangler secrets, never logged.
- The ingest worker never reads the `corp_authorized_sources` list — it
  has no public requests to filter.

This is the reason for the two-worker split (Section 1.4): the app worker
is the only piece with a public attack surface, and the ingest worker is
the only piece with privileged write access. Neither role is reachable
through the other.

---

## 4.6 Telemetry & Observability

- **Every application-level rate limit or quota block** (such as the daily search quota exceedance) emits an Analytics Engine data point from the SvelteKit worker with `blob1 = RATE_LIMIT` or `blob1 = GLOBAL_QUOTA_EXHAUSTED`, `blob5 = <route>`, `blob6 = country`, `blob7 = colo`. This populates the dashboard's "throttled traffic" widget.
- **WAF and edge-level blocks** (which occur before the SvelteKit worker is reached) do not execute worker code and cannot write to the Analytics Engine. Their telemetry is monitored natively via the Cloudflare dashboard's Security Analytics view or via WAF firewall logs.
- **Live log streaming** uses `wrangler tail threat-lens-app` during incident response. No Tail Worker or `[[tail_consumers]]` binding is configured for v2.
- **`/api/admin/health`** surfaces the count of application-level rate-limit and quota events in the last hour from Analytics Engine, with a row per source IP for incident correlation.

---

## 4.7 Phase 1 — Perimeter Lock Deliverable Order

These steps execute as the second half of Phase 1, after the workers are
scaffolded (Section 1.5).

1. Create the `corp_authorized_sources` IP List with the bootstrap entries
   from 4.1.4. Record the list ID in `RESOURCES.md`.
2. Deploy WAF custom rules `allow_method_safe`,
   `block_method_unexpected`, `block_offlist_traffic` to the staging zone
   first. Verify with three smoke tests:
   - In-list, GET `/` → 200.
   - Off-list, GET `/` → 403 with `code = "FORBIDDEN_NETWORK"`.
   - In-list, PUT `/` → 405 with `code = "METHOD_NOT_ALLOWED"`.
3. Deploy WAF rate-limit rules `rl_per_ip_general` and `rl_per_ip_admin`.
   Verify with a burst test driver that walks through each limit and
   confirms the 429 with correct `Retry-After` and envelope shape.
4. Configure Super Bot Fight Mode and HSTS via the dashboard.
5. Run `wrangler tail threat-lens-app` in a separate terminal to confirm
   live log streaming works during incident response. (Tail is a CLI
   capability and does not require a `[[tail_consumers]]` binding.)
6. Verify WAF and edge-level blocks are visible in the Cloudflare
   dashboard's Security Analytics view. Application-level quota Analytics
   are verified later in Phase 4, after the D1 ledgers and `/api/search`
   path exist.
7. Promote rules from staging to production (the IP List is shared; only
   the WAF rule and rate-limit rule deployment is per-zone).
8. Commit the resulting `docs/network/whitelist-ledger.md` and any zone
   IDs into `RESOURCES.md`.

The perimeter is now closed. Phase 2 (storage provisioning) proceeds
inside this protected envelope.
