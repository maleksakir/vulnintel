# IP Allowlist Ledger — `corp_authorized_sources`

This file is the authoritative source of truth for all IP ranges in the
`corp_authorized_sources` Cloudflare IP List. Every entry must have:
- A CIDR block
- An owner (team or individual)
- A purpose
- An expiry date or `permanent`

Changes must be reviewed by the security team before being applied to the
Cloudflare IP List via the `runIpListPrune` ingest pipeline or manually.

---

## Active Entries

| CIDR               | Owner                | Purpose                          | Expiry        |
|--------------------|----------------------|----------------------------------|---------------|
| _(add entries)_    | _(team or person)_   | _(e.g. "office network egress")_ | _(YYYY-MM-DD or permanent)_ |

---

## Change Log

| Date       | CIDR               | Action  | Requested by       | Reason                     |
|------------|--------------------|---------|--------------------|----------------------------|
| _(pending)_| _(pending)_        | Added   | _(pending)_        | Initial allowlist setup    |

---

## Expiry convention

The `runIpListPrune` ingest cron (04:00 UTC daily, §5.1.1) reads entries
with a comment field formatted as `expires:YYYY-MM-DD`. Entries without this
comment field are treated as permanent and never pruned automatically.

To add a temporary entry, set the comment in the Cloudflare IP List UI or API to:

```
expires:2026-12-31 | <owner> | <purpose>
```

The prune pipeline parses the `expires:` prefix and deletes any entry whose
expiry date is in the past.

---

## Emergency revocation

To immediately revoke an IP range:
1. Remove the entry from the Cloudflare IP List via the dashboard or API.
2. Record the removal in the Change Log above.
3. Notify the security team via the standard incident channel.

The WAF rule referencing `corp_authorized_sources` takes effect within
seconds of the list update (Cloudflare propagates IP List changes globally
in under 30 seconds).
