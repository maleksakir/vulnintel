# Cloudflare Resource IDs

This file is the sealed record of all Cloudflare resource IDs provisioned for
Threat-Lens CVE Hub. Fill each `REPLACE_AFTER_PROVISIONING` placeholder with
the real ID immediately after running `wrangler` provisioning commands.
Never commit secrets here — only structural IDs (database IDs, namespace IDs,
index names). Secrets go in `wrangler secret put`.

---

## D1 Databases

| Environment | Database name     | Database ID                        |
|-------------|-------------------|------------------------------------|
| Production  | `cve_prod_d1`     | `REPLACE_AFTER_PROVISIONING`       |
| Staging     | `cve_staging_d1`  | `REPLACE_AFTER_PROVISIONING`       |

**Provision command:**
```sh
wrangler d1 create cve_prod_d1
wrangler d1 create cve_staging_d1
```

---

## Vectorize Indexes

| Environment | Index name                  | Dimensions | Metric  |
|-------------|-----------------------------|------------|---------|
| Production  | `cve-vector-index`          | 768        | cosine  |
| Staging     | `cve-vector-index-staging`  | 768        | cosine  |

**Provision command:**
```sh
wrangler vectorize create cve-vector-index --dimensions=768 --metric=cosine
wrangler vectorize create cve-vector-index-staging --dimensions=768 --metric=cosine
```

---

## KV Namespaces

| Environment | Binding | Namespace name              | Namespace ID                       |
|-------------|---------|-----------------------------|------------------------------------|
| Production  | `CACHE` | `cve_cache_prod`            | `REPLACE_AFTER_PROVISIONING`       |
| Staging     | `CACHE` | `cve_cache_staging`         | `REPLACE_AFTER_PROVISIONING`       |

**Provision command:**
```sh
wrangler kv namespace create cve_cache_prod
wrangler kv namespace create cve_cache_staging
```

---

## Queues

| Environment | Queue name                  | DLQ name                      |
|-------------|-----------------------------|-------------------------------|
| Production  | `cve-ingest-retry`          | `cve-ingest-dlq`              |
| Staging     | `cve-ingest-retry-staging`  | `cve-ingest-dlq-staging`      |

**Provision command:**
```sh
wrangler queues create cve-ingest-retry
wrangler queues create cve-ingest-dlq
wrangler queues create cve-ingest-retry-staging
wrangler queues create cve-ingest-dlq-staging
```

---

## Analytics Engine Datasets

| Environment | Binding     | Dataset name                    |
|-------------|-------------|---------------------------------|
| Production  | `ANALYTICS` | `cve_analytics_dataset`         |
| Staging     | `ANALYTICS` | `cve_analytics_dataset_staging` |

Analytics Engine datasets are created automatically on first write. No
provisioning command is required — confirm they appear in the Cloudflare
dashboard after the first ingest run.

---

## Cloudflare IP List

| Name                      | Type | Purpose                             |
|---------------------------|------|-------------------------------------|
| `corp_authorized_sources` | IP   | WAF allowlist — corp network ranges |

**Provision via dashboard:** Account → Security → IP Lists → Create.
Alternatively:
```sh
curl -X POST "https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/rules/lists" \
  -H "Authorization: Bearer {API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name":"corp_authorized_sources","kind":"ip","description":"Corp authorized network ranges"}'
```

Capture the returned `id` and record it here:

| List name                 | List ID                              |
|---------------------------|--------------------------------------|
| `corp_authorized_sources` | `REPLACE_AFTER_PROVISIONING`         |

---

## Post-provisioning checklist

After filling all IDs above:

1. Update `apps/app/wrangler.toml` — replace both `REPLACE_AFTER_PROVISIONING` values (D1 prod + KV prod).
2. Update `apps/ingest/wrangler.toml` — replace both `REPLACE_AFTER_PROVISIONING` values (D1 prod + KV prod).
3. Update the staging blocks in both `wrangler.toml` files for the staging IDs.
4. Run `wrangler deploy --env staging --dry-run` for both workers to confirm bindings resolve.
5. Apply the D1 migrations: `wrangler d1 migrations apply cve_prod_d1` and `cve_staging_d1`.
6. Provision secrets via `wrangler secret put` per §1.4.4.
