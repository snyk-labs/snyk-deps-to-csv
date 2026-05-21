![Snyk logo](https://snyk.io/style/asset/logo/snyk-print.svg)

![snyk-oss-category](https://github.com/snyk-labs/oss-images/blob/main/oss-community.jpg)

# snyk-deps-to-csv

collects all dependencies from all orgs in a group and outputs to a CSV file `snyk-deps_<timestamp>.csv`, see an example [here](sample-output/snyk-deps_2022_01_05_05_40_39_59.csv).

> To process all Snyk orgs in a group, ensure your token has group level permission.  If the token in use only has access to specific orgs in the group, only the data from those orgs will be retrieved.

Please try to avoid running for all dependencies against your Snyk group(s) more than 1–2 times per day.

## Requirements

- Node.js 18 or later
- A Snyk API token with group-level access (see note above)
- Environment variables (or CLI flags where noted below)

## Environment variables

This tool uses [snyk-request-manager](https://github.com/snyk-labs/snyk-request-manager) (v1.9.3+), which reads the same configuration as the Snyk CLI. Set **`SNYK_API`** to the V1 API base URL for your tenant region before running.

| Variable | Required | Description |
| --- | --- | --- |
| `SNYK_API` | **Yes** | V1 API base URL (must include `/v1`). Defaults to US-01 if unset in some setups; set explicitly to avoid calling the wrong region. |
| `SNYK_TOKEN` | Yes* | Snyk API token (or pass `--token`) |
| `SNYK_GROUP` | Yes* | Group ID to export (or pass `--group-id`) |

\*Required via env or CLI.

### `SNYK_API` — default and regional endpoints

Use the V1 base URL that matches where your Snyk account lives ([Snyk V1 API docs](https://docs.snyk.io/snyk-api/v1-api)):

| Region | `SNYK_API` value |
| --- | --- |
| SNYK-US-01 (default) | `https://api.snyk.io/v1` |
| SNYK-US-02 | `https://api.us.snyk.io/v1` |
| SNYK-EU-01 | `https://api.eu.snyk.io/v1` |
| SNYK-AU-01 | `https://api.au.snyk.io/v1` |

For self-hosted or on-prem Snyk, set `SNYK_API` to your instance V1 API root (for example `https://my.snyk.domain/api/v1`).

**Example (US default):**

```bash
export SNYK_API="https://api.snyk.io/v1"
export SNYK_TOKEN="your-api-token"
export SNYK_GROUP="your-group-id"
```

**Example (EU):**

```bash
export SNYK_API="https://api.eu.snyk.io/v1"
export SNYK_TOKEN="your-api-token"
export SNYK_GROUP="your-group-id"
```

## Snyk V1 API endpoints used

All requests go to `{SNYK_API}` + path below (HTTPS only). This tool does not call the REST API (`/rest/...`).

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/group/{groupId}/orgs?perPage=100&page={page}` | List organizations in the group (paginated, `page` starts at 1) |
| `POST` | `/org/{orgId}/dependencies?perPage=1000` | List dependencies for an org (first page; optional JSON body with `filters.dependencies`) |
| `POST` | `/org/{orgId}/dependencies?perPage=1000&page={page}` | Additional dependency pages when `total` exceeds 1000 (`page` ≥ 2) |

**Permissions (from Snyk API):**

- Group orgs: READ on the group and LIST organizations in the group
- Dependencies: View Organization, View Project, View Project Snapshot

**Dependencies rate limit:** up to 150 requests per minute per user (see [Rate limiting](#rate-limiting) below).

## To run

```bash
npm install
npm run build
```

### Get all dependencies from all orgs in the specified group

```bash
export SNYK_API="https://api.snyk.io/v1"
node dist/index.js --token=$SNYK_TOKEN --group-id=$SNYK_GROUP
# or, with env vars only:
node dist/index.js
```

### Filter by 1 or more dependencies from all orgs in the specified group

```bash
export SNYK_API="https://api.snyk.io/v1"
node dist/index.js --token=$SNYK_TOKEN --group-id=$SNYK_GROUP \
     --dependency-list="ansi-regex@2.0.0,assert-plus@1.0.0"
```

### Rate limiting

The Snyk dependencies API allows up to **150 requests per minute** per user. This tool uses [snyk-request-manager](https://github.com/snyk-labs/snyk-request-manager) with a leaky-bucket limiter (~135 req/min) and automatic retries (including after HTTP 429). Avoid running unfiltered exports more than once or twice per day for large groups.

### Filter by dependencies file from all orgs in the specified group (*nix example)

Log4Shell:

```bash
export SNYK_API="https://api.snyk.io/v1"
node dist/index.js --token=$SNYK_TOKEN --group-id=$SNYK_GROUP \
     --dependency-list="$(cat example-deps-files/log4j-core_deps.txt | xargs | sed -e 's/ /,/g')"
```

Spring4Shell:

```bash
export SNYK_API="https://api.snyk.io/v1"
node dist/index.js --token=$SNYK_TOKEN --group-id=$SNYK_GROUP \
     --dependency-list="$(cat example-deps-files/spring4shell_deps.txt | xargs | sed -e 's/ /,/g')"
```

## Contributing
contributions are welcomed for this project, following the [contribution guidelines](.github/CONTRIBUTING.md)

## Issues
for any issues or questions, please submit a [github issue](https://github.com/snyk-tech-services/snyk-deps-to-csv/issues)

## License
[License: Apache License, Version 2.0](LICENSE)
