![Snyk logo](https://snyk.io/style/asset/logo/snyk-print.svg)

![snyk-oss-category](https://github.com/snyk-labs/oss-images/blob/main/oss-community.jpg)

# snyk-deps-to-csv

collects all dependencies from all orgs in a group and outputs to a CSV file `snyk-deps_<timestamp>.csv`, see an example [here](sample-output/snyk-deps_2022_01_05_05_40_39_59.csv).

> To process all Snyk orgs in a group, ensure your token has group level permission.  If the token in use only has access to specific orgs in the group, only the data from those orgs will be retrieved.

Please try to avoid running for all dependencies against your Snyk group(s) more than 1–2 times per day.

## Requirements

- Node.js 18 or later
- A Snyk API token with group-level access (see note above)
- `SNYK_TOKEN` and `SNYK_GROUP` environment variables, or pass `--token` and `--group-id`

## To run

```bash
npm install
npm run build
```

### Get all dependencies from all orgs in the specified group

```bash
node dist/index.js --token=$SNYK_TOKEN --group-id=$SNYK_GROUP
# or, with env vars only:
node dist/index.js
```

### Filter by 1 or more dependencies from all orgs in the specified group

```bash
node dist/index.js --token=$SNYK_TOKEN --group-id=$SNYK_GROUP \
     --dependency-list="ansi-regex@2.0.0,assert-plus@1.0.0"
```

### Rate limiting

The Snyk dependencies API allows up to **150 requests per minute** per user. This tool uses [snyk-request-manager](https://github.com/snyk-labs/snyk-request-manager) with a leaky-bucket limiter (~135 req/min) and automatic retries (including after HTTP 429). Avoid running unfiltered exports more than once or twice per day for large groups.

### Filter by dependencies file from all orgs in the specified group (*nix example)

Log4Shell:

```
node dist/index.js --token=$SNYK_TOKEN --group-id=$SNYK_GROUP \
     --dependency-list="$(cat example-deps-files/log4j-core_deps.txt | xargs | sed -e 's/ /,/g')"
```

Spring4Shell:

```
node dist/index.js --token=$SNYK_TOKEN --group-id=$SNYK_GROUP \
     --dependency-list="$(cat example-deps-files/spring4shell_deps.txt | xargs | sed -e 's/ /,/g')"
```

## Contributing
contributions are welcomed for this project, following the [contribution guidelines](.github/CONTRIBUTING.md)

## Issues
for any issues or questions, please submit a [github issue](https://github.com/snyk-tech-services/snyk-deps-to-csv/issues)

## License
[License: Apache License, Version 2.0](LICENSE)
