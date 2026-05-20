#!/usr/bin/env node

import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import { requestsManager } from 'snyk-request-manager';
import type { AxiosResponse } from 'axios';
import debugLib from 'debug';
import pMap from 'p-map';
import fs from 'fs';
import readline from 'readline';

const debug = debugLib('snyk:index');

/** V1 API: dependencies endpoint allows up to 150 requests/minute per user. */
const DEPENDENCIES_RATE_LIMIT_PER_MIN = 150;
/** Stay below the documented limit to leave headroom for retries after 429s. */
const RATE_LIMIT_SAFETY_FACTOR = 0.9;
const REQUEST_PERIOD_MS = Math.ceil(
  60_000 / (DEPENDENCIES_RATE_LIMIT_PER_MIN * RATE_LIMIT_SAFETY_FACTOR),
);
const REQUEST_BURST_SIZE = 1;
const DEPS_PER_PAGE = 1000;
const GROUP_ORGS_PER_PAGE = 100;
const ORG_PROCESS_CONCURRENCY = 3;

interface GroupOrg {
  id: string;
  slug: string;
  name: string;
}

interface DependencyProject {
  id: string;
  name: string;
}

interface Dependency {
  id?: string;
  name: string;
  version?: string;
  latestVersion?: string;
  latestVersionPublishedDate?: string;
  firstPublishedDate?: string;
  isDeprecated?: boolean;
  projects: DependencyProject[];
}

interface DependenciesResponse {
  results: Dependency[];
  total: number | string;
}

interface GroupOrgsResponse {
  orgs: GroupOrg[];
}

interface OrgJob {
  orgId: string;
  orgSlug: string;
  filterBody: string;
}

function timestamp(): string {
  const m = new Date();
  const pad = (n: number, len = 2): string => String(n).padStart(len, '0');
  return [
    m.getUTCFullYear(),
    pad(m.getUTCMonth() + 1),
    pad(m.getUTCDate()),
    pad(m.getUTCHours()),
    pad(m.getUTCMinutes()),
    pad(m.getUTCSeconds()),
    pad(m.getUTCMilliseconds(), 3),
  ].join('_');
}

const CSV_FILE = `snyk-deps_${timestamp()}.csv`;

const argv = yargs(hideBin(process.argv))
  .usage(
    `\nUsage: $0 [OPTIONS]
If no arguments are specified, values are picked up from environment variables.

If pointing to a self-hosted or on-premise instance of Snyk,
SNYK_API is required to be set in your environment,
e.g. SNYK_API=https://my.snyk.domain/api. If omitted, Snyk SaaS is used.`,
  )
  .options({
    token: {
      describe: 'Your Snyk API token. If not specified, taken from SNYK_TOKEN.',
      type: 'string',
      default: process.env.SNYK_TOKEN,
    },
    'group-id': {
      describe:
        'The id of the group to process. If not specified, taken from SNYK_GROUP.',
      type: 'string',
      default: process.env.SNYK_GROUP,
    },
    'dependency-list': {
      describe:
        'Comma-delimited list of dependencies to filter results for. If not specified, all dependencies are retrieved.',
      type: 'string',
    },
    concurrency: {
      describe: `Number of orgs to process in parallel (default ${ORG_PROCESS_CONCURRENCY}). Requests still respect the global rate limiter.`,
      type: 'number',
      default: ORG_PROCESS_CONCURRENCY,
    },
  })
  .demandOption(['token', 'group-id'])
  .help()
  .parseSync();

const groupId = argv['group-id'] as string;
const dependencyList = argv['dependency-list'] as string | undefined;
const orgConcurrency = argv.concurrency as number;

const requestManager = new requestsManager({
  snykToken: String(argv.token),
  userAgentPrefix: 'snyk-deps-to-csv',
  burstSize: REQUEST_BURST_SIZE,
  period: REQUEST_PERIOD_MS,
  maxRetryCount: 5,
});

function csvEscape(value: string | undefined | boolean): string {
  if (value === undefined || value === null) {
    return '';
  }
  const str = String(value);
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str.replace(/,/g, ';');
}

function writeToCSV(message: string): void {
  fs.appendFileSync(CSV_FILE, `${message}\n`);
}

function printProgress(progress: string): void {
  readline.cursorTo(process.stdout, 0);
  process.stdout.write(progress);
}

async function getGroupOrgs(): Promise<GroupOrg[]> {
  const orgs: GroupOrg[] = [];
  let page = 1;
  let hasMore = true;

  while (hasMore) {
    const response = (await requestManager.request({
      verb: 'GET',
      url: `/group/${groupId}/orgs?perPage=${GROUP_ORGS_PER_PAGE}&page=${page}`,
    })) as AxiosResponse<GroupOrgsResponse>;

    const batch: GroupOrg[] = response.data?.orgs ?? [];
    orgs.push(...batch);

    hasMore = batch.length >= GROUP_ORGS_PER_PAGE;
    page += 1;
  }

  debug(`found ${orgs.length} orgs in group ${groupId}`);
  return orgs;
}

async function fetchDependencyPages(
  orgId: string,
  filterBody: string,
): Promise<{ deps: Dependency[]; extraPageRequests: number }> {
  const baseUrl = `/org/${orgId}/dependencies?perPage=${DEPS_PER_PAGE}`;
  const first = (await requestManager.request({
    verb: 'POST',
    url: baseUrl,
    body: filterBody,
  })) as AxiosResponse<DependenciesResponse>;

  const data = first.data;
  const total = Number(data.total);
  if (!total) {
    return { deps: [], extraPageRequests: 0 };
  }

  let deps = data.results ?? [];
  const extraPageRequests = Math.max(0, Math.ceil(total / DEPS_PER_PAGE) - 1);

  if (extraPageRequests > 0) {
    const pageRequests = [];
    for (let page = 2; page <= extraPageRequests + 1; page++) {
      pageRequests.push({
        verb: 'POST' as const,
        url: `${baseUrl}&page=${page}`,
        body: filterBody,
      });
    }

    const results = (await requestManager.requestBulk(
      pageRequests,
    )) as AxiosResponse<DependenciesResponse>[];
    for (const result of results) {
      const pageData = result.data;
      deps = deps.concat(pageData.results ?? []);
    }
  }

  return { deps, extraPageRequests };
}

function writeOrgDependencies(
  orgSlug: string,
  orgId: string,
  deps: Dependency[],
): void {
  for (const dep of deps) {
    for (const project of dep.projects ?? []) {
      const projectUrl = `https://app.snyk.io/org/${orgSlug}/project/${project.id}`;
      writeToCSV(
        [
          csvEscape(orgSlug),
          csvEscape(orgId),
          csvEscape(dep.id),
          csvEscape(dep.name),
          csvEscape(dep.version),
          csvEscape(dep.latestVersion),
          csvEscape(dep.latestVersionPublishedDate),
          csvEscape(dep.firstPublishedDate),
          csvEscape(dep.isDeprecated?.toString()),
          csvEscape(project.name),
          csvEscape(project.id),
          csvEscape(projectUrl),
        ].join(','),
      );
    }
  }
}

async function processOrg(
  job: OrgJob,
  stats: {
    processed: number;
    total: number;
    pagedRequests: number;
    depCount: number;
  },
): Promise<void> {
  const { deps, extraPageRequests } = await fetchDependencyPages(
    job.orgId,
    job.filterBody,
  );

  stats.pagedRequests += extraPageRequests;
  stats.depCount += deps.length;
  writeOrgDependencies(job.orgSlug, job.orgId, deps);

  stats.processed += 1;
  printProgress(
    ` - ${stats.processed}/${stats.total} orgs completed (extra paged requests: ${stats.pagedRequests}, total deps: ${stats.depCount})`,
  );
}

async function processOrgs(
  queue: OrgJob[],
  concurrency: number,
): Promise<void> {
  const stats = {
    processed: 0,
    total: queue.length,
    pagedRequests: 0,
    depCount: 0,
  };

  console.log(`Processing ${queue.length} orgs for dependency data...`);

  await pMap(queue, (job) => processOrg(job, stats), { concurrency });
}

async function app(): Promise<void> {
  debug(`groupId: ${groupId}`);

  let filterBody = '{}';
  if (dependencyList) {
    const deps = String(dependencyList)
      .split(',')
      .map((d) => d.trim())
      .filter(Boolean);
    filterBody = JSON.stringify({ filters: { dependencies: deps } });
    console.log(
      `Filtering dependencies for:\n${JSON.stringify(deps, null, 2)}\n`,
    );
  }

  writeToCSV(
    'org-slug,org-id,dep-id,dep-name,dep-version,latest-version,latest-version-published-date,first-published-date,is-deprecated,project-name,project-id,project-url',
  );

  const orgs = await getGroupOrgs();
  if (orgs.length === 0) {
    console.error(
      `No organizations found for group ${groupId}. Check SNYK_GROUP and token permissions.`,
    );
    process.exit(1);
  }

  const queue: OrgJob[] = orgs.map((org) => ({
    orgId: org.id,
    orgSlug: org.slug,
    filterBody,
  }));

  await processOrgs(queue, orgConcurrency);
  console.log(`\nWrote results to ${CSV_FILE}`);
}

app().catch((err: unknown) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
