#!/usr/bin/env node

import * as yargs from 'yargs';
import { requestsManager } from 'snyk-request-manager';
import * as debugLib from 'debug';
import * as pMap from 'p-map';
import * as fs from 'fs';
import { exit } from 'process';
import { error } from 'console';

const readline = require('readline');
const debug = debugLib('snyk:index');

var m = new Date();

const LOG_TIMESTAMP =
    m.getUTCFullYear() +
    '_' +
    ('0' + (m.getUTCMonth() + 1)).slice(-2) +
    '_' +
    ('0' + m.getUTCDate()).slice(-2) +
    '_' +
    ('0' + m.getUTCHours()).slice(-2) +
    '_' +
    ('0' + m.getUTCMinutes()).slice(-2) +
    '_' +
    ('0' + m.getUTCSeconds()).slice(-2) +
    '_' +
    ('0' + m.getUTCMilliseconds()).slice(-2) +
    '';

const LOG_FILE="snyk-deps-to-csv.log"
const CSV_FILE=`snyk-deps_${LOG_TIMESTAMP}.csv`

const argv = yargs
  .usage(
    `\nUsage: $0 [OPTIONS]
                If no arguments are specified, values will be picked up from environment variables.\n
                If pointing to a self-hosted or on-premise instance of Snyk,
                SNYK_API is required to be set in your environment,
                e.g. SNYK_API=https://my.snyk.domain/api. If omitted, then Snyk SaaS is used.`,
  )
  .options({
    'token': {
      describe: `your snyk token 
                       if not specified, then taken from SNYK_TOKEN`,
      demandOption: true,
    },
    'group-id': {
      describe: `the id of the group to process 
                       if not specified, then taken from SNYK_GROUP`,
      demandOption: true,
    },
    'dependency-list': {
      describe: `comma-delimited list of dependencies to filter results for 
                       if not specified, then all dependencies are retrieved`,
      demandOption: false,
    }
  })
  .help().argv;

const token = argv['token']
const groupId = argv['group-id']
const dependencyList = argv['dependency-list']


const requestManager = new requestsManager({
  snykToken: String(argv['token']),
  userAgentPrefix: 'snyk-deps-to-csv',
  burstSize: 1,
  period: 425
});


function writeToCSV(message: string) {
    //console.log(message);
    fs.appendFileSync(
      CSV_FILE,
      `${message}\n`,
    );
  }
  
function printProgress(progress: string) {
  readline.cursorTo(process.stdout, 0)
  process.stdout.write(`${progress}`);
}

function buildLicenseString(licenses: Array<any>) {
  if (licenses == null || licenses.length == 0) {
    return '';
  }

  return '"' + licenses.map(function (license: any) {
    return license.license;
  }).join(',') + '"';
}

async function processQueue(queue: any[], ) {
  let numProcessed: number = 0;
  let numAdditionallyFetched: number = 0;
  let totalDepsCount: number = 0;
  console.log(`processing ${queue.length} orgs for dependency data...`);

  try {
      queue.forEach(async function(url) {
        let totalDeps: any = []
        const result = await requestManager.request(url)
        if (result.data.total != "0") { 
            //console.log(`total deps found: ${result.data.total}`)
            totalDeps = result.data.results

            let additionalPages: number = Math.floor(Number(result.data.total)/1000)
            numAdditionallyFetched += additionalPages
          
            if (additionalPages > 0) {
                //splice additional data to base data
                totalDeps = totalDeps.concat(await getMoreDepsPages(url.url, url.body, additionalPages))
            } 

            for (const dep of totalDeps) {
                //debug(`dep: ${JSON.stringify(dep)}`)
                for (const project of dep.projects) {
                    let projectUrl = `https://app.snyk.io/org/${url.orgSlug}/project/${project.id}` 

                    let depLicenses = buildLicenseString(dep.licenses);
                    writeToCSV(`${url.orgSlug},${url.orgId},${dep.id?.replace(',',';')},${dep.name},${dep.version?.replace(',',';')},${depLicenses},${dep.latestVersion},${dep.latestVersionPublishedDate},${dep.firstPublishedDate},${dep.isDeprecated},${project.name},${project.id},${projectUrl}`)
                }
                
            }

            totalDepsCount += totalDeps.length
        }
        printProgress(` - ${++numProcessed}/${queue.length} completed (additional paged requests: ${numAdditionallyFetched}, total deps: ${totalDepsCount})`);
      })

  } catch (err: any) {
      console.log(`error occurred: ${err}`);

  }
}

async function getMoreDepsPages(baseURL: string, filterBody: any, additionalPages: number) {

    let deps: any = []
    let queue = []

    // build request list for concurrency
    for(var  page = 2; page <= (additionalPages+1); page++) {
          let url = `${baseURL}&page=${page}`
          debug(`queueing url: ${url}`)
          queue.push({
              verb: 'POST',
              url: `${url}`,
              body: filterBody
            });
    }

    try {
      const results: any[] = await requestManager.requestBulk(queue);
      //console.log(`found ${res.data.results.length} results for ${JSON.stringify(reqData)}`)
      results.forEach(function (result) {
        deps = deps.concat(result.data.results)
        //console.log(result.data.results)
      })

    } 
    catch (err: any) {
      console.log(`error occurred: ${err}`);
    }

    return deps
}

async function getSnykOrgs () {
    let orgs: any = []

    try {
        let response = await requestManager.request({
            verb: 'GET',
            url: `/orgs`,
          });
        orgs = response.data.orgs
        orgs = orgs.filter(function (el: any)
        {
          return el.group && el.group.id == groupId ;
        }
        );
        
        debug(`orgs: ${JSON.stringify(orgs)}`)
      } catch (err: any) {
        console.log(err);
      }
    
      return orgs
}

async function app() {
    debug(`token: ${token}`)
    debug(`groupId: ${groupId}`)

    let filterBody = {}

    if (dependencyList) { 
      debug(`dependencyList: ${dependencyList}`)
      try {
        filterBody = {"filters": {"dependencies": String(dependencyList).split(',')}}
      }
      catch(err: any) {
        console.log(`error parsing dependency-list, exiting...`)
        exit(1)
      }
      console.log(`filtering dependencies for ${JSON.stringify(String(dependencyList).split(','), null, 2)}\n`)

    }
    writeToCSV(`org-slug,org-id,dep-id,dep-name,dep-version,dep-licenses,latest-version,latest-version-published-date,first-published-date,is-deprecated,project-name,project-id,project-url`)
    let queue = [];
    // get all the orgs for the snyk group
    const orgs = await getSnykOrgs();
    debug(`orgs: ${orgs}`)
    for (const org of orgs) {
        debug(`org.id: ${org.id}`)
        queue.push({
            verb: 'POST',
            url: `/org/${org.id}/dependencies?perPage=1000`,
            body: filterBody,
            orgId: org.id,
            orgSlug: org.slug
      });
    }
    await processQueue(queue)
    console.log(`writing results to ${CSV_FILE}\n`)
}

app();
