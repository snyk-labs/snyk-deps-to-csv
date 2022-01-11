#!/usr/bin/env node

import * as yargs from 'yargs';
import { requestsManager } from 'snyk-request-manager';
import * as debugLib from 'debug';
import * as pMap from 'p-map';
import * as fs from 'fs';
import { exit } from 'process';

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

async function processQueue(queue: any[], ) {
  let totalDeps: any = []
  var numProcessed: number = 0;
  var numAdditionallyFetched: number = 0;
  console.log(`processing ${queue.length} orgs for dependency data...`);
  await pMap(
    queue,
    async (reqData) => {
      try {
        const res = await requestManager.request(reqData);

        totalDeps = res.data.results

        let additionalPages: number = Math.floor(Number(res.data.total)/1000)
        numAdditionallyFetched += additionalPages
        
        if (additionalPages > 0) {
            var moreDeps = await getMoreDepsPages(reqData.url, reqData.body, additionalPages)
            //splice additional data to base data
            totalDeps = totalDeps.concat(moreDeps)
        } 

        if (res.data.total != "0") { 
            for (const dep of totalDeps) {
                debug(`dep: ${JSON.stringify(dep)}`)
                for (const project of dep.projects) {
                    // debug(`for org ${reqData.orgId}, found project ${project.id},${project.name}`)
                    let projectUrl = `https://app.snyk.io/org/${reqData.orgSlug}/project/${project.id}` 
                    writeToCSV(`${reqData.orgSlug},${reqData.orgId},${dep.id.replace(',',';')},${dep.name},${dep.version.replace(',',';')},${project.name},${project.id},${projectUrl}`)
                }
            }
        }

        totalDeps = []

        printProgress(` - ${++numProcessed}/${queue.length} completed (additional paged requests: ${numAdditionallyFetched})`);

      } catch (err: any) {
        console.log(`${err}`);
      }
    },
    { concurrency: 10 },
  );

}

async function getMoreDepsPages(baseURL: string, filterBody: any, additionalPages: number) {
    let deps: any = []
    for(var  page = 2; page <= (additionalPages+1); page++) {
      try {
          let url = `${baseURL}&page=${page}`
          debug(`fetching url: ${url}`)
          let response = await requestManager.request({
              verb: 'POST',
              url: `${url}`,
              body: filterBody
            });
          debug(`found ${response.data.results.length} results`)
          deps = deps.concat(response.data.results)
          //debug(`additional deps: ${JSON.stringify(deps)}`)
      } catch (err: any) {
          console.log(err);
      }
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
    writeToCSV(`org-slug,org-id,dep-id,dep-name,dep-version,project-name,project-id,project-url`)
    let userMembershipQueue = [];
    // get all the orgs for the snyk group
    const orgs = await getSnykOrgs();
    debug(`orgs: ${orgs}`)
    for (const org of orgs) {
        debug(`org.id: ${org.id}`)
        userMembershipQueue.push({
            verb: 'POST',
            url: `/org/${org.id}/dependencies?perPage=1000`,
            body: filterBody,
            orgId: org.id,
            orgSlug: org.slug
      });
    }
    await processQueue(userMembershipQueue)
    console.log(`\n\nresults written to ${CSV_FILE}`)
}

app();



