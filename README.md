# snyk-deps-to-csv

collects all dependencies from all orgs in a group and outputs to a file `snyk-deps_<timestamp>.csv`

## to run
build with `npm run build`

run with
```
node dist/index.js --token=$SNYK_TOKEN --group-id=$SNYK_GROUP
```
