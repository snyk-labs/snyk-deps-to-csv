# snyk-deps-to-csv

collects all dependencies from all orgs in a group and outputs to a file `snyk-deps_<timestamp>.csv`

> To process all Snyk orgs in a group, ensure your token has group level permission.  If the token in use only has access to specific orgs in the group, only the data from those orgs will be retrieved.

## To run
install with `npm install`

build with `npm run build`

### Get all dependencies from all orgs in the specified group
```
node dist/index.js --token=$SNYK_TOKEN --group-id=$SNYK_GROUP
```

### Filter by 1 or more dependencies from all orgs in the specified group
```
node dist/index.js --token=$SNYK_TOKEN --group-id=$SNYK_GROUP \
     --dependency-list="ansi-regex@2.0.0,assert-plus@1.0.0"
```

### Filter by dependencies file from all orgs in the specified group (*nix example)
```
node dist/index.js --token=$SNYK_TOKEN --group-id=$SNYK_GROUP \
     --dependency-list="$(cat example-deps-files/log4j-core_deps.txt | xargs | sed -e 's/ /,/g')"
```

## Contributing
contributions are encouraged for this project, following the [contribution guidelines](.github/CONTRIBUTING.md)

## License
[License: Apache License, Version 2.0](LICENSE)
