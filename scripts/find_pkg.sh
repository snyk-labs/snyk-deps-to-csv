#!/bin/bash

# find_pkg.sh
# Search a snyk-deps-to-csv export for a specific package (and optionally, package version)"

function usage {
	log ""
	log "Usage:"
	log "$0 -csv <input file> -depname <package name> [ -depver <package version> ]"
	log ""
	log "To save your results, redirect stdout to a file."
	log ""
	log "Example:"
	log "   $0 -csv \"snyk-deps.csv\" -depname pysnyk > pysnyk-results.csv"
	log ""
}

function log {
	echo $1 1>&2
}

function init_defaults {
	if [[ -z $DEP_CSV ]]; then
		DEP_CSV="./snyk-deps.csv"
	fi
	PKG_NAME=""
	PKG_VER="*"
}

function parse_args {
	while test $# -gt 0; do
		case "$1" in
			-csv)
				shift
				DEP_CSV=$1
				shift
				;;
			-depname)
				shift
				PKG_NAME=$1
				shift
				;;
			-depver)
				shift
				PKG_VER=$1
				shift
				;;
			*)
				usage
				exit 1;
				;;
		esac
	done

	if [[ -z $PKG_NAME ]]; then
		log ""
		log "$0: package name is required"
		usage
		exit 1
	fi
}

function find_deps {
	log "Searching \"$DEP_CSV\" for package \"$PKG_NAME\" @ version \"$PKG_VER\"  ..."
	log "."

	# CSV format:
	# org-slug,org-id,dep-id,dep-name,dep-version,project-name,project-id,project-url
	#

	echo "Snyk Organization,Package Name,Package Version,Snyk Project Name,Snyk Project URL"
	grep -i -e "$PKG_NAME," $DEP_CSV | cut -d, -f 1,4,5,10,12 | grep -e ",$PKG_VER," | sort

	log "."
	log "Done."
}

# Main body
init_defaults
parse_args $@
find_deps
