#!/bin/bash

if [ $# -lt 1 ]; then
	echo "Usage: bash $0 report_dir"
	exit -1
fi

echo "Processing $1/report.md"

docker run --rm \
       --volume "$(pwd)/$1:/data" \
       --volume "$(pwd)/template:/data/template" \
       --user $(id -u):$(id -g) \
       pandoc/extra report.md -o report-$(date +"%F.%H:%M").pdf --template template/gcs --from markdown -V lang=pt --number-sections

echo "Done"
