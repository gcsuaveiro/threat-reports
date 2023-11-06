#!/bin/bash

if [ $# -lt 1 ]; then
	echo "Usage: bash $0 file.md"
	exit -1
fi

OUTFILE=$(echo $1 |sed -e "s/\.md/\.pdf/g")
echo "Processing $1 into $OUTFILE"

docker run --rm \
       --volume "$(pwd):/data" \
       --user $(id -u):$(id -g) \
       pandoc/extra $1 -o $OUTFILE --template template/gcs --from markdown -V lang=pt --number-sections

echo "Done"
