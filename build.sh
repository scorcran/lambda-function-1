#!/usr/bin/env bash

FILENAME=$1

docker build -t python-lambda .

docker run -it --rm --name py-lamb -v "$PWD/src/package:/zipped-package" python-lambda $FILENAME
