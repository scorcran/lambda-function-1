#!/usr/bin/env bash

FILENAME=$1

cd /app/src
zip "/zipped-package/$FILENAME.zip" "$FILENAME.py"
cd /app/src/package/
zip -ur "/zipped-package/$FILENAME.zip" vendored
exit 1
