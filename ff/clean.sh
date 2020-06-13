#!/bin/bash

FILES="$(find . ! -name 'ff.go' ! -name 'ff_test.go' ! -name 'clean.sh' ! -name 'README.md' | -name '.')"
for f in ${FILES}; do
   rm -f "$f"
done
