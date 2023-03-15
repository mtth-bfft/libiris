#!/bin/sh
# Wrapper used by gitlab-ci to run compiled tests without `cargo` installed

exit_code=0
at_least_one=0
for f in $1/*; do
    [ -f $f ] || continue;
    echo
    echo "===== $f"
    at_least_one=1
    $f --nocapture || exit_code=$?
done
if [ "$at_least_one" -eq "0" ]; then
    echo No test found >&2
    exit 1
fi
exit $exit_code
