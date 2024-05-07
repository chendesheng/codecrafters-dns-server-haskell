#!/bin/bash
export CODECRAFTERS_SUBMISSION_DIR=$(pwd)
export CODECRAFTERS_TEST_CASES_JSON=$(cat test_cases.json)
(cd $GOPATH/dns-server-tester/ && ./dist/main.out)