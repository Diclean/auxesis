#!/bin/sh
# Fixture stdio MCP server for the catalog-pin test.
#
# It never speaks MCP: a correct install stays off, and a tampered artefact is
# refused before any child starts. The marker file is how the test proves the
# child never ran.
printf 'started\n' > "$(dirname "$0")/child-started"
exit 0
