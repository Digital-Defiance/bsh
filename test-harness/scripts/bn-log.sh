#!/bin/sh
# Dump recent BrightNexus os_log output (subsystem
# org.digitaldefiance.brightchain.BrightNexus, category 'diag').
log show \
  --predicate 'subsystem == "org.digitaldefiance.brightchain.BrightNexus" AND category == "diag"' \
  --last 2m \
  --info 2>&1 \
  | tail -50
