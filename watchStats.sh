#!/bin/bash
#
if [[ $# -eq 0 || $# -gt 2 ]]; then
	echo "USAGE: $0 [wallet/miner integer] [log version 1-6]"
	exit 1
fi

source ./ore_env.sh $1
VERSION=${2:-1}

STATS_LOGFILE_BASE="./logs/${MINER_NAME// /_}"
watch -n 5 "echo Displaying log $(ls ${STATS_LOGFILE_BASE}--${VERSION}--*.log); cat ${STATS_LOGFILE_BASE}--${VERSION}--*.log"