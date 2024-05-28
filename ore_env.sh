#!/bin/bash
#

if [ $# -ne 1 ]; then
	echo "USAGE: $0 [integer representing the miner number in ore_env.priv.sh]"
	exit 1
fi

source ./ore_env.priv.sh

# Determine the values of the miner from the parameter number passed and ore_env.priv.sh
RPCNO=RPC$1
KEYNO=KEY$1
THREADSNO=THREADS$1
FEENO=PRIORITY_FEE$1
WATTAGEIDLENO=MINER_WATTAGE_IDLE$1
WATTAGEBUSYNO=MINER_WATTAGE_BUSY$1
BUFFER_TIMENO=BUFFER_TIME$1
DESIRED_DIFFICULTY_LEVELNO=DESIRED_DIFFICULTY_LEVEL$1

RPC_URL=${!RPCNO}
KEY=${!KEYNO}
THREADS=${!THREADSNO}
FEE=${!FEENO}
BUFFER_TIME=${!BUFFER_TIMENO}


MINER_NAME="Miner ${1}"
MINER_WATTAGE_IDLE=${!WATTAGEIDLENO}
MINER_WATTAGE_BUSY=${!WATTAGEBUSYNO}
MINER_COST_PER_KILOWATT_HOUR=${ELECTRICITY_COST_PER_KILOWATT_HOUR}
MINER_DESIRED_DIFFICULTY_LEVEL=${!DESIRED_DIFFICULTY_LEVELNO}

# echo RPC_URL:							${RPC_URL}
# echo KEY: 							${KEY}
# echo THREADS:							${THREADS}
# echo FEE:								${FEE}
# echo BUFFER_TIME:						${BUFFER_TIME}
# echo MINER_WATTAGE_IDLE:				${MINER_WATTAGE_IDLE}
# echo MINER_WATTAGE_BUSY:				${MINER_WATTAGE_BUSY}
# echo MINER_COST_PER_KILOWATT_HOUR:	${MINER_COST_PER_KILOWATT_HOUR}
# echo MINER_DESIRED_DIFFICULTY_LEVEL:	${MINER_DESIRED_DIFFICULTY_LEVEL}

# Check that all required parameters have been specified for the miner number passed
if [ -v ${RPC_URL} ]; then
	echo "ERROR: No RPC URL has been detected for miner $1. Please configure RPC$1 in your ore_env.priv.sh file."
	exit 2
fi
if [ -v ${KEY} ]; then
	echo "ERROR: No key has been detected for miner $1. Please configure KEY$1 in your ore_env.priv.sh file."
	exit 3
fi
if [ ! -f ${KEY} ]; then
	echo "ERROR: the keyfile could not be located: ${KEY}. Please configure KEY$1 in your ore_env.priv.sh file."
	exit 4
fi
if [ ${THREADS} -lt 1 ]; then
	echo "ERROR: No number of threads has been detected for miner $1. Please configure THREADS$1 in your ore_env.priv.sh file."
	exit 5
fi
if [ -v ${FEE} ]; then
	if [[ ! "${FEE}" =~ ^[0-9]+$ ]]; then
		echo "ERROR: No default priority fee has been specified for miner $1. Please configure PRIORITY_FEE$1 in your ore_env.priv.sh file."
		exit 5
	fi
fi

# check that the ore-cli binary is present
ORE_BIN=./target/release/ore
if [ ! -f ${ORE_BIN} ]; then
	echo "Sorry, the ore-cli file does not exist: ${ORE_BIN}"
	exit 2
fi


rotateLogFile() {
	origIndex=$1
	newIndex=$2
	ls ${STATS_LOGFILE_BASE}--${origIndex}--*.log >/dev/null 2>&1
	if [ $? -eq 0 ]; then
		for oldlog in $(ls ${STATS_LOGFILE_BASE}--${origIndex}--*.log); do
			if [ -f "${oldlog}" ]; then
				newlog="${oldlog/--${origIndex}--/--${newIndex}--}"
				echo "Rotating old log file: ${oldlog} -> ${newlog}"
				mv ${oldlog} ${newlog}
				if [ ${origIndex} -eq 1 ]; then
					echo -e "*** This is an archived log file ***\n\n$(cat ${newlog})" > ${newlog}
				fi
			fi
		done
	fi
}
removeLogFile() {
	origIndex=$1
	ls ${STATS_LOGFILE_BASE}--${origIndex}--*.log >/dev/null 2>&1
	if [ $? -eq 0 ]; then
		for oldlog in $(ls ${STATS_LOGFILE_BASE}--${origIndex}--*.log); do
			if [ -f "${oldlog}" ]; then
				echo "Removing old log file: ${oldlog}"
				rm "${oldlog}"
			fi
		done
	fi
}
