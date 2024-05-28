#!/bin/bash
#

source ./ore_env.priv.sh

if [ $# -lt 1 ]; then
	echo "USAGE: $0 [Ore|Sol] [quiet]"
	exit 1
fi


if [[ ! "$1" == "Ore" && ! "$1" == "Sol" ]]; then
	echo "USAGE: $0 [Ore|Sol]"
	exit 1
fi
QUIET=0

if [ $# -eq 2 ]; then
	QUIET=1
fi

FILENAME=currentPriceOf${1}.txt

TOKENNAME="solana"
if [ "$1" = "Ore" ]; then
	TOKENNAME="ore"
fi

if [ -z ${COINGECKO_APIKEY} ]; then
	if [ ${QUIET} -eq 0 ]; then
		echo "ERROR: you do not appear to have a unique COINGECKO_APIKEY defined in your ore_env.priv.sh. Please obtain one to use the coingecko api to obtain a token price."
		echo "See https://docs.coingecko.com/reference/setting-up-your-api-key for further information"
		echo Failed to obtain current ORE price: writing \$0.00 to ${FILENAME}
	fi
	echo 0.00 > ${FILENAME}
	exit 0
fi

# Lookup the current price
for i in 1 2 3 4 5
do
	PRICE=$(curl -s "https://api.coingecko.com/api/v3/simple/price?ids=${TOKENNAME}&vs_currencies=usd&x_cg_demo_api_key=${COINGECKO_APIKEY}" | grep -o '"usd":[0-9.]*' | awk -F: '{print $2}')
	if [ "${PRICE}" == "" ]; then
		if [ ${QUIET} -eq 0 ]; then
			echo "`date +'%Y-%m-%d %H:%M:%S'` Failed to download the current $1 price :("
		fi
		PRICE="0.00"
	else
		break
	fi
done
if [ ${QUIET} -eq 0 ]; then
	echo Downloading current $1 price: writing \$${PRICE} to ${FILENAME}
fi
echo ${PRICE} > ${FILENAME}
