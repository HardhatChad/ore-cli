#!/bin/bash
#
if [ $# -ne 1 ]; then
	echo "USAGE: $0 [wallet/miner integer]"
	exit 1
fi
source ./ore_env.sh $1

SHORT_KEY=$(basename ${KEY})

echo -n "`date +'%Y%m%d%H%M%S'` ${SHORT_KEY} "
balance=$(${ORE_BIN} --rpc ${RPC_URL} --keypair ${KEY} balance)
retval1=$?
if [ ${retval1} -ne 0 ]; then
	echo "ERROR: Failed to retrieve the balance"
	exit ${retval1}
fi
balanceVal=$(echo ${balance} | awk '{printf("%.11f", $2)}')
stakedVal=$(echo ${balance} | awk '{printf("%.11f", $5)}')
./coingeckoDownloadPrice.sh Ore quiet
oreDollars=$(cat ./currentPriceOfOre.txt)
balanceDollars=$(echo "${balanceVal} * ${oreDollars}" | bc )
balanceDollars=$(printf "%.2f" ${balanceDollars})
stakedDollars=$(echo "${stakedVal} * ${oreDollars}" | bc )
stakedDollars=$(printf "%.2f" ${stakedDollars})
echo "Wallet $1 ORE balance: ${balanceVal} ORE (\$${balanceDollars})	Staked: ${stakedVal} ORE (\$${stakedDollars})"
