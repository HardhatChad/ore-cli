#!/bin/bash

if [ $# -ne 1 ]; then
	echo "USAGE: $0 [wallet/miner integer]"
	exit 1
fi
source ./ore_env.sh $1

echo Unsure what this command does yet so disabling
exit 1

echo ------------------------------------------------------------------------------------------
cutoff=0.10
./coingeckoDownloadPrice.sh Ore
./walletBalance.sh $1
balance=$(${ORE_BIN} --rpc ${RPC_URL} --keypair ${KEY} balance)
retval1=$?
balanceVal=$(echo ${balance} | awk '{printf("%.11f", $2)}')
stakedVal=$(echo ${balance} | awk '{printf("%.11f", $5)}')
oreDollars=$(cat ./currentPriceOfOre.txt)
balanceDollars=$(echo "${balanceVal} * ${oreDollars}" | bc )
stakedDollars=$(echo "${stakedVal} * ${oreDollars}" | bc )
echo "Wallet $1 ${balanceVal} ORE (\$${balanceDollars})	staked=${stakedVal} ORE (\$${stakedDollars})"
echo ------------------------------------------------------------------------------------------
echo "Closing accounts...."
balance=$(${ORE_BIN} --rpc ${RPC_URL} --keypair ${KEY} --priority-fee=${FEE} close)
echo ------------------------------------------------------------------------------------------
echo After closing the accounts...
./walletBalance.sh $1
