#!/bin/bash

if [ $# -ne 2 ]; then
	echo "USAGE: $0 [wallet/miner integer] [amount to stake|all]"
	exit 1
fi
source ./ore_env.sh $1

balance=$(${ORE_BIN} --rpc ${RPC_URL} --keypair ${KEY} balance)
retval1=$?
balanceVal=$(echo ${balance} | awk '{printf("%.11f", $2)}')
./walletBalance.sh $1
if [ "${balanceVal}" = "0.00000000000" ]; then
	echo "=========================================================================================================="
	echo "Wallet $1 has no ORE available for staking."
	echo "=========================================================================================================="

else
	stakedVal=$(echo ${balance} | awk '{printf("%.11f", $5)}')
	oreDollars=$(cat ./currentPriceOfOre.txt)
	balanceDollars=$(echo "${balanceVal} * ${oreDollars}" | bc )
	balanceDollars=$(printf "%.2f" ${balanceDollars})
	stakedDollars=$(echo "${stakedVal} * ${oreDollars}" | bc )
	stakedDollars=$(printf "%.2f" ${stakedDollars})

	if [ "$2" = "all" ]; then
		amountToStake=""
	else
		amountToStake="--amount $2"
	fi

	echo "Wallet has \$${balanceDollars} ready to add to current stake \$${stakedDollars}"
	echo "----------------------------------------------------------------------------------------------------------"
	echo "Staking additional ${balanceVal} ORE...."
	balance=$(${ORE_BIN} --rpc ${RPC_URL} --keypair ${KEY} --priority-fee=${FEE} stake ${amountToStake})
	echo "=========================================================================================================="
	echo "The wallet balance after staking is now:"
	./walletBalance.sh $1
	echo "=========================================================================================================="
fi
