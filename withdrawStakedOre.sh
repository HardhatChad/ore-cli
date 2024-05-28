#!/bin/bash

if [ $# -ne 2 ]; then
	echo "USAGE: $0 [wallet/miner integer] [amount_to_unstake|all]"
	exit 1
fi
source ./ore_env.sh $1

cutoff=0.10
balance=$(${ORE_BIN} --rpc ${RPC_URL} --keypair ${KEY} balance)
retval1=$?
balanceVal=$(echo ${balance} | awk '{printf("%.11f", $2)}')
stakedVal=$(echo ${balance} | awk '{printf("%.11f", $5)}')

./walletBalance.sh $1
if [ "${stakedVal}" = "0.0000000000" ]; then
	echo "=========================================================================================================="
	echo "Wallet $1 has no staked ore to withdraw."
	echo "=========================================================================================================="
else
	oreDollars=$(cat ./currentPriceOfOre.txt)
	balanceDollars=$(echo "${balanceVal} * ${oreDollars}" | bc )
	balanceDollars=$(printf "%.2f" ${balanceDollars})
	stakedDollars=$(echo "${stakedVal} * ${oreDollars}" | bc )
	stakedDollars=$(printf "%.2f" ${stakedDollars})

	if [ "$2" = "all" ]; then
		amountToWithdraw=""
	else
		amountToWithdraw="--amount $2"
	fi

	echo "This wallet can currently withdraw up to ${stakedVal} staked ORE worth \$${stakedDollars}."

	if [ $(echo "${stakedDollars} > ${cutoff}" | bc -l) -eq 1 ]; then
		echo Your rewards of \$${stakedDollars} are greater than \$${cutoff} so proceeding to claim rewards.
		echo "----------------------------------------------------------------------------------------------------------"
		${ORE_BIN} --keypair ${KEY} --rpc ${RPC_URL} --priority-fee ${FEE} claim ${amountToWithdraw}
		echo "=========================================================================================================="
		echo "The wallet balance after withdrawing the staked ore is:"
		./walletBalance.sh $1
		echo "=========================================================================================================="
	else
		echo "=========================================================================================================="
		echo "Sorry, there in not enough staked ORE to justify spending SOL to withdraw it."
		echo "Please try again when you have more than \$${cutoff} waiting to be withdrawn."
	echo "=========================================================================================================="
	fi
fi
