#!/bin/bash
#
# This will only work when connected to devnet.

if [ $# -ne 2 ]; then
	echo "USAGE: $0 [wallet/miner integer] [amount_of_sol]"
	exit 1
fi
source ./ore_env.sh $1

echo Requesting an airdrop of $2 SOL...
echo ------------------------------------------------------------------
solana config set --url ${RPC_URL} >/dev/null
solana airdrop -v $2 ${KEY}
echo ------------------------------------------------------------------
echo Wallet now has $(solana -k ${KEY} balance) available
