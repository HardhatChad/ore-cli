#!/bin/bash
#
source ./ore_env.priv.sh

if [ $# -ne 1 ]; then
	echo USAGE: $0 [/path/to/new/wallet.json]
	echo The default wallet is normally something like ~/.config/solana/id.json
	exit 1
fi

WALLET_PATH=$1
if [ -f ${WALLET_PATH} ]; then
	echo ERROR: a wallet file already exists at ${WALLET_PATH}
	exit 1
fi

echo Attempting to create new solana wallet...${WALLET_PATH}
echo ------------------------------------------------------------------
solana config set --url ${RPC1} >/dev/null
solana-keygen new --outfile ${WALLET_PATH}
solana-keygen verify $(solana-keygen pubkey ${WALLET_PATH}) ${WALLET_PATH}
echo ------------------------------------------------------------------
echo Wallet has $(solana -k ${WALLET_PATH} balance) available
echo If you are connected to devnet, you can get airdropped some Sol after configuring your ore_env.priv.sh to use the new wallet for a miner:
echo "./airdropDevnetSol.sh [wallet/miner number] [amount_of_sol]"
echo "e.g    ./airdropDevnetSol.sh 1 0.5"
echo
echo ------------------------------------------------------------------
echo Write down and store the seed phrase above if you want to import and use this wallet somewhere else e.g. Phantom Wallet
echo You can also paste the contents of ${WALLET_PATH} into a wallet as your private key.
echo ${WALLET_PATH} contains your private key to the new solana wallet and should not be distributed to anyone if you value what is in the wallet.
echo $(solana-keygen pubkey ${WALLET_PATH}) is your wallet address for sending any tokens to.
echo ------------------------------------------------------------------

