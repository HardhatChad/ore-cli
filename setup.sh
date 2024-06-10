#!/bin/bash

solana config set -u devnet

echo "Welcome to Ore Miner Setup. I'm going to run some checks to see if you have prerequisites installed." | fold -s -w 80
echo ""; echo "Please read all instructions CAREFULLY. This is all important."; echo ""

function test_solana_cli {
	echo "Testing if solana cli is installed."
	if command -v solana > /dev/null 2>&1; then
		echo "solana cli installed, OK"
	else
		while true; do
			SOLANA_INSTALL_MSG="solana cli is either not installed or not on PATH.  \
			solana cli is required for ore mining. Would you like me to install it now? If no, program will exit"
			echo $SOLANA_INSTALL_MSG | fold -s -w 80
			echo "Enter [y/n]"
			read install1
			if [ $install1 = "y" ]; then
				echo "Installing solana cli. You will see other logging messages from the solana cli being installed."
				sh -c "$(curl -sSfL https://release.solana.com/stable/install)"
				export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
			elif [ $install1 = "n" ]; then
				echo "Exiting program."
				exit 0
			else 
				echo "Invalid input, try again."
			fi
		done
	fi
}

test_solana_cli

function test_rust {
	echo "Testing if rust is installed"
	if command -v cargo > /dev/null 2>&1; then
		echo "Rust installed, OK"
	else
		while true; do
			echo "Rust is not installed or not on path."
			echo "Rust is required for ore mining. Would you like me to install it now? If no, program will exit"
			echo "Enter [y/n]"
			read install2
			if [ $install2 = "y" ]; then
				echo "You will see other logging messages from Rust being installed"
				curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
			elif [ $install2 = "n" ]; then
				echo "Exiting program."
				exit 0
			else
				echo "Invalid input, try again."
			fi
		done
	fi
}

test_rust

function test_ore_cli {
	echo "Testing if ore-cli is installed"
	if command -v ore > /dev/null 2>&1; then
		echo "ore-cli installed, OK"
	else
		echo "ore-cli is not installed or not on path."
		echo "Now installing ore-cli. You will see other logging messages from ore-cli."
		cargo install ore-cli
		export PATH="$HOME/.cargo/bin:$PATH"
	fi
}

test_ore_cli 

NUM_PROCESSORS=$(nproc)
NUM_MINERS=$((NUM_PROCESSORS - 2))

function build_accounts {
	while true; do
		echo ""; 
		BUILD_ACCOUNTS_MSG="Your PC has $NUM_PROCESSORS processors. The maximum recommended is one account per CPU, but we \
		must leave some space for other operations on the PC, so we should leave two processors free. \
		To follow this recommendation, type a for accept. To generate just one account for mining, enter 1. To ignore this \
		recommendation, type d for deny and provide the number of accounts to generate."
		echo $BUILD_ACCOUNTS_MSG | fold -s -w 80; echo ""
		echo "a) accept"; 
		echo "1) one account"; 
		echo "d) deny, provide alternatives"; 
		echo ""
		read choice2

		# TO DO: check whether the keys we're going to create exist already
		if [ "$choice2" == "a" ]; then
			echo "You will have to either set a password for $NUM_MINERS keys, or just press enter a bunch to skip setting passwords"
			pubkey_list=()

			# There are three conditions: the proposed key doesn't exist, the proposed key does exist and the user wants to overwrite,
			# or the key exists and the the user does not want to overwrite.
			for ((i=1; i<=$NUM_MINERS; i++)) do
				if [ -e "/home/user/.config/solana/id$i.json"]; then 
					echo "Key in $HOME/.config/solana/id$i.json already exists. Overwrite?"
					echo "[y/n]"
					read overwrite
					if [ "$overwrite" == "y" ]; then
						solana-keygen new -o $HOME/.config/solana/id$i.json --force
						solana config set -k ~/.config/solana/id$i.json > /dev/null
						pubkey_list+=($(solana address))
					else
						echo "Ok, not overwriting this key, but adding it to the list of miners to use."
						solana config set -k ~/.config/solana/id$i.json > /dev/null
						pubkey_list+=($(solana address))
					fi
				else 
					solana-keygen new -o $HOME/.config/solana/id$i.json
					solana config set -k ~/.config/solana/id$i.json > /dev/null
					pubkey_list+=($(solana address))
				fi
			done
			break
		elif [ "$choice2" == "1" ]; then
			echo "Ok, generating one account. Provide a password for the account or press enter for none."
			pubkey_list=()
			solana-keygen new -o /home/user/.config/solana/id$i.json
			solana config set -k ~/.config/solana/id$i.json > /dev/null
			pubkey_list+=($(solana address))
			NUM_MINERS=1
			break
		elif [ "$choice2" == "d" ]; then
			echo "OK, you need to enter the number of accounts you want"
			echo "Number of accounts: "
			read num_accounts
			NUM_MINERS=$num_accounts
			
			echo "You will have to either set a password for $NUM_MINERS keys, or just press enter a bunch to skip setting passwords"
			pubkey_list=()
			for ((i=1; i<=$NUM_MINERS; i++)) do
				if [ -e "/home/user/.config/solana/id$i.json" ]; then 
					echo "Key in $HOME/.config/solana/id$i.json already exists. Overwrite?"
					echo "[y/n]"
					read overwrite
					if [ "$overwrite" == "y" ]; then
						solana-keygen new -o $HOME/.config/solana/id$i.json --force
						solana config set -k ~/.config/solana/id$i.json > /dev/null
						pubkey_list+=($(solana address))
					else
						echo "Ok, not overwriting this key, but adding it to the list of miners to use."
						solana config set -k ~/.config/solana/id$i.json > /dev/null
						pubkey_list+=($(solana address))
					fi
				else 
					solana-keygen new -o $HOME/.config/solana/id$i.json
					solana config set -k ~/.config/solana/id$i.json > /dev/null
					pubkey_list+=($(solana address))
				fi
			done
			break
		else 
			echo "Invalid choice."
		fi
	done
}

build_accounts 

function fund_accounts {
	FUND_MSG="I have generated $NUM_MINERS private keys labelled id#.json in the directroy ~/.config/solana/ for you. \
	They will now be backed up by creating a tar file containing all of them, placed in your home directory." 
	echo ""; echo $FUND_MSG | fold -s -w 80; echo ""
	echo "*	*	*	*	*	*	*	*	*	*	*	*	*"; echo ""
	echo "Now this part is REALLY important!"; echo ""
	echo "IF YOU LOSE THIS FILE, YOU MAY LOSE ALL YOUR SOL AND YOUR ORE."; echo ""
	FUND_MSG2="I realize this is a lot private keys to keep track of, but you need to do it. Put it on a thumb drive \
	or something. Do you understand?"
	echo $FUND_MSG2 | fold -s -w 80; echo ""
	while true; do
		echo "Press y for 'I got it' and proceed. Press n to exit the program."
		echo "[y/n]"; echo ""
		read choice3
		echo ""
		if [ "$choice3" == "y" ]; then

			tar -cf keys.tar *
			mv keys.tar ~
			echo "Remember, I placed a file named keys.tar in your home director which is here: $(echo ~)"
			echo "Don't screw this up."; echo ""
			break
		elif [ "$choice3" == "n" ]; then 
			echo "It's ok. You weren't ready to accept the responsibility."
			exit 0
		else 
			echo "Invalid choice."
		fi
	done
	MIN_SOL=$(echo "scale=5; $NUM_MINERS * 0.025" | bc)
	FUND_MSG3="The next thing we need to do is fund one of the accounts to use to pay for fees. This program will then disburse \
	the funds to the rest of the accounts, so we need to get the amount right.  Each account should have a minimum of 0.025 \
	SOL, or you'll run out fairly quickly. You generated $NUM_MINERS keys. That means you'll need $MIN_SOL SOL at a \
	minimum."
	echo $FUND_MSG3 | fold -s -w 80
	solana config set -k ~/.config/solana/id1.json > /dev/null
	MAIN_ACCOUNT=$(solana address)
	while true; do
		FUND_MSG4="You need to fund this address $MAIN_ACCOUNT with $MIN_SOL SOL, and then I will divide it into all the other \
		accounts. I will pause while you fund the initial account. Press c to continue once you have sent the necessary \
		SOL to $MAIN_ACCOUNT and are ready to proceed. Type e to exit program." 
		echo $FUND_MSG4 | fold -s -w 80; echo ""
		echo "c) to continue"
		echo "e) to exit the program"
		read choice4
		echo ""
		if [ "$choice4" = "c" ]; then
			echo "Checking balance on main account "
			MAIN_ACCT_BAL=$(solana balance | awk '{print $1}')
			if [ $(echo "$MAIN_ACCT_BAL == 0" | bc) -eq 1 ]; then
				echo "Main account balance is 0 still, try again."
			elif [ $(echo "$MAIN_ACCT_BAL > 0" | bc) -eq 1 ] && [ $(echo "scale=5; $MAIN_ACCT_BAL < $MIN_SOL" | bc) -eq 1 ]; then
				FUND_MSG4="You have $MAIN_ACCT_BAL SOL in your wallet, but this is less than the recommended minimum of $MIN_SOL \
				SOL. Send some more." 
				echo $FUND_MSG4 | fold -s -w 80
			elif [ $(echo "$MAIN_ACCT_BAL >= $MIN_SOL" | bc) -eq 1 ]; then
				echo "Ok, id1.json has $MAIN_ACCT_BAL SOL which is greater than the minimum recommended $MIN_SOL SOL"
				SOL_PER_MINER=$(echo "scale=5; $MAIN_ACCT_BAL / $NUM_MINERS" | bc )
				break
			fi
		elif [ $choice4 == "e" ]; then
			echo "Exiting program."
			exit 0
		else 
			echo "Invalid input. Try again."
		fi
	done
}

fund_accounts

function disburse_sol {
	while true; do
		DISBURSE_MSG="Now I will disburse the SOL in the main account $MAIN_ACCOUNT across the rest of the so they all have \
		enough to pay fees."
		echo ""; echo $DSBRS_MSG | fold -s -w 80

		# Double check it's set to acct 1 that has the SOL in it
		solana config set -k ~/.config/solana/id1.json > /dev/null
		MAIN_ACCT_BAL=$(echo $(solana balance) | awk '{print $1}')
		AMT_TO_TRANSFER=$( echo "scale=5; $MAIN_ACCT_BAL / $NUM_MINERS" | bc )
		DISBURSE_MSG2="Your main account now has $MAIN_ACCT_BAL SOL. I'm going to divide that equally across all miner accounts so \
		they all contain about $AMT_TO_TRANSFER SOL. Some of the transactions may fail, but will be retried automatically."
		echo $DISBURSE_MSG2 | fold -s -w 80
		echo ""; 
		DISBURSE_MSG3="Press s to confirm you want to distribute the SOL from your main account across the other $NUM_MINERS miner \
		accounts or type e to exit." 
		echo $DISBURSE_MSG3 | fold -s -w 80; echo ""
		DISBURSE_WARNING="*	*	* Take note: This is real SOL. You are authorizing the program to send it to your other accounts. \
		This is just like signing a transaction in a wallet."
		echo $DISBURSE_WARNING | fold -s -w 80; echo ""
		echo "s) Send the SOL"
		echo "e) Exit the program"
		read choice5
		echo ""

		if [ "$choice5" = "s" ]; then
			echo "Beginning transfers. This will take some time as they finalize, and especially if we need multiple retries."
			for ((i=1; i<${#pubkey_list[@]}; i++)) do
				solana transfer ${pubkey_list[i]} $AMT_TO_TRANSFER --allow-unfunded-recipient
			done
			echo "Checking that all accounts now have SOL for fees"; echo ""
			empty_accts=()
			SUCCESS_FLAG=false
			for ((i=0; i<${#pubkey_list[@]}; i++)) do 
				TEMP_BAL=$(solana balance ${pubkey_list[i]} | awk '{print $1}')
				if [ $(echo "$TEMP_BAL > 0" | bc) -eq 0 ]; then
					echo "${pubkey_list[i]} has a 0 balance. Will retry send up to 5 times."
					RETRY_COUNT=5
					while [ $RETRY_COUNT -gt 0 ]; do
						solana transfer ${pubkey_list[i]} $AMT_TO_TRANSFER --allow-unfunded-recipient
						TEMP_BAL=$(solana balance ${pubkey_list[i]} | awk '{print $1}')
						if [ $(echo "$TEMP_BAL > 0" | bc) -eq 1 ]; then
							break
						else 
							((RETRY_COUNT--))
						fi
					done
				fi
			done
			if [ ${#empty_accts[@]} = 0 ]; then
				SUCCESS_FLAG=true
			fi
			if $SUCCESS_FLAG = true; then
				echo "All accounts are now funded and setup is complete."
				echo "Here is a breakdown of the accounts, associated private keys, and their balances:"; echo ""
				echo "Pubkey                                        Private Key                Balance "
				for ((i=0; i<${#pubkey_list[@]}; i++)) do
					TEMP_BAL=$(solana balance ${pubkey_list[i]} | awk '{print $1}')
					echo "${pubkey_list[i]}  ~/.config/solana/id$((i + 1)).json  $TEMP_BAL SOL"
				done
				echo ""; echo "You can now run the ore_miner_controller.sh script to start/stop/interact with these miner accounts"
				echo "See you in the shafts!"
				break
			else
				DISBURSE_MSG4="Not all accounts could be successfully funded. Recommend you try manual transactions to fund the \
				remaining empty accounts. Here is the current state of all accounts so you can see which ones are still empty." 
				echo $DISBURSE_MSG4 | fold -s -w 80
				echo ""
				echo "Pubkey                                        Private Key                Balance "
				for ((i=0; i<${#pubkey_list[@]}; i++)) do
					TEMP_BAL=$(solana balance ${pubkey_list[i]} | awk '{print $1}')
					echo "${pubkey_list[i]}  ~/.config/solana/id$((i + 1)).json  $TEMP_BAL SOL"
				done
				echo "To fund the remaining empty accounts, import the private key located at ~/.config/solana/id1.json into a wallet."
				echo "Then send transactions manually to fund the empty accounts."
				echo "To show the private key for id1.json, use the command cat ~/.config/solana/id1.json"
				exit 0
			fi
		elif [ $choice5 = "e" ]; then
			exit 0
		else 
			echo "Please choose either to proceed with disbursing the funds or to exit."
		fi
	done
}

disburse_sol 

exit 0

