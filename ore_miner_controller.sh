# This script assumes all the keys in $HOME/.config/solana/ are to be used for ore mining

mkdir 
solana config set -u devnet
RPC_PROVIDER=$(grep '^RPC_PROVIDER=' ore_miner_controller.config | cut -d'=' -f2)
NUM_THREADS=$(grep '^NUM_THREADS=' ore_miner_controller.config | cut -d'=' -f2)
PRIORITY_FEE=$(grep '^PRIORITY_FEE=' ore_miner_controller.config | cut -d'=' -f2)
RPC_MSG="RPC Provider"
THREAD_MSG="thread count"
FEE_MSG="priority fee"
PIDS=()

while true; do

    cat << "EOF"

 _____   ____    ____               ______  __  __  ____    ____
/\  __`\/\  _`\ /\  _`\     /'\_/`\/\__  _\/\ \/\ \/\  _`\ /\  _`\
\ \ \/\ \ \ \L\ \ \ \L\_   /\      \/_/\ \/\ \ `\\ \ \ \L\_\ \ \L\ \
 \ \ \ \ \ \ ,  /\ \  _\L  \ \ \__\ \ \ \ \ \ \ , ` \ \  _\L\ \ ,  /
  \ \ \_\ \ \ \\ \\ \ \L\   \ \ \_/\ \ \_\ \_\ \ \`\ \ \ \L\ \ \ \\ \
   \ \_____\ \_\ \_\ \____/  \ \_\\ \_\/\_____\ \_\ \_\ \____/\ \_\ \_\
    \/_____/\/_/\/ /\/___/    \/_/ \/_/\/_____/\/_/\/_/\/___/  \/_/\/ /

        ___                                  
       /   \                                        
      /_____\                                       
      |  _  |    ___                                
      | |_| |   /   \                               
      |_____|     /  \                              
     /       \   /   |                              
    |         | /                                   
    |    |    |/                                    
    |    |    |                                     
    |    |    |                                     
     \_______/                                      
        | |                                         
        | |                    _/^^^^\__            
        | |                   /         \           
        | |                  /           \          
        | |                 |             |  

EOF

    WELCOME_MSG="Welcome to Ore Miner Controller.  This program is designed to leverage multiple keys in the \
    $HOME/.config/solana/ directory to run ore miners.  If you haven't already set up the number you want \
    re-run the setup.sh script. If you're ready to proceed, choose c"
    echo $WELCOME_MSG | fold -s -w 80; echo ""
    echo "c) Continue"
    echo "e) Exit"
    read choice

    if [ "$choice" == "c" ]; then
        echo ""
        break
    elif [ "$choice" == "e" ]; then
        echo "Goodbye"
        exit 0
    else
        echo "Invalid choice."
    fi
done

function check_balances {
    KEYFILES=$(ls ~/.config/solana/ | grep -E "id[0-9]+\.json")
    echo "Here are the balances for the ore miner accounts stored in ~/.config/solana/"; echo ""
    echo "Pubkey                                            Private Key        SOL         ORE "
    for KEY in $KEYFILES; do
        FULLPATH="$HOME/.config/solana/$KEY" 
        solana config set -k $FULLPATH > /dev/null
        SOL_BAL=$(solana balance | awk '{print $1}')
        ORE_BAL=$(ore balance --keypair $FULLPATH --rpc $RPC_PROVIDER | awk '{print $1}')
        PUBKEY=$(solana address)
        echo "$PUBKEY      $KEY       $SOL_BAL      $ORE_BAL"
        
    done
    echo ""
}

function change_settings {
    while true; do
        echo "Current $1 $2 is: $3"
        echo "Set new $1 $2? Enter c to continue, q to quit to main menu:"; echo ""
        echo "c) continue"; echo "q) quit to main menu"; echo ""
        read choice3; echo ""
        if [ "$choice3" == "c" ]; then
            echo "Enter new $1 $2:"; read NEW_VAL; echo ""
            if [ "$1" == "RPC" ]; then
                sed -i "s#^RPC_PROVIDER=.*#RPC_PROVIDER=$NEW_VAL#" ore_miner_controller.config 
                RPC_PROVIDER=$(grep '^RPC_PROVIDER=' ore_miner_controller.config | cut -d'=' -f2)
                echo "$1 $2 now set to $RPC_PROVIDER for all accounts."; echo ""
            elif [ "$1" == "thread" ]; then
                sed -i "s#^NUM_THEADS=.*#NUM_THEADS=$NEW_VAL#" ore_miner_controller.config 
                NUM_THREADS=$(grep '^NUM_THREADS=' ore_miner_controller.config | cut -d'=' -f2)
                echo "$1 $2 now set to $NUM_THREADS for all accounts."; echo ""
            elif [ "$1" == "priority" ]; then
                sed -i "s#^PRIORITY_FEE=.*#PRIORITY_FEE=$NEW_VAL#" ore_miner_controller.config
                PRIORITY_FEE=$(grep '^PRIORITY_FEE=' ore_miner_controller.config | cut -d'=' -f2)
                echo "$1 $2 now set to $PRIORITY_FEE for all accounts."; echo ""
            fi
            echo ""
            break
        elif [ "$choice3" == "q" ]; then
            echo "Keeping current $1 $2 of $3"
            echo "Returning to main menu"
            break
        else
            echo "Invalid selection, try again"
        fi
    done
    echo ""
}

while true; do
    echo "Please select from the following options: "
    echo "1) Check settings"
    echo "2) Start miners"
    echo "3) Stop miners"
    echo "4) Set RPC provider"
    echo "5) Set number of threads"
    echo "6) Set priority fee"
    echo "7) Check balances"
    echo "8) Collect all ore"
    echo "9) Display miner status"
    echo "0) Exit"; echo ""

    read choice2

    case $choice2 in
        "1") 
            echo ""; echo "Current configuration: "; echo ""
            echo "RPC Provider: $RPC_PROVIDER"
            echo "Number of threads: $NUM_THREADS"
            echo "Priority fee: $PRIORITY_FEE"; echo ""
        ;;

        "2") 
            KEYFILES=$(ls ~/.config/solana/ | grep -E "id[0-9]+\.json")
            echo ""; echo "Starting miners..."
            for KEY in $KEYFILES; do
                FULLPATH="$HOME/.config/solana/$KEY" 
                MINER_NUM=$(echo $KEY | grep -oE "[0-9]+")
                LOG_FILE="ore$MINER_NUM.log"
                COMMAND="ore --rpc $RPC_PROVIDER --keypair $FULLPATH --priority-fee $PRIORITY_FEE mine --threads $NUM_THREADS"
                $COMMAND >> $LOG_FILE 2>&1 &
                PIDS+=($!)
            done
            echo "All miners started in separate processes."; echo ""
        ;;

        "3")
            echo ""; echo "Stopping miners..."
            for PID in "${PIDS[@]}"; do
                echo "Killing PID $PID"
                kill -9 $PID
            done
            
            # Confirm that all ore miners have been killed
            sleep 2
            if pgrep -f "ore --rpc" > /dev/null; then 
                echo "There are still ore miners running. Try running the command again"
            else
                echo "All ore miners have been killed."
                PIDS=()
            fi
            echo ""
        
        ;;

        "4")
            change_settings $RPC_MSG $RPC_PROVIDER
        ;; 

        "5")
            change_settings $THREAD_MSG $NUM_THREADS
        ;;

        "6")
            change_settings $FEE_MSG $PRIORITY_FEE
        ;;

        "7")
            echo ""; echo "Checking balances..."
            check_balances
        ;;

        "8")
            echo ""; echo "Collecting all the ore from your miners..."
            KEYFILES=$(ls ~/.config/solana/ | grep -E "id[0-9]+\.json")
            for KEY in $KEYFILES; do
                FULLPATH="$HOME/.config/solana/$KEY" 
                ore claim --keypair $FULLPATH
            done
            echo ""
        ;;

        "9")
            echo ""; echo "pid   cmd"
            if pgrep -f "ore --rpc" > /dev/null; then 
                pgrep -f "ore --rpc" -a
            else
                echo "There are no miners running right now."
            fi
            echo ""
        ;;

        "0")
            echo ""; echo "Goodbye"
            exit 0
        ;;
    esac 
done

exit 0