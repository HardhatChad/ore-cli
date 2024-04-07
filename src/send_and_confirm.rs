use std::{
    time::Duration,
};

use solana_client::{
    client_error::{ClientError, ClientErrorKind, Result as ClientResult},
    nonblocking::rpc_client::RpcClient,
    rpc_config::{RpcSendTransactionConfig, RpcSimulateTransactionConfig},
};
use solana_transaction_status::Encodable;
use solana_program::instruction::Instruction;
use solana_sdk::{
    commitment_config::{CommitmentConfig, CommitmentLevel},
    compute_budget::ComputeBudgetInstruction,
    signature::{Signature, Signer},
    transaction::Transaction,
};
use solana_transaction_status::{TransactionConfirmationStatus, UiTransactionEncoding};
use std::io::Write;

const NONCE_RENT: u64 = 1_447_680;

pub struct NonceManager {
    pub rpc_client: std::sync::Arc<RpcClient>,
    pub authority: solana_sdk::pubkey::Pubkey,
    pub capacity: u64,
    pub idx: u64,
}
async fn get_recent_priority_fee_estimate(request: GetPriorityFeeEstimateRequest) -> f64 {
    let api_key = std::env::var("HELIUS_API_KEY").unwrap();
    let response = reqwest::Client::new()
        .post("https://mainnet.helius-rpc.com/?api-key=".to_owned() + &api_key)
        .body(serde_json::json!(
            {
                "jsonrpc": "2.0",
                "id": "1",
                "method": "getPriorityFeeEstimate",
                "params": 
            [
                request
            ]
        }
        ).to_string())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let request = serde_json::from_str::<serde_json::Value>(&response).unwrap();
request["result"]["priorityFeeEstimate"].as_f64().unwrap_or(1200.0)
}

#[derive(serde::Deserialize, serde::Serialize)]

struct GetPriorityFeeEstimateRequest {
  transaction: Option<String>,   // estimate fee for a serialized txn
  account_keys: Option<Vec<String>>, // estimate fee for a list of accounts
  options: Option<GetPriorityFeeEstimateOptions>
}

#[derive(serde::Deserialize, serde::Serialize)]
struct GetPriorityFeeEstimateOptions {
	priority_level: Option<PriorityLevel>, // Default to MEDIUM
	include_all_priority_fee_levels: Option<bool>, // Include all priority level estimates in the response
	transaction_encoding: Option<UiTransactionEncoding>, // Default Base58
	lookback_slots: Option<u8>, // number of slots to look back to calculate estimate. Valid number are 1-150, defualt is 150
}

#[derive(serde::Deserialize, serde::Serialize)]
enum PriorityLevel {
	NONE, // 0th percentile
	LOW, // 25th percentile
	MEDIUM, // 50th percentile
	HIGH, // 75th percentile
	VERY_HIGH, // 95th percentile
  // labelled unsafe to prevent people using and draining their funds by accident
	UNSAFE_MAX, // 100th percentile 
	DEFAULT, // 50th percentile
}
#[derive(serde::Deserialize)]
struct GetPriorityFeeEstimateResponse {
  priority_fee_estimate: Option<MicroLamportPriorityFee>,
  priority_fee_levels: Option<MicroLamportPriorityFeeLevels>
}

type MicroLamportPriorityFee = f64;
#[derive(serde::Deserialize)]
struct MicroLamportPriorityFeeLevels {
	none: f64,
	low: f64,
	medium: f64,
	high: f64,
	very_high: f64,
	unsafe_max: f64,
}

impl NonceManager {
    pub fn new(rpc_client: std::sync::Arc<RpcClient>, authority: solana_sdk::pubkey::Pubkey, capacity: u64) -> Self {
        NonceManager {
            rpc_client,
            authority,
            capacity,
            idx: 0,
        }
    }

    pub async fn try_init_all(&mut self, payer: &solana_sdk::signer::keypair::Keypair) -> Vec<Result<Signature, solana_client::client_error::ClientError>> {
        let (blockhash, _) = self.rpc_client
            .get_latest_blockhash_with_commitment(CommitmentConfig::finalized()).await
            .unwrap_or_default();
        let mut sigs = vec![];
        for _ in 0..self.capacity {
            let nonce_account = self.next();
            let ixs = self.maybe_create_ixs(&nonce_account.pubkey()).await;
            if ixs.is_none() {
                continue;
            }
            let ixs = ixs.unwrap();
            let tx = Transaction::new_signed_with_payer(&ixs, Some(&payer.pubkey()), &[&payer, &nonce_account], blockhash);
            sigs.push(self.rpc_client.send_transaction(&tx).await);
        }
        sigs
    }

    fn next_seed(&mut self) -> u64 {
        let ret = self.idx;
        self.idx = (self.idx + 1) % self.capacity;
        ret
    }

    pub fn next(&mut self) -> solana_sdk::signer::keypair::Keypair {
        let seed = format!("Nonce:{}:{}", self.authority.clone(), self.next_seed());
        let seed = sha256::digest(seed.as_bytes());
        let kp = solana_sdk::signer::keypair::keypair_from_seed(&seed.as_ref()).unwrap();
        kp
    }

    pub async fn maybe_create_ixs(&mut self, nonce: &solana_sdk::pubkey::Pubkey) -> Option<Vec<Instruction>> {
        if solana_client::nonce_utils::nonblocking::get_account(&self.rpc_client, nonce).await.is_ok() {
            None
        } else {
            Some(solana_sdk::system_instruction::create_nonce_account(
                    &self.authority,
                    &nonce,
                    &self.authority,
                    NONCE_RENT,
            ))
        }
    }
}
use crate::Miner;

const RPC_RETRIES: usize = 0;
const SIMULATION_RETRIES: usize = 4;
const GATEWAY_RETRIES: usize = usize::MAX;
const CONFIRM_RETRIES: usize = usize::MAX;

impl Miner {
    pub async fn send_and_confirm(
        &self,
        ixs: &[Instruction],
        dynamic_cus: bool,
        skip_confirm: bool,
    ) -> ClientResult<Signature> {
        let signer = self.signer();
        let client =
            std::sync::Arc::new(RpcClient::new_with_commitment(self.cluster.clone(), CommitmentConfig::finalized()));
        let mut nonce_manager = NonceManager::new(client.clone(), signer.pubkey(), 10 as u64);
            nonce_manager.try_init_all(&signer).await; 

            nonce_manager.try_init_all(&signer).await; 


            nonce_manager.try_init_all(&signer).await; 


            nonce_manager.try_init_all(&signer).await; 


            nonce_manager.try_init_all(&signer).await; 


        // Return error if balance is zero
        let balance = client
            .get_balance_with_commitment(&signer.pubkey(), CommitmentConfig::finalized())
            .await
            .unwrap();
        if balance.value <= 0 {
            return Err(ClientError {
                request: None,
                kind: ClientErrorKind::Custom("Insufficient SOL balance".into()),
            });
        }

        // Build tx
        let (hash, slot) = client
            .get_latest_blockhash_with_commitment(CommitmentConfig::finalized())
            .await
            .unwrap();
        let send_cfg = RpcSendTransactionConfig {
            skip_preflight: true,
            preflight_commitment: Some(CommitmentLevel::Finalized),
            encoding: Some(UiTransactionEncoding::Base64),
            max_retries: Some(RPC_RETRIES),
            min_context_slot: Some(slot),
        };
        
       let msg = solana_sdk::message::Message::new_with_nonce( 
        ixs.to_vec(),
        Some(&signer.pubkey()), 
            &nonce_manager.next().pubkey(), 
            &signer.pubkey());

        let mut tx = Transaction::new_unsigned(msg.clone());
        
        // Simulate if necessary
        if dynamic_cus {
            let mut sim_attempts = 0;
            'simulate: loop {
                let sim_res = client
                    .simulate_transaction_with_config(
                        &tx,
                        RpcSimulateTransactionConfig {
                            sig_verify: false,
                            replace_recent_blockhash: true,
                            commitment: Some(CommitmentConfig::finalized()),
                            encoding: Some(UiTransactionEncoding::Base64),
                            accounts: None,
                            min_context_slot: None,
                            inner_instructions: false,
                        },
                    )
                    .await;
                match sim_res {
                    Ok(sim_res) => {
                        if let Some(err) = sim_res.value.err {
                            println!("Simulaton error: {:?}", err);
                            sim_attempts += 1;
                            if sim_attempts.gt(&SIMULATION_RETRIES) {
                                return Err(ClientError {
                                    request: None,
                                    kind: ClientErrorKind::Custom("Simulation failed".into()),
                                });
                            }
                        } else if let Some(units_consumed) = sim_res.value.units_consumed {
                            println!("Dynamic CUs: {:?}", units_consumed);
                            let cu_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(
                                units_consumed as u32 + 1000,
                            );
                            let priority_fee = get_recent_priority_fee_estimate(GetPriorityFeeEstimateRequest {
                                transaction: Some(bs58::encode(bincode::serialize(&tx).unwrap()).into_string()),
                                account_keys: None,
                                options: Some(GetPriorityFeeEstimateOptions {
                                    priority_level: Some(PriorityLevel::HIGH),
                                    include_all_priority_fee_levels: Some(false),
                                    transaction_encoding: Some(UiTransactionEncoding::Base58),
                                    lookback_slots: Some(150),
                                }),
                            }).await;
                            let cu_price_ix =
                                ComputeBudgetInstruction::set_compute_unit_price(priority_fee as u64);
                            let mut final_ixs = vec![];
                            final_ixs.extend_from_slice(&[cu_budget_ix, cu_price_ix]);
                            final_ixs.extend_from_slice(ixs);
                            tx = Transaction::new_with_payer(&final_ixs, Some(&signer.pubkey()));
                            break 'simulate;
                        }
                    }
                    Err(err) => {
                        println!("Simulaton error: {:?}", err);
                        sim_attempts += 1;
                        if sim_attempts.gt(&SIMULATION_RETRIES) {
                            return Err(ClientError {
                                request: None,
                                kind: ClientErrorKind::Custom("Simulation failed".into()),
                            });
                        }
                    }
                }
            }
        }

        // Submit tx
        tx.sign(&[&signer], hash);
        let mut attempts = 0;
            let res = client.send_transaction_with_config(&tx, send_cfg.clone()).await;
            match res {
                Ok(sig) => {
                    if skip_confirm {
                        return Ok(sig);
                    }
                    let client_clone = client.clone();
                    let sig_clone = sig;
                    let tx_clone = tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = confirm_transaction(client_clone, &mut vec![sig_clone], tx_clone).await {
                            println!("Background confirmation error: {:?}", e);
                        }
                    });
                    Ok(sig)
                }
                Err(err) => {
                    println!("Error: {:?}", err);
                    attempts += 1;
                    if attempts.gt(&GATEWAY_RETRIES) {
                        return Err(ClientError {
                            request: None,
                            kind: ClientErrorKind::Custom("Max retries".into()),
                        });
                    }
                    return Err(err);
                }
        }
    }
    }


// Async function to confirm a transaction in the background
async fn confirm_transaction(client: std::sync::Arc<RpcClient>, sigs : &mut Vec<Signature>,
tx: Transaction
) -> Result<(), ClientError> {
    let mut attempts = 0;
    loop {
        // Use async sleep to delay without blocking
       tokio::time::sleep(Duration::from_secs((1.1*attempts as f64) as u64)).await;
        println!("Checking transaction statuses {:?}", sigs);
        match client.get_signature_statuses(&sigs).await {
            Ok(statuses) => {
                // Process the statuses to check if the transaction is confirmed...
                for status in statuses.value.iter() {
                    if let Some(status) = status {
                        if let Some(confirmation_status) = &status.confirmation_status {
                            match confirmation_status {
                                TransactionConfirmationStatus::Confirmed
                                | TransactionConfirmationStatus::Finalized => {
                                    println!("---!");
                                    println!("Transaction confirmed!");
                                    println!("---!");
                                    println!("---!");
                                    // append it to file, appending txs.csv
                                    // append
                                    let mut file = std::fs::OpenOptions::new()
                                        .append(true)
                                        .create(true)
                                        .open("txs.csv")
                                        .unwrap();
                                    file.write_all(format!("{:?}\n", tx.signatures).as_bytes()).unwrap();

                                    
                    

                                    return Ok(());
                                },
                                _ => {
                                    println!("Transaction not confirmed yet...");
                                    sigs.push(client.send_transaction(&tx.clone()).await?);
                                }
                            }
                        }
                    }
                }
            },
            Err(err) => {
                println!("Error checking transaction status: {:?}", err);
            }
        }

        attempts += 1;
        let _ = client.send_transaction(&tx.clone()).await;

        println!("Confirmation attempts: {:?}", attempts);
        if attempts >= CONFIRM_RETRIES as u64 {
            return Err(ClientError {
                request: None,
                kind: ClientErrorKind::Custom("Confirmation attempts exceeded".into()),
            });
        }
    }
}
