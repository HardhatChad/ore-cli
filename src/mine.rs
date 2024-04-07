use std::{
    io::{stdout, Write},
    sync::{atomic::AtomicBool, Arc, Mutex},
};

use ore::{self, state::Bus, BUS_ADDRESSES, BUS_COUNT, EPOCH_DURATION};
use rand::Rng;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    compute_budget::ComputeBudgetInstruction,
    keccak::{hashv, Hash as KeccakHash},
    signature::Signer,
};

use crate::{
    cu_limits::{CU_LIMIT_MINE, CU_LIMIT_RESET},
    utils::{get_clock_account, get_proof, get_treasury},
    Miner,
};

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
      transaction_encoding: Option<solana_transaction_status::UiTransactionEncoding>, // Default Base58
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
  
// Odds of being selected to submit a reset tx
const RESET_ODDS: u64 = 20;

impl Miner {
    pub async fn mine(&self, threads: u64) {
        // Register, if needed.
        let signer = self.signer();
        self.register().await;
        let mut stdout = stdout();
        let mut rng = rand::thread_rng();

        // Start mining loop
        loop {
            // Fetch account state
            let balance = self.get_ore_display_balance().await;
            let treasury = get_treasury(self.cluster.clone()).await;
            let proof = get_proof(self.cluster.clone(), signer.pubkey()).await;
            let rewards =
                (proof.claimable_rewards as f64) / (10f64.powf(ore::TOKEN_DECIMALS as f64));
            let reward_rate =
                (treasury.reward_rate as f64) / (10f64.powf(ore::TOKEN_DECIMALS as f64));
            stdout.write_all(b"\x1b[2J\x1b[3J\x1b[H").ok();
            println!("Balance: {} ORE", balance);
            println!("Claimable: {} ORE", rewards);
            println!("Reward rate: {} ORE", reward_rate);

            // Escape sequence that clears the screen and the scrollback buffer
            println!("\nMining for a valid hash...");
            let (next_hash, nonce) =
                self.find_next_hash_par(proof.hash.into(), treasury.difficulty.into(), threads);

            // Submit mine tx.
            // Use busses randomly so on each epoch, transactions don't pile on the same busses
            println!("\n\nSubmitting hash for validation...");
            loop {
                // Reset epoch, if needed
                let treasury = get_treasury(self.cluster.clone()).await;
                let clock = get_clock_account(self.cluster.clone()).await;
                let threshold = treasury.last_reset_at.saturating_add(EPOCH_DURATION);
                if clock.unix_timestamp.ge(&threshold) {
                    // There are a lot of miners right now, so randomly select into submitting tx
                    if rng.gen_range(0..RESET_ODDS).eq(&0) {
                        println!("Sending epoch reset transaction...");
                        let cu_limit_ix =
                            ComputeBudgetInstruction::set_compute_unit_limit(CU_LIMIT_RESET);
                            let priority_fee = get_recent_priority_fee_estimate(GetPriorityFeeEstimateRequest {
                                transaction: Some(bs58::encode(bincode::serialize(&solana_sdk::transaction::Transaction::new_unsigned(solana_sdk::message::Message::new(&vec![ore::instruction::reset(
                                    signer.pubkey(),
                                )], Some(&signer.pubkey())))).unwrap()).into_string()),
                                account_keys: None,
                                options: Some(GetPriorityFeeEstimateOptions {
                                    priority_level: Some(PriorityLevel::HIGH),
                                    include_all_priority_fee_levels: Some(false),
                                    transaction_encoding: Some(solana_transaction_status::UiTransactionEncoding::Base58),
                                    lookback_slots: Some(150),
                                }),
                            }).await;
                        let cu_price_ix =
                            ComputeBudgetInstruction::set_compute_unit_price(priority_fee as u64);
                        let reset_ix = ore::instruction::reset(signer.pubkey());
                        self.send_and_confirm(&[cu_limit_ix, cu_price_ix, reset_ix], false, true)
                            .await
                            .ok();
                    }
                }

                // Submit request.
                let bus = self.find_bus_id(treasury.reward_rate).await;
                let bus_rewards = (bus.rewards as f64) / (10f64.powf(ore::TOKEN_DECIMALS as f64));
                println!("Sending on bus {} ({} ORE)", bus.id, bus_rewards);
                let cu_limit_ix = ComputeBudgetInstruction::set_compute_unit_limit(CU_LIMIT_MINE);
                let priority_fee = get_recent_priority_fee_estimate(GetPriorityFeeEstimateRequest {
                    transaction: Some(bs58::encode(bincode::serialize(&solana_sdk::transaction::Transaction::new_unsigned(solana_sdk::message::Message::new(&vec![ore::instruction::mine(
                        signer.pubkey(),
                        BUS_ADDRESSES[bus.id as usize],
                        next_hash.into(),
                        nonce,
                    )], Some(&signer.pubkey())))).unwrap()).into_string()),
                    account_keys: None,
                    options: Some(GetPriorityFeeEstimateOptions {
                        priority_level: Some(PriorityLevel::HIGH),
                        include_all_priority_fee_levels: Some(false),
                        transaction_encoding: Some(solana_transaction_status::UiTransactionEncoding::Base58),
                        lookback_slots: Some(150),
                    }),
                }).await;

  
                let cu_price_ix =
                    ComputeBudgetInstruction::set_compute_unit_price(priority_fee as u64);
                let ix_mine = ore::instruction::mine(
                    signer.pubkey(),
                    BUS_ADDRESSES[bus.id as usize],
                    next_hash.into(),
                    nonce,
                );
                match self
                    .send_and_confirm(&[cu_limit_ix, cu_price_ix, ix_mine], false, false)
                    .await
                {
                    Ok(sig) => {
                        println!("Success: {}", sig);
                        break;
                    }
                    Err(_err) => {
                        // TODO
                    }
                }
            }
        }
    }

    async fn find_bus_id(&self, reward_rate: u64) -> Bus {
        let mut rng = rand::thread_rng();
        loop {
            let bus_id = rng.gen_range(0..BUS_COUNT);
            if let Ok(bus) = self.get_bus(bus_id).await {
                if bus.rewards.gt(&reward_rate.saturating_mul(4)) {
                    return bus;
                }
            }
        }
    }

    fn _find_next_hash(&self, hash: KeccakHash, difficulty: KeccakHash) -> (KeccakHash, u64) {
        let signer = self.signer();
        let mut next_hash: KeccakHash;
        let mut nonce = 0u64;
        loop {
            next_hash = hashv(&[
                hash.to_bytes().as_slice(),
                signer.pubkey().to_bytes().as_slice(),
                nonce.to_le_bytes().as_slice(),
            ]);
            if next_hash.le(&difficulty) {
                break;
            } else {
                println!("Invalid hash: {} Nonce: {:?}", next_hash.to_string(), nonce);
            }
            nonce += 1;
        }
        (next_hash, nonce)
    }

    fn find_next_hash_par(
        &self,
        hash: KeccakHash,
        difficulty: KeccakHash,
        threads: u64,
    ) -> (KeccakHash, u64) {
        let found_solution = Arc::new(AtomicBool::new(false));
        let solution = Arc::new(Mutex::<(KeccakHash, u64)>::new((
            KeccakHash::new_from_array([0; 32]),
            0,
        )));
        let signer = self.signer();
        let pubkey = signer.pubkey();
        let thread_handles: Vec<_> = (0..threads)
            .map(|i| {
                std::thread::spawn({
                    let found_solution = found_solution.clone();
                    let solution = solution.clone();
                    let mut stdout = stdout();
                    move || {
                        let n = u64::MAX.saturating_div(threads).saturating_mul(i);
                        let mut next_hash: KeccakHash;
                        let mut nonce: u64 = n;
                        loop {
                            next_hash = hashv(&[
                                hash.to_bytes().as_slice(),
                                pubkey.to_bytes().as_slice(),
                                nonce.to_le_bytes().as_slice(),
                            ]);
                            if nonce % 10_000 == 0 {
                                if found_solution.load(std::sync::atomic::Ordering::Relaxed) {
                                    return;
                                }
                                if n == 0 {
                                    stdout
                                        .write_all(
                                            format!("\r{}", next_hash.to_string()).as_bytes(),
                                        )
                                        .ok();
                                }
                            }
                            if next_hash.le(&difficulty) {
                                stdout
                                    .write_all(format!("\r{}", next_hash.to_string()).as_bytes())
                                    .ok();
                                found_solution.store(true, std::sync::atomic::Ordering::Relaxed);
                                let mut w_solution = solution.lock().expect("failed to lock mutex");
                                *w_solution = (next_hash, nonce);
                                return;
                            }
                            nonce += 1;
                        }
                    }
                })
            })
            .collect();

        for thread_handle in thread_handles {
            thread_handle.join().unwrap();
        }

        let r_solution = solution.lock().expect("Failed to get lock");
        *r_solution
    }

    pub async fn get_ore_display_balance(&self) -> String {
        let client =
            RpcClient::new_with_commitment(self.cluster.clone(), CommitmentConfig::confirmed());
        let signer = self.signer();
        let token_account_address = spl_associated_token_account::get_associated_token_address(
            &signer.pubkey(),
            &ore::MINT_ADDRESS,
        );
        match client.get_token_account(&token_account_address).await {
            Ok(token_account) => {
                if let Some(token_account) = token_account {
                    token_account.token_amount.ui_amount_string
                } else {
                    "0.00".to_string()
                }
            }
            Err(_) => "Err".to_string(),
        }
    }
}
