use std::time::Duration;
use std::time::Instant;

use colored::*;
use solana_client::{
    client_error::{ClientError, ClientErrorKind, Result as ClientResult},
    rpc_config::RpcSendTransactionConfig,
};
use solana_program::{
    instruction::Instruction,
    native_token::{lamports_to_sol, sol_to_lamports},
};
use solana_rpc_client::spinner;
use solana_sdk::transaction::TransactionError;
use solana_sdk::{
    commitment_config::CommitmentLevel,
    compute_budget::ComputeBudgetInstruction,
    signature::{Signature, Signer},
    transaction::Transaction,
};
use solana_transaction_status::{TransactionConfirmationStatus, UiTransactionEncoding};

use crate::Miner;

const MIN_SOL_BALANCE: f64 = 0.005;

const RPC_RETRIES: usize = 0;
const _SIMULATION_RETRIES: usize = 4;


// Failing Transaction time = GATEWAY_RETRIES * GATEWAY_DELAY = 40 * 250ms = 10s
const GATEWAY_RETRIES: usize = 40;	// How many times to retry a failed transaction - Reducing this value to 1 triggers regular ERROR-D
const GATEWAY_DELAY: u64 = 250;		// Delay in ms before retrying a failed transaction

// Time spent waiting for confirmation of transaction = CONFIRM_RETRIES * CONFIRM_DELAY = 1 * 50 = 50ms
const CONFIRM_RETRIES: usize = 9;	// try to get transaction confirmation this many times
const CONFIRM_DELAY: u64 = 50;		// Delay in ms between reach confirmation check


pub enum ComputeBudget {
    Dynamic,
    Fixed(u32),
}

impl Miner {
	pub async fn send_and_confirm(
        &self,
        ixs: &[Instruction],
        compute_budget: ComputeBudget,
        skip_confirm: bool,
		skip_sol_check: bool,
    ) -> ClientResult<Signature> {
		
		let signer = self.signer();
        let client = self.rpc_client.clone();
		let submit_start_time: Instant = Instant::now();
		let mut log_tx=String::from("");

        // Return error, if balance is zero
		if !skip_sol_check {
			if let Ok(balance) = client.get_balance(&signer.pubkey()).await {
				if balance <= sol_to_lamports(MIN_SOL_BALANCE) {
					panic!(
						"{} Insufficient balance: {} SOL\nPlease top up with at least {} SOL",
						"ERROR".bold().red(),
						lamports_to_sol(balance),
						MIN_SOL_BALANCE
					);
				}
			}
		}

        // Set compute units
        let mut final_ixs = vec![];
        match compute_budget {
            ComputeBudget::Dynamic => {
                // TODO simulate
                final_ixs.push(ComputeBudgetInstruction::set_compute_unit_limit(1_400_000))
            }
            ComputeBudget::Fixed(cus) => {
                final_ixs.push(ComputeBudgetInstruction::set_compute_unit_limit(cus))
            }
        }
        final_ixs.push(ComputeBudgetInstruction::set_compute_unit_price(
            self.priority_fee,
        ));
        final_ixs.extend_from_slice(ixs);

        // Build tx
        let send_cfg = RpcSendTransactionConfig {
            skip_preflight: true,
            preflight_commitment: Some(CommitmentLevel::Confirmed),
            encoding: Some(UiTransactionEncoding::Base64),
            max_retries: Some(RPC_RETRIES),
            min_context_slot: None,
        };
        let mut tx = Transaction::new_with_payer(&final_ixs, Some(&signer.pubkey()));

        // Sign tx
        let (hash, _slot) = client
            .get_latest_blockhash_with_commitment(self.rpc_client.commitment())
            .await
            .unwrap();
        tx.sign(&[&signer], hash);		// Commenting out this line enables tesing a failed transation

        // Submit tx
        let mut attempts = 1;
		let progress_bar = spinner::new_progress_bar();
		loop {
			progress_bar.set_message(format!("[{}{}]  Attempt {}: Submitting transaction...",
				submit_start_time.elapsed().as_secs().to_string().dimmed(),
				"s".dimmed(),
				attempts,
			));
			match client.send_transaction_with_config(&tx, send_cfg).await {
                Ok(sig) => {
					progress_bar.set_message(format!("[{}{}]  Attempt {}: awaiting transaction to complete...",
						submit_start_time.elapsed().as_secs().to_string().dimmed(),
						"s".dimmed(),
						attempts,
					));
	
					// Skip confirmation
                    if skip_confirm {
						let mess=format!("[{}{}]  Attempt {}: Sent: {}",
							submit_start_time.elapsed().as_secs().to_string().dimmed(),
							"s".dimmed(),
							attempts,
							sig.to_string().dimmed(),
						);
                        progress_bar.finish_with_message(mess.clone());
						log_tx+=mess.as_str();
                        return Ok(sig);
                    }

                    // Confirm the tx landed
                    for confirm_counter in 0..CONFIRM_RETRIES {
                        std::thread::sleep(Duration::from_millis(CONFIRM_DELAY));
                        match client.get_signature_statuses(&[sig]).await {
                            Ok(signature_statuses) => {
                                for status in signature_statuses.value {
                                    if let Some(status) = status {
										progress_bar.set_message(format!("[{}{}]  Attempt {}: Check transaction Status...",
											submit_start_time.elapsed().as_secs().to_string().dimmed(),
											"s".dimmed(),
											attempts,
										));
				
										if let Some(err) = status.err {
											let pretty_error_message=self.lookup_ore_error_description(err.clone());
                                            progress_bar.set_message(format!("[{}{}]  Attempt {}-{}: {} {}",
												submit_start_time.elapsed().as_secs().to_string().dimmed(),
												"s".dimmed(),
												attempts,
												confirm_counter+1,
												"ERROR-A".bold().red(),
												pretty_error_message.bold().red(),
											));
                                        }
                                        if let Some(confirmation) = status.confirmation_status {
                                            match confirmation {
                                                TransactionConfirmationStatus::Processed => {}
                                                TransactionConfirmationStatus::Confirmed
                                                | TransactionConfirmationStatus::Finalized => {
                                                    let mess=format!(
                                                        "[{}{}]  Attempt {}-{}: {}\t\tTxid: {}",
														submit_start_time.elapsed().as_secs().to_string().dimmed(),
														"s".dimmed(),
														attempts,
														confirm_counter+1,
                                                        "SUCCESS".bold().green(),
                                                        sig.to_string().dimmed()
                                                    );
                                                    progress_bar.finish_with_message(mess.clone());
													log_tx+=mess.as_str();
													return Ok(sig);
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // Handle confirmation errors
                            Err(err) => {
                                progress_bar.set_message(format!("[{}{}]  Attempt {}: {} {}",
									submit_start_time.elapsed().as_secs().to_string().dimmed(),
									"s".dimmed(),
									attempts,
									"ERROR-B".bold().red(),
									err.kind().to_string().bold().red(),
                                ));
								println!(""); // leave error visible
                            }
                        }
                    }
                }

                // Handle submit errors
                Err(err) => {
                    progress_bar.set_message(format!("[{}{}]  Attempt {}: {} {}",
						submit_start_time.elapsed().as_secs().to_string().dimmed(),
						"s".dimmed(),
						attempts,
						"ERROR-C".bold().red(),
						err.kind().to_string().bold().red(),
                    ));
					println!(""); // leave error visible
                }
            }

            // Retry
			attempts += 1;
            if attempts > GATEWAY_RETRIES {
				let error_message=format!("Failed due to reaching max gateway retry limit ({})", GATEWAY_RETRIES);
                let mess=format!("[{}{}]  Attempt {}: {}: {}",
					submit_start_time.elapsed().as_secs().to_string().dimmed(),
					"s".dimmed(),
					attempts,
					"ERROR-D".bold().red(),
					error_message.bold().red(),
				);
				progress_bar.finish_with_message(mess.clone());
				log_tx+=mess.as_str();
                return Err(ClientError {
                    request: None,
                    kind: ClientErrorKind::Custom(error_message.into()),
                });
            }
			// Try again to send transaction after a small delay
            std::thread::sleep(Duration::from_millis(GATEWAY_DELAY));
        }
    }

	// Add a human description to the ORE transaction error number (copied from error.rs in the ORE repository)
	fn lookup_ore_error_description(&self, err: TransactionError) -> String {
		let error_message=err.to_string();
		let mut additional_text="";
		if error_message.contains("0x0") { additional_text=": Mining is paused"; }
		if error_message.contains("0x1") { additional_text=": The epoch has ended and needs reset"; }
		if error_message.contains("0x2") { additional_text=": The provided hash is invalid"; }
		if error_message.contains("0x3") { additional_text=": The provided hash did not satisfy the minimum required difficulty"; }
		if error_message.contains("0x4") { additional_text=": The claim amount cannot be greater than the claimable rewards"; }
		if error_message.contains("0x5") { additional_text=": The clock time is invalid"; }
		if error_message.contains("0x6") { additional_text=": Only one hash may be validated per transaction"; }
		if error_message.contains("0x7") { additional_text=": The tolerance cannot exceed i64 max value"; }
		if error_message.contains("0x8") { additional_text=": The tolerance cannot exceed i64 max value"; }

		if additional_text=="" {
			// return original error message as a string
			error_message
		} else {
			// return original error + extra description as a string
			error_message+additional_text
		}
	}

    // TODO
    fn _simulate(&self) {

        // Simulate tx
        // let mut sim_attempts = 0;
        // 'simulate: loop {
        //     let sim_res = client
        //         .simulate_transaction_with_config(
        //             &tx,
        //             RpcSimulateTransactionConfig {
        //                 sig_verify: false,
        //                 replace_recent_blockhash: true,
        //                 commitment: Some(self.rpc_client.commitment()),
        //                 encoding: Some(UiTransactionEncoding::Base64),
        //                 accounts: None,
        //                 min_context_slot: Some(slot),
        //                 inner_instructions: false,
        //             },
        //         )
        //         .await;
        //     match sim_res {
        //         Ok(sim_res) => {
        //             if let Some(err) = sim_res.value.err {
        //                 println!("Simulaton error: {:?}", err);
        //                 sim_attempts += 1;
        //             } else if let Some(units_consumed) = sim_res.value.units_consumed {
        //                 if dynamic_cus {
        //                     println!("Dynamic CUs: {:?}", units_consumed);
        //                     let cu_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(
        //                         units_consumed as u32 + 1000,
        //                     );
        //                     let cu_price_ix =
        //                         ComputeBudgetInstruction::set_compute_unit_price(self.priority_fee);
        //                     let mut final_ixs = vec![];
        //                     final_ixs.extend_from_slice(&[cu_budget_ix, cu_price_ix]);
        //                     final_ixs.extend_from_slice(ixs);
        //                     tx = Transaction::new_with_payer(&final_ixs, Some(&signer.pubkey()));
        //                 }
        //                 break 'simulate;
        //             }
        //         }
        //         Err(err) => {
        //             println!("Simulaton error: {:?}", err);
        //             sim_attempts += 1;
        //         }
        //     }

        //     // Abort if sim fails
        //     if sim_attempts.gt(&SIMULATION_RETRIES) {
        //         return Err(ClientError {
        //             request: None,
        //             kind: ClientErrorKind::Custom("Simulation failed".into()),
        //         });
        //     }
        // }
    }
}
