use std::fs::{File, write};
use std::io::{BufRead, BufReader, Result};
use std::sync::{Arc, Mutex};
use std::env;
use std::collections::BTreeMap;
use std::time::{Instant, Duration};
use std::process::Command;
use humantime::format_duration;
use systemstat::{System, Platform};
use chrono::prelude::*;

use colored::*;
use drillx::{
    equix::{self},
    Hash, Solution
};
use ore::{self, state::Proof, BUS_ADDRESSES, BUS_COUNT, EPOCH_DURATION};

use rand::Rng;
use solana_program::{
	pubkey::Pubkey,
    native_token::{lamports_to_sol, sol_to_lamports},
};

use solana_rpc_client::spinner;
use solana_sdk::signer::Signer;
use solana_sdk::clock::Clock;

use crate::{
    args::MineArgs,
	send_and_confirm::ComputeBudget,
    utils::{amount_u64_to_f64, get_clock, get_config, get_proof},
    Miner,
};

impl Miner {
	pub async fn mine(&self, args: MineArgs) {
		const MIN_SOL_BALANCE: f64 = 0.005;

		// Register, if needed.
        let signer = self.signer();
        self.register().await;

		let sys = System::new();

        // Check num threads
        self.check_num_cores(args.threads);

		let mut cutoff_time: u64;						// How long each pass will mine for
		let mining_start_time_display = Local::now();	// When the miner was initially started
		let mining_start_time = Instant::now();	// When the miner was initially started
		let mut pass=1;								// This represents how many times the miner has tried to mine
		let mut current_sol_balance: f64;					// The amount of SOL in the wallet
		let mut current_staked_balance: f64;				// The amount of staked ORE in the wallet
		let mut last_sol_balance: f64 = 0.0;				// The amount of SOL in the wallet in the previous mining pass
		let mut last_staked_balance: f64 = 0.0;				// The amount of ORE in the wallet in the previous mining pass
		let mut last_pass_difficulty: u32= 0;				// The best difficulty solved in the last pass
		let mut session_ore_mined: f64 = 0.0;				// A running tally of the ORE mined in all passes (session)
		let mut session_sol_used: f64 = 0.0;				// A running tally of the SOL spent in all passes (session)
		let mut session_hashes: u64 = 0;					// A running tally of the number of hashes in all passes (session)
		let mut difficulties_solved: BTreeMap<u32, usize> = BTreeMap::new();	// An array that counts how many of each difficulty has been solved in this session
		let mut max_reward: f64 = 0.0;						// What has been the highest reward mined in this session
		let mut max_reward_text: String = "".to_string();	// A text string detailing the maximum reward pass

		let mut _current_ore_price:f64;
		let mut _current_sol_price:f64;

		let miner_name=env::var("MINER_NAME").unwrap_or("Unnamed Miner".to_string());
		let wallet_name=env::var("WALLET_NAME").unwrap_or("Unnamed Wallet".to_string());
		let rig_wattage_idle: f64 = env::var("MINER_WATTAGE_IDLE").ok().and_then(|x| x.parse::<f64>().ok()).unwrap_or(10.0);
		let rig_wattage_busy: f64 = env::var("MINER_WATTAGE_BUSY").ok().and_then(|x| x.parse::<f64>().ok()).unwrap_or(100.0);
		let cost_per_kw_hour: f64 = env::var("MINER_COST_PER_KILOWATT_HOUR").ok().and_then(|x| x.parse::<f64>().ok()).unwrap_or(0.30);
		let rig_desired_difficulty_level: u32 = env::var("MINER_DESIRED_DIFFICULTY_LEVEL").ok().and_then(|x| x.parse::<u32>().ok()).unwrap_or(13);
		let stats_logfile=env::var("STATS_LOGFILE").unwrap_or("".to_string());
	
		let separator_line = ("=======================================================================================================================================").to_string().dimmed();
		let green_separator_line=separator_line.clone().green();
		let yellow_separator_line=separator_line.clone().yellow();

		let mut log_startup=String::from("");
		let mut log_stats=String::from("");
		let mut log_start_pass=String::from("");
		let mut log_end_pass=String::from("");
		let mut log_mined=String::from("");
		let mut log_hash=String::from("");
		let log_tx=String::from("");
		log_startup+=format!("{}\n", green_separator_line).as_str();
		log_startup+=format!("| Rig Wattage When Idle: {}W\n", rig_wattage_idle.to_string().bold()).as_str();
		log_startup+=format!("| Rig Wattage When Busy: {}W\n", rig_wattage_busy.to_string().bold()).as_str();
		log_startup+=format!("| Cost of electric per kWHr: ${}\n", cost_per_kw_hour.to_string().bold()).as_str();
		log_startup+=format!("| Wallet name: {}\n", wallet_name.bold()).as_str();
		_current_ore_price=self.load_ore_price();
		_current_sol_price=self.load_sol_price();
		log_startup+=format!("{}\n", green_separator_line).as_str();
		log_startup+=format!("| {} {}...\n", "Starting first pass...".bold().green(), miner_name.bold().green()).as_str();

        // Start mining loop
        loop {
			let pass_start_time = Instant::now();

            // Fetch proof
            let proof = get_proof(&self.rpc_client, signer.pubkey()).await;

			// Determine Wallet ORE & SOL Balances
			current_sol_balance=self.get_sol_balance(false).await;
			current_staked_balance=amount_u64_to_f64(proof.balance);

			// Lookup CPU stats for 1min, 5 mins and 15 mins
			let mut load_avg_1min: f32=0.0;
			let mut load_avg_5min: f32=0.0;
			let mut load_avg_15min: f32=0.0;
			match sys.load_average() {
				Ok(load_avg) => {
					load_avg_1min=load_avg.one;			// 1 min
					load_avg_5min=load_avg.five;		// 5 min
					load_avg_15min=load_avg.fifteen;	// 15 min
				}
				Err(err) => eprintln!("Error: Failed to get CPU load average: {}", err),
			}
			// CPU Temp - this will not report anything if in WSL2 on windows
			let cpu_temp: f32;
			match sys.cpu_temp() {
				Ok(t) => { cpu_temp=t; },
				Err(_err) => { cpu_temp=-99.0; },
					// eprintln!("Error (cpu_temp): {}", err),
			};
			let mut cpu_temp_txt=format!("{}°C   ", cpu_temp.to_string());
			if cpu_temp==-99.0 {
				cpu_temp_txt="".to_string();
			}

			// Calc cutoff time
			let clock = get_clock(&self.rpc_client).await;
           	cutoff_time = self.get_cutoff(proof, args.buffer_time, &clock).await;

			// Special handling of first miner pass
			if pass==1 {
				let seconds_since_last_hash: u64 =clock.unix_timestamp.saturating_sub(proof.last_hash_at) as u64;
				log_startup+=format!("| {} seconds since last hash submission.\n", seconds_since_last_hash).as_str();
				// Classed as Spam if submitting transaction before 55 secs
				// Classed as Liveness Penalty if submitting difficulty >60 and <=120
				// Classed as Liveness Penalty & no Reward if >120
				let mut extra_text="";
				// Shorten the first pass if a liveness penalty (no reward) will be applied
				if seconds_since_last_hash>110 {
					log_startup+=format!("| {}\n", "You will be hit with a liveness penalty for the first pass resulting in no rewards.".red()).as_str();
					log_startup+=format!("| Reducing it's duration to compensate and stop you crying if you solve a high difficulty.\n").as_str();
					cutoff_time=3;
					extra_text="shortened to ";
				} 
				// Notify the first pass will get a liveness penalty applied (reduced reward)
				else if seconds_since_last_hash>60 {
					log_startup+=format!("| {}\n", "You will be hit with a liveness penalty for the first pass resulting in a reduced reward.".yellow()).as_str();
					cutoff_time = 60 - (seconds_since_last_hash-60) - args.buffer_time;
					if cutoff_time>15 {	// shorten the pass to 15 to maximise reduced reward
						cutoff_time=15;
					}
					if cutoff_time<3 { // catch if it would be less than 3 which will fail
						cutoff_time=3;
					}
				}
				log_startup+=format!("| First pass will be {}{} seconds long.\n", extra_text, cutoff_time).as_str();
				log_startup+=format!("{}\n", green_separator_line).as_str();	

				// Write the startup log to the screen
				print!("{}", log_startup);
				// Write stat to log file every pass overwriting previous version
				if stats_logfile != "" {
					let _result = write(stats_logfile.clone(), log_startup.clone());
				}
			}

			// Summarize the results of the previous mining pass
			if pass>1 {
				// Add the difference in staked ore from the previous pass to the session_ore_mined tally
				let mut last_pass_ore_mined=current_staked_balance-last_staked_balance;
				// If ore has been unstaked, then this value will be wrong for last pass so ignore it
				if last_pass_ore_mined<0.0 {
					last_pass_ore_mined=0.0;
				}
				// Not sure how to detect is additional ore has been staked
				// possible to check with proof last claimed > last pass start time?
				session_ore_mined+=last_pass_ore_mined;	// Update the session ore mined tally

				// Add the difference in sol from the previous pass to the session_sol_used tally
				let mut last_pass_sol_used=current_sol_balance-last_sol_balance;
				// Sol has been added to wallet so disregard the last passed sol_used as it is incorrect
				if last_pass_sol_used>0.0 {
					last_pass_sol_used=-0.0;
				}
				// not sure how to detect a change in sol level after the start of the last pass that is not just a transaction fee.
				session_sol_used-=last_pass_sol_used;	// Update the session sol used tally

				log_mined+=format!("  Mined: {} ORE     Cost: {:>11.6} SOL    Session: {} ORE    {:11.6} SOL\n",
					format!("{:>17.11}", last_pass_ore_mined).green(),
					last_pass_sol_used,
					format!("{:>17.11}", session_ore_mined).green(),
					session_sol_used,
				).as_str();

				// Show a warning if you never earned anything in the last pass
				if last_pass_ore_mined==0.0 {
					log_mined+=format!("{}\n{}\n{}\n", 
						yellow_separator_line,
						"|                  *** WARNING: the last pass resulted in no rewards ***".bold().yellow(),
						yellow_separator_line,
					).as_str();
				}
				// Log if this pass is your maximum reward for this session
				if last_pass_ore_mined>max_reward {
					max_reward = last_pass_ore_mined;
		       		max_reward_text = format!("|      Max session reward: {} ORE  (${:.2}) at difficulty {} during pass {}\t{}",
						format!("{:>17.11}", last_pass_ore_mined).green(),
						last_pass_ore_mined * _current_ore_price,
						last_pass_difficulty.to_string().yellow(),
						(pass-1).to_string().yellow(),
						format!("[~{:.4}% of supply]", last_pass_ore_mined * 100.0).dimmed(),
					);
					log_mined+=format!("{}\n{}\n{}\n{}\n", 
						green_separator_line,
						"| You just mined your highest reward for this session!!".bold().green(),
						max_reward_text.green(), 
						green_separator_line,
					).as_str();				
				}
				log_end_pass+=log_mined.as_str();
				print!("{}", log_mined);

				// Show a status page of the difficulties solved for this mining session every X passes
				// This will indicate the most common difficulty solved by this miner
				log_stats+=format!("{}\n", green_separator_line).as_str();

				// Display stats banner
				log_stats+=format!("{}\n",
					format!("| Stats for {} pass {} at {}\t[{}]\tStarted at {}",
						miner_name.bold(),
						pass-1,
						Local::now().format("%H:%M:%S on %Y-%m-%d").to_string(),
						wallet_name.bold(),
						mining_start_time_display.format("%H:%M:%S on %Y-%m-%d").to_string(),
					).green(),
				).as_str();
				log_stats+=format!("{}\n", green_separator_line).as_str();

				// Display Ore & sol price
				_current_ore_price=self.load_ore_price();
				_current_sol_price=self.load_sol_price();
				if _current_ore_price!=0.00 || _current_sol_price !=0.00 {
					log_stats+=format!("|       Current ORE Price: {:>17.2} USD\t\tCurrent SOL Price: ${:>.2} USD\n",
						_current_ore_price,
						_current_sol_price,
					).as_str();
				} else {
					log_stats+=format!("| No prices are available for ORE & SOL so setting them to $0.00. Consider setting up a coingecko api key as described in the README\n").as_str();
				}

				// Display Max Reward
				if max_reward_text != "" {
					log_stats+=format!("{}\n", max_reward_text).as_str();
				}
				
				// Display Average Reward
				log_stats+=format!("|          Average reward: {} ORE  (${:>.4}) over {} passes\t\t\t{}\n",
					format!("{:>17.11}", (session_ore_mined / (pass-1) as f64)).green(),
					(session_ore_mined / (pass-1) as f64) * _current_ore_price,
					(pass-1).to_string().yellow(),
					format!("[~{:.4}% of supply]", (session_ore_mined / (pass-1) as f64) * 100.0).dimmed(),
				).as_str();

				log_stats+=format!("|         Session Summary: {:>17}               {:>11}        Cost (Electric)\n", "Profit", "Cost").as_str();
				
				let session_kwatts_used=(rig_wattage_busy/1000.0) * (pass-1) as f64 / 60.0;	// (MINER_WATTAGE_BUSY/1000.0) * (pass-1) / number of passes per hour
				log_stats+=format!("|                  Tokens: {} ORE           {} SOL    {:.3}kW for {:.0}W rig\n",
					format!("{:>17.11}", session_ore_mined).green(),
					format!("{:>11.6}", session_sol_used).bright_cyan(),
					// (MINER_WATTAGE_X/1000.0) * (pass-1) / number of passes per hour
					session_kwatts_used,
					rig_wattage_busy,
				).as_str();

				log_stats+=format!("|              In dollars: {:>17.02} USD           {:>11.2} USD    {:.2} @ ${:.2} per kW/Hr\n",
					(session_ore_mined * _current_ore_price),
					(session_sol_used * _current_sol_price),
					// Cost per minute * watts used * number of minutes mined for
					// (ELECTRICITY_COST_PER_KILOWATT_HOUR/60) * (MINER_WATTAGE_X/1000.0) * passes/ number of passes per hour
					cost_per_kw_hour * session_kwatts_used,
					cost_per_kw_hour,
				).as_str();

				log_stats+=format!("|          Profitablility: {} USD\n",
					// Mined Ore - SOL Spent - Electic Cost
					format!("{:>17.2}", (session_ore_mined * _current_ore_price) - (session_sol_used * _current_sol_price) - (cost_per_kw_hour * session_kwatts_used)).bright_green(),
				).as_str();

				log_stats+=format!("| Total Hashes in session: {:.1}M\t\tAverage Hashes per pass: {:.0}\t\tThreads: {}\n",
					(session_hashes as f64) / 1048576.0,		// Calc Mega Hashes
					session_hashes as f64 / (pass-1) as f64,
					args.threads,
				).as_str();

				log_stats+=format!("|\n| Difficulties solved during {} passes:\n", pass-1).as_str();

				let mut max_count: u32 = 0;
				let mut most_popular_difficulty: u32 = 0;
				log_stats+=format!("|------------").as_str();	// Difficulty title row
				for (difficulty, count) in &difficulties_solved {
					if (*count as u32) >= max_count {
						max_count=*count as u32;
						most_popular_difficulty=*difficulty;
					}
					log_stats+=format!("|----").as_str();
				}
				log_stats+=format!("|\n").as_str();

				log_stats+=format!("| Difficulty ").as_str();	// solved difficulty levels
				for (difficulty, _count) in &difficulties_solved {
					if *difficulty == most_popular_difficulty {
						log_stats+=format!("|{:>4}", difficulty.to_string().bold().yellow()).as_str();
					} else {
						log_stats+=format!("|{:>4}", difficulty).as_str();
					}
				}
				log_stats+=format!("|\n").as_str();

				log_stats+=format!("| Solves     ").as_str();	// solved difficulty counts
				let mut total_solves=0;
				for (_difficulty, count) in &difficulties_solved {
					if (*count as u32) == max_count {
						log_stats+=format!("|{:>4}", (*count as u32).to_string().bold().yellow()).as_str();
					} else {
						log_stats+=format!("|{:>4}", count).as_str();
					}
					total_solves+=*count as u32;
				}
				log_stats+=format!("|\n").as_str();

				log_stats+=format!("| Percentage ").as_str();	// solved percentage row
				let mut cumulative=0.0;
				for (_difficulty, count) in &difficulties_solved {
					let percent=(*count as f64)*100.0/(total_solves as f64);
					cumulative += percent;
					let display_val=f64::trunc(percent) as u32;
					if (*count as u32) == max_count {
						log_stats+=format!("|{:>3}{}", display_val.to_string().bold().yellow(), "%".dimmed()).as_str();
					} else if cumulative<20.0 || (cumulative-percent)>85.0 {
						log_stats+=format!("|{:>3}{}", display_val.to_string().dimmed(), "%".dimmed()).as_str();
					} else {
						log_stats+=format!("|{:>3}{}", display_val, "%".dimmed()).as_str();
					}
				}
				log_stats+=format!("|\n").as_str();

				log_stats+=format!("| Cumulative ").as_str();	// solved cumulative percentage Row
				cumulative=0.0;
				for (_difficulty, count) in &difficulties_solved {
					let percent=(*count as f64)*100.0/(total_solves as f64);
					cumulative += percent;
					let display_val=f64::trunc(cumulative) as u32;
					if (*count as u32) == max_count {
						log_stats+=format!("|{:>3}{}", display_val.to_string().bold().yellow(), "%".dimmed()).as_str();
					} else if cumulative<20.0 || (cumulative-percent)>85.0 {
						log_stats+=format!("|{:>3}{}", display_val.to_string().dimmed(), "%".dimmed()).as_str();
					} else {
						log_stats+=format!("|{:>3}{}", display_val, "%".dimmed()).as_str();
					}
				}
				log_stats+=format!("|\n").as_str();
				log_stats+=format!("{}\n", green_separator_line).as_str();

				// Write stat to log file every pass overwriting previous version
				if stats_logfile != "" {
					let what_to_log=format!("{}{}{}{}{}", log_stats, log_start_pass, log_hash, log_tx, log_end_pass);
					let _result = write(stats_logfile.clone(), what_to_log);
				}

				// Display stats on screen every X passes
				if (pass-1) % 5 == 0 {
					print!("\n{}", log_stats);
				} else {
					// Add a separator no stats are to be shown
					println!("\n{}\n", green_separator_line);
				}
			}

			// Reset Stats Log
			log_stats=String::from("");

			// Store this pass's sol/staked balances for use in the next pass
			last_sol_balance=current_sol_balance;
			last_staked_balance=current_staked_balance;

			// New pass has started - log pass information
			log_end_pass=String::from("");
			log_mined=String::from("");
			log_start_pass=String::from("");
			log_start_pass+=format!("Pass {} started at {}\t\tMined for {}\tCPU: {}{:.2}/{:.2}/{:.2}\n",
				pass,
				Local::now().format("%H:%M:%S on %Y-%m-%d").to_string(),
				format_duration(Duration::from_secs(mining_start_time.elapsed().as_secs())),
				cpu_temp_txt,
				load_avg_1min,
				load_avg_5min,
				load_avg_15min,
			).as_str();

			// New pass - log staked & balance details
            log_start_pass+=format!("        Currently Staked: {:>17.11} ORE   Wallet: {:>11.6} SOL    \n",
				current_staked_balance,
				current_sol_balance,
            ).as_str();
			print!("{}", log_start_pass);

			// Pause mining for one minute if no SOL available for transaction fee
			// This keeps the miner looping and will restart mining when enough SOL is added to miner's wallet
			if current_sol_balance<MIN_SOL_BALANCE {
				let progress_bar = Arc::new(spinner::new_progress_bar());
				for _ in 0..60 {
					progress_bar.set_message(format!("[{}{}] {}",
						(60-pass_start_time.elapsed().as_secs()).to_string().dimmed(),
						("s to go").dimmed(),
						("Not enough sol in wallet. Please deposit more to continue mining after the timeout.").yellow(),
					));
					std::thread::sleep(Duration::from_millis(1000));
				}
				let mut log_no_sol=String::from("");
				log_no_sol+=format!("[{}{}] {}\n",
					(60-pass_start_time.elapsed().as_secs()).to_string().dimmed(),
					("s").dimmed(),
					("Not enough sol in wallet. Please deposit more to continue mining.").yellow(),
				).as_str();
				progress_bar.finish_with_message(log_no_sol.clone());
				log_end_pass+=log_no_sol.as_str();
			}

			// The proof of work processing for this individual mining pass
			if current_sol_balance>=MIN_SOL_BALANCE {
				log_hash=String::from("");
				// Run drillx
        let (solution, best_difficulty, num_hashes, log) = Self::find_hash_par(proof, cutoff_time, args.threads, rig_desired_difficulty_level).await;
				log_hash+="  ";
				log_hash+=log.as_str();
				log_hash+="\n";
				
				// Submit most difficult hash
				let mut ixs = vec![];
				if self.needs_reset().await {
					ixs.push(ore::instruction::reset(signer.pubkey()));
				}
				ixs.push(ore::instruction::mine(
					signer.pubkey(),
					find_bus(),
					solution,
				));
				// std::thread::sleep(Duration::from_millis(60000)); // debug submitting transactions too late
				match self.send_and_confirm(&ixs, ComputeBudget::Fixed(500_000), false, true)
					.await {
						Ok(_sig) => {
							// Log the difficulty solved to hashMap to record progress
							*difficulties_solved.entry(best_difficulty).or_insert(0) += 1;
							last_pass_difficulty=best_difficulty;
						},
						Err(err) => {
							log_end_pass+=format!("        {} {}\n", "Transaction failed:".yellow(), err.to_string().yellow()).as_str();
						},
					};

				// Duplicate the difficulty log line to stats
				session_hashes+=num_hashes;
			}

			// Log how long this pass took to complete
			log_end_pass+=format!("  [{}{}] Completed",
				pass_start_time.elapsed().as_secs().to_string().dimmed(),
				"s".dimmed(),
			).as_str();
			print!("{}", log_end_pass);

			pass+=1;
        }
    }

	// This is the main hashing functio for the ORE mining loop
    async fn find_hash_par(proof: Proof, cutoff_time: u64, threads: u64, rig_desired_difficulty_level: u32) -> (Solution, u32, u64, String) {
        // Dispatch job to each thread
		let timer = Instant::now();
		let progress_bar = Arc::new(spinner::new_progress_bar());
		let global_max_difficulty = Arc::new(Mutex::new(u32::MIN));
		let global_max_difficulty_took = Arc::new(Mutex::new(u64::MIN));
		let global_hashes = Arc::new(Mutex::new(u64::MIN));
		let stop_all_threads = Arc::new(Mutex::new(false));
		progress_bar.set_message(format!("[{}s to go] Mining...", cutoff_time));
		let handles: Vec<_> = (0..threads)
            .map(|thread_number| {
				std::thread::spawn({
                    let proof = proof.clone();
                    let progress_bar = progress_bar.clone();
                    let mut memory = equix::SolverMemory::new();
					let thread_max_difficulty = Arc::clone(&global_max_difficulty);
					let thread_max_difficulty_took = Arc::clone(&global_max_difficulty_took);
					let thread_hashes = Arc::clone(&global_hashes);
					let thread_stop_all_threads = Arc::clone(&stop_all_threads);
					move || {
                        let mut nonce = u64::MAX.saturating_div(threads).saturating_mul(thread_number);
                        let mut best_nonce = nonce;
                        let mut best_difficulty = 0;
                        let mut best_hash = Hash::default();
						let mut last_elapsed:u64 = 0;
						let mut hashes=0;

                        loop {
							hashes+=1;

							// Create hash
                            if let Ok(hx) = drillx::hash_with_memory(
                                &mut memory,
                                &proof.challenge,
                                &nonce.to_le_bytes(),
                            ) {
                                let difficulty = hx.difficulty();
                                if difficulty.gt(&best_difficulty) {
                                    best_nonce = nonce;
                                    best_difficulty = difficulty;
                                    best_hash = hx;
									{	// Update the global max difficulty counter
										let mut global_max_difficulty=thread_max_difficulty.lock().unwrap();
										if difficulty>*global_max_difficulty {
											*global_max_difficulty = difficulty+0;
											let mut global_max_difficult_took=thread_max_difficulty_took.lock().unwrap();
											*global_max_difficult_took = timer.elapsed().as_secs();
										}
									}
                                }
                            }

                            // Thread processing every 100 hashes (saves CPU & triggers every second or so)
                            if nonce % 100 == 0 {
								let elapsed_secs=timer.elapsed().as_secs();
								let global_max_difficulty=thread_max_difficulty.lock().unwrap();
								let mut global_stop_all_threads=thread_stop_all_threads.lock().unwrap();
								let over_time=elapsed_secs.ge(&cutoff_time);

								// Check if this thread has been asked to stop
								if *global_stop_all_threads {
									// this thread has been asked to terminate by another thread
									break;
								}

								// Check if we have mined for the appropriate length of time
								if over_time {
									// Ask all other threads to stop if we have attained a desired difficulty level
									if global_max_difficulty.ge(&rig_desired_difficulty_level) {
										// println!("{} Reached desired difficulty of {}", thread_number, rig_desired_difficulty_level);
										*global_stop_all_threads = true;
										break;
									}
									// Terminate this thread if we have attained a desired difficulty level
									if best_difficulty.gt(&ore::MIN_DIFFICULTY) {
									// if best_difficulty.gt(&ore::MIN_DIFFICULTY) && global_max_difficulty.ge(&rig_desired_difficulty_level) {
										// Mine until min difficulty has been met
										break;
									}
								}

								// Only log for first thread - other threads are silent
								if thread_number == 0 {
									if elapsed_secs != last_elapsed {
										last_elapsed=elapsed_secs;

										let countdown_text;
										let mut extended_hashing_txt="";
										if elapsed_secs<cutoff_time {
											countdown_text=format!("{}{}",
												cutoff_time.saturating_sub(elapsed_secs).to_string().dimmed(),
												"s to go".dimmed(),
											);
										} else {
											countdown_text=format!("{}{}",
												(elapsed_secs-cutoff_time).to_string().dimmed(),
												"s over".dimmed(),
											);
											extended_hashing_txt="[Extended hashing period]";
										}

										let mut attained_desired_difficulty="";
										if global_max_difficulty.ge(&rig_desired_difficulty_level) {
											attained_desired_difficulty="*";
										}

										let global_max_difficult_took=thread_max_difficulty_took.lock().unwrap();
										progress_bar.set_message(format!(
											"[{}] Mining... {} {}{} after {} secs\tApprox Hashes: {} {}",
											countdown_text,
											"Difficulty so far:".dimmed(),
											global_max_difficulty,
											attained_desired_difficulty,
											global_max_difficult_took,
											hashes*threads,
											extended_hashing_txt,
										));
									}
								}
                            }

                            // Increment nonce
                            nonce += 1;
                        }

						{
							let mut global_hashes=thread_hashes.lock().unwrap();
							*global_hashes += hashes;
						}

                        // Return the best nonce
                        (best_nonce, best_difficulty, best_hash)
                    }
                })
            })
            .collect();

        // Join handles and return best nonce
        let mut best_nonce = 0;
        let mut best_difficulty = 0;
        let mut best_hash = Hash::default();
        for h in handles {
            if let Ok((nonce, difficulty, hash)) = h.join() {
                if difficulty > best_difficulty {
                    best_difficulty = difficulty;
                    best_nonce = nonce;
                    best_hash = hash;
                }
            }
        }

        // Update log
		let hashes=global_hashes.lock().unwrap();
		let mut attained_desired_difficulty="";
		if best_difficulty.ge(&rig_desired_difficulty_level) {
			attained_desired_difficulty="*";
		}

		let mut log_hash=String::from("");
		log_hash+=format!(
            "[{}{}] Difficulty: {}{} after {} secs   Hashes: {}   Hash: {}",
			timer.elapsed().as_secs().to_string().dimmed(),
			"s".dimmed(),
            best_difficulty.to_string().bold().yellow(),
			attained_desired_difficulty,
			global_max_difficulty_took.lock().unwrap().to_string().bold().yellow(),
			*hashes,
			// 100.0* (*hashes as f64)/(u64::MAX as f64) *1000000000.0,
            bs58::encode(best_hash.h).into_string().dimmed(),
		).as_str();
		progress_bar.finish_with_message(log_hash.clone());

        (Solution::new(best_hash.d, best_nonce.to_le_bytes()), best_difficulty, *hashes, log_hash)
    }

	// Ensure that the requested number of threads is not above the number of CPU cores
    pub fn check_num_cores(&self, threads: u64) {
        // Check num threads
        let num_cores = num_cpus::get() as u64;
        if threads.gt(&num_cores) {
            println!(
                "{} Number of threads ({}) exceeds available cores ({})",
                "WARNING".bold().yellow(),
                threads,
                num_cores
            );
        }
    }

	// Determine if a reset is required ()
    async fn needs_reset(&self) -> bool {
        let clock = get_clock(&self.rpc_client).await;
        let config = get_config(&self.rpc_client).await;
        config
            .last_reset_at
            .saturating_add(EPOCH_DURATION)
            .saturating_sub(5) // Buffer
            .le(&clock.unix_timestamp)
    }

	// Calculate how long to mine for
	// Based upon (last_hash_at time) + (1 minute) - (desired buffer_time) - (clock time)
    async fn get_cutoff(&self, proof: Proof, buffer_time: u64, clock: &Clock) -> u64 {
        // clock is passed in to prevent calling get_clock() twice in quick succession from RPC
		// let clock = get_clock(&self.rpc_client).await;
        let mut retval=proof.last_hash_at
            .saturating_add(60)
            .saturating_sub(buffer_time as i64)
            .saturating_sub(clock.unix_timestamp.clone())
            .max(0) as u64;
		if retval==0 {
			retval=(60 as i64).saturating_sub(buffer_time as i64).max(0) as u64;
		}
		return retval;
    }

	async fn get_sol_balance(&self, panic: bool) -> f64 {
		let mut current_sol_balance=self.get_sol_balance_tx(panic).await;
		if current_sol_balance==0.0 {
			for _ in 0..50 {
				std::thread::sleep(Duration::from_millis(50));
				current_sol_balance=self.get_sol_balance_tx(panic).await;
				if current_sol_balance>=0.0 {
					return current_sol_balance
				}
			}
		}
		return current_sol_balance
	}

	// Query the wallet for the amount of SOL present and panic if less than a minimum amount
	async fn get_sol_balance_tx(&self, panic: bool) -> f64 {
		const MIN_SOL_BALANCE: f64 = 0.005;
		let signer = self.signer();
		let client = self.rpc_client.clone();

		// Return error, if balance is zero
		if let Ok(lamports_balance) = client.get_balance(&signer.pubkey()).await {
			let sol_balance:f64 = lamports_to_sol(lamports_balance);
			if lamports_balance <= sol_to_lamports(MIN_SOL_BALANCE) {
				if panic {
					panic!(
						"{} Insufficient balance: {} SOL\nPlease top up with at least {} SOL",
						"ERROR".bold().red(),
						sol_balance,
						MIN_SOL_BALANCE
					);
				}
			}
			return sol_balance
		} else {
			if panic {
				panic!(
					"{} Failed to lookup sol balance",
					"ERROR".bold().red(),
				);
			} else {
				return 0.0 as f64
			}
		}
	}

	// Read a file to get a f64 value from the first line of the file
	pub fn read_f64_from_file(&self, file_path: &str) -> Result<f64> {
		let file = File::open(file_path)?;
		let reader = BufReader::new(file);

		if let Some(first_line) = reader.lines().next() {
			if let Ok(line) = first_line {
				if let Ok(value) = line.trim().parse::<f64>() {
					return Ok(value);
				}
			}
		}

		Err(std::io::Error::new(
			std::io::ErrorKind::InvalidData,
			"Failed to read or parse f64 from the first line.",
		))
	}

	// read the current ORE price in from text file
	fn load_ore_price(&self) -> f64 {
		self.lookup_updated_token_price("Ore");

		let file_path = "./currentPriceOfOre.txt";
		match self.read_f64_from_file(&file_path) {
			Ok(value) => value,
			Err(err) => {
				eprintln!("Error: failed to read ORE price from {}: {}", file_path, err);
				0.0
			}
		}
	}

	// read the current SOL price in from text file
	fn load_sol_price(&self) -> f64 {
		self.lookup_updated_token_price("Sol");

		let file_path = "./currentPriceOfSol.txt";
		match self.read_f64_from_file(&file_path) {
			Ok(value) => value,
			Err(err) => {
				eprintln!("Error: failed to read SOL price from {}: {}", file_path, err);
				0.0
			}
		}
	}

	// lookup updated prices for token from coingecko
	fn lookup_updated_token_price(&self, tokenname: &str) {
		let mut command = Command::new("./coingeckoDownloadPrice.sh");
    	command.arg(tokenname);
		command.arg("quiet");
		// command.arg(format!("pwd();"));
		// let current_dir = env::current_dir().expect("Failed to get current directory");
		// command.current_dir(current_dir);
    	let status = command.status().expect(format!("Failed to execute command to download {} price", tokenname).as_str());
    	if ! status.success() {
        	println!("{} {}", "ERROR: coingeckoDownloadPrice.sh failed to execute.".bold().red(), status);
    	}
	}

}

// TODO Pick a better strategy (avoid draining bus)
fn find_bus() -> Pubkey {
    let i = rand::thread_rng().gen_range(0..BUS_COUNT);
    BUS_ADDRESSES[i]
}
