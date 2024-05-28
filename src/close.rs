use colored::*;
use solana_sdk::signature::Signer;
use spl_token::amount_to_ui_amount;

use crate::{
    args::ClaimArgs,
    send_and_confirm::ComputeBudget,
    utils::{ask_confirm, get_proof},
    Miner,
};

impl Miner {
    pub async fn close(&self) {
        // Confirm proof exists
        let signer = self.signer();
        let proof = get_proof(&self.rpc_client, signer.pubkey()).await;

        // Confirm the user wants to close.
        if !ask_confirm(
            format!("{} You have {} ORE staked in this account.\nAre you sure you want to {}close this account? [Y/n]",
                "WARNING".yellow(),
                amount_to_ui_amount(proof.balance, ore::TOKEN_DECIMALS),
                if proof.balance.gt(&0) { "claim your stake and "} else { "" }
            ).as_str()
        ) {
            return;
        }

        // Claim stake
        if proof.balance.gt(&0) {
            self.claim(ClaimArgs {
                amount: None,
                beneficiary: None,
            })
            .await;
        }

        // Submit deregister transaction
        let ix = ore::instruction::deregister(signer.pubkey());
        self.send_and_confirm(&[ix], ComputeBudget::Dynamic, false, false)
            .await
            .ok();
    }
}
