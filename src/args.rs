use clap::{arg, Parser};

#[derive(Parser, Debug)]
pub struct BalanceArgs {
    #[arg(
        long,
        value_name = "ADDRESS",
        help = "The address of the account to fetch the balance of"
    )]
    pub address: Option<String>,
}

#[derive(Parser, Debug)]
pub struct BenchmarkArgs {
    #[arg(
        long,
        short,
        value_name = "THREAD_COUNT",
        help = "The number of threads to use during the benchmark",
        default_value = "1"
    )]
    pub threads: u64,
}

#[derive(Parser, Debug)]
pub struct BussesArgs {}

#[derive(Parser, Debug)]
pub struct ClaimArgs {
    #[arg(
        long,
        value_name = "AMOUNT",
        help = "The amount of rewards to claim. Defaults to max."
    )]
    pub amount: Option<f64>,

    #[arg(
        long,
        value_name = "TOKEN_ACCOUNT_ADDRESS",
        help = "Token account to receive mining rewards."
    )]
    pub beneficiary: Option<String>,
}

#[derive(Parser, Debug)]
pub struct CloseArgs {}

#[cfg(feature = "admin")]
#[derive(Parser, Debug)]
pub struct InitializeArgs {}

#[derive(Parser, Debug)]
pub struct MineArgs {
    // #[cfg(not(feature = "gpu"))]
    #[arg(
        long,
        short,
        value_name = "THREAD_COUNT",
        help = "The number of CPU threads to allocate to mining",
        default_value = "1"
    )]
    pub threads: u64,

    #[arg(
        long,
        short,
        value_name = "SECONDS",
        help = "The number seconds before the deadline to stop mining and start submitting",
        default_value = "5"
    )]
    pub buffer_time: u64,
}

#[derive(Parser, Debug)]
pub struct RewardsArgs {}

#[derive(Parser, Debug)]
pub struct StakeArgs {
    #[arg(
        long,
        value_name = "AMOUNT",
        help = "The amount of Ore to stake. Defaults to max."
    )]
    pub amount: Option<f64>,

    #[arg(
        long,
        value_name = "TOKEN_ACCOUNT_ADDRESS",
        help = "Token account to send Ore from."
    )]
    pub sender: Option<String>,
}

#[cfg(feature = "admin")]
#[derive(Parser, Debug)]
pub struct UpdateAdminArgs {
    pub new_admin: String,
}

#[derive(Parser, Debug)]
pub struct UpgradeArgs {
    #[arg(
        long,
        value_name = "AMOUNT",
        help = "The amount of Ore to upgrade from v1 to v2. Defaults to max."
    )]
    pub amount: Option<f64>,
}
