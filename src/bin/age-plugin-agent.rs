//! Run by age clients only, never by hand.

use std::process::ExitCode;

fn main() -> ExitCode {
    // SEC-2 for the plugin too: it holds the passphrase it collects and the file keys.
    age_agent::sys::harden_process();
    let Some(state_machine) = std::env::args().find_map(|a| a.strip_prefix("--age-plugin=").map(str::to_owned)) else {
        eprintln!("age-plugin-agent is run by age clients, not by hand; see `age-agent --help`");
        return ExitCode::from(2);
    };
    match age_plugin::run_state_machine(&state_machine, age_agent::plugin::Handler) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("age-plugin-agent: {e}");
            ExitCode::FAILURE
        }
    }
}
