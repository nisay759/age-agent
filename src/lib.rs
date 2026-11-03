//! age-agent: caches unlocked age identities in a daemon, exposed to age clients as a plugin.

pub mod client;
pub mod config;
pub mod daemon;
pub mod identities;
pub mod prompt;
pub mod protocol;
pub mod stub;
pub mod sys;
pub mod plugin;
pub mod autolock;
