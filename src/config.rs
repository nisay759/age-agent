//! `~/.config/age-agent/config.toml` and the paths around it.

use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{env, fs, io};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
#[serde(default)]
pub struct Config {
    #[serde(rename = "identity")]
    pub identities: Vec<IdentityEntry>,
    pub agent: AgentConfig,
    pub prompt: PromptConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IdentityEntry {
    pub file: String,
    /// Hex stub references, written by setup.
    pub refs: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct AgentConfig {
    pub idle_timeout: String,
    pub max_lifetime: String,
    pub lock_on_screen_lock: bool,
    pub lock_on_suspend: bool,
    pub confirm_each_use: bool,
    pub log: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            idle_timeout: "15m".into(),
            max_lifetime: "8h".into(),
            lock_on_screen_lock: true,
            lock_on_suspend: true,
            confirm_each_use: false,
            log: false,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct PromptConfig {
    /// auto | terminal | pinentry
    pub mode: String,
    /// Absolute path only (SEC-8).
    pub pinentry: Option<String>,
}

impl Default for PromptConfig {
    fn default() -> Self {
        Self { mode: "auto".into(), pinentry: None }
    }
}

impl Config {
    pub fn load() -> io::Result<Self> {
        match fs::read_to_string(config_path()?) {
            Ok(s) => toml::from_str(&s).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    pub fn save(&self) -> io::Result<()> {
        let path = config_path()?;
        fs::create_dir_all(path.parent().expect("config path has a parent"))?;
        let text = toml::to_string_pretty(self).map_err(io::Error::other)?;
        fs::write(path, text)
    }

    pub fn idle_timeout(&self) -> io::Result<Duration> {
        parse_duration(&self.agent.idle_timeout)
    }

    pub fn max_lifetime(&self) -> io::Result<Duration> {
        parse_duration(&self.agent.max_lifetime)
    }
}

/// Parses `0`, `90s`, `15m`, `8h`, `1d`. A bare number is seconds. Zero means "none".
pub fn parse_duration(s: &str) -> io::Result<Duration> {
    let bad = || io::Error::new(io::ErrorKind::InvalidInput, format!("invalid duration {s:?}"));
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().map_err(|_| bad())?;
    let mult = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err(bad()),
    };
    n.checked_mul(mult).map(Duration::from_secs).ok_or_else(bad)
}

pub fn config_dir() -> io::Result<PathBuf> {
    if let Some(dir) = env::var_os("XDG_CONFIG_HOME").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir).join("age-agent"));
    }
    Ok(home()?.join(".config").join("age-agent"))
}

pub fn config_path() -> io::Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}

pub fn stub_file_path() -> io::Result<PathBuf> {
    Ok(config_dir()?.join("identities.txt"))
}

/// SEC-4: `$XDG_RUNTIME_DIR/age-agent/agent.sock`. On Linux there is no fallback: the only
/// candidate would sit under the shared `/tmp`, where another user can create the directory
/// first and keep the agent from ever starting. macOS has a private per-user temp dir.
pub fn socket_path() -> io::Result<PathBuf> {
    let base = match env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) {
        Some(d) => PathBuf::from(d),
        #[cfg(target_os = "macos")]
        None => env::temp_dir(),
        #[cfg(not(target_os = "macos"))]
        None => {
            return Err(io::Error::other(
                "XDG_RUNTIME_DIR is not set; age-agent needs the session's private runtime directory",
            ));
        }
    };
    Ok(base.join("age-agent").join("agent.sock"))
}

pub fn home() -> io::Result<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))
}

pub fn expand_tilde(p: &str) -> io::Result<PathBuf> {
    match p.strip_prefix("~/") {
        Some(rest) => Ok(home()?.join(rest)),
        None => Ok(Path::new(p).to_path_buf()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_duration("8h").unwrap(), Duration::from_secs(28800));
        assert_eq!(parse_duration("0").unwrap(), Duration::ZERO);
        assert_eq!(parse_duration("45").unwrap(), Duration::from_secs(45));
        assert!(parse_duration("").is_err());
        assert!(parse_duration("5x").is_err());
        assert!(parse_duration("m").is_err());
    }

    #[test]
    fn config_round_trip_and_defaults() {
        let c: Config = toml::from_str("[[identity]]\nfile='~/x'\nrefs=['ab']\n").unwrap();
        assert_eq!(c.identities[0].file, "~/x");
        assert_eq!(c.agent.idle_timeout, "15m");
        let again: Config = toml::from_str(&toml::to_string_pretty(&c).unwrap()).unwrap();
        assert_eq!(again.identities[0].refs, ["ab"]);
    }
}
