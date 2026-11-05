//! Command-line parsing for the `kdxd` binary (kept in the library so it can
//! be unit-tested).

use std::path::PathBuf;

use kdx_server_core::limits::MAX_USERNAME_LEN;

pub const USAGE: &str = "\
usage:
  kdxd [--allow-root] [CONFIG.toml]
      Run the server.
  kdxd useradd USER [--prompt | --password-stdin] [CLASS] [CONFIG.toml]
      Create an account, then exit. The password is asked for on the
      terminal without echo (the default when only USER is given), or read
      as one line from standard input with --password-stdin.
  kdxd useradd USER PASS [CLASS] [CONFIG.toml]
      Deprecated: PASS is visible to other local users (ps) and saved in
      your shell history.

CLASS is one of guest|user|power|admin (default: user). Relative paths in
CONFIG.toml are resolved against the directory that contains it.
kdxd refuses to run as root unless --allow-root is given.";

/// `kdxd [--allow-root] [CONFIG]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunArgs {
    pub config: Option<PathBuf>,
    pub allow_root: bool,
}

/// Where `useradd` gets the new account's password from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordSource {
    /// No-echo prompt on the controlling terminal.
    Prompt,
    /// One line from standard input.
    Stdin,
    /// The deprecated positional argument.
    Argv(String),
}

/// `kdxd useradd ...`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UseraddArgs {
    pub username: String,
    pub password: PasswordSource,
    pub class: i64,
    pub config: Option<PathBuf>,
    pub allow_root: bool,
}

pub fn parse_run(args: &[String]) -> Result<RunArgs, String> {
    let mut allow_root = false;
    let mut positional = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--allow-root" => allow_root = true,
            flag if flag.starts_with("--") => return Err(format!("unknown option '{flag}'")),
            _ => positional.push(arg),
        }
    }
    if positional.len() > 1 {
        return Err("too many arguments".into());
    }
    Ok(RunArgs {
        config: positional.first().map(PathBuf::from),
        allow_root,
    })
}

pub fn parse_useradd(args: &[String]) -> Result<UseraddArgs, String> {
    let mut allow_root = false;
    let mut source = None;
    let mut positional = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--allow-root" => allow_root = true,
            "--password-stdin" | "--prompt" => {
                if source.is_some() {
                    return Err("give at most one of --prompt / --password-stdin".into());
                }
                source = Some(if arg == "--prompt" {
                    PasswordSource::Prompt
                } else {
                    PasswordSource::Stdin
                });
            }
            flag if flag.starts_with("--") => return Err(format!("unknown option '{flag}'")),
            _ => positional.push(arg.clone()),
        }
    }
    let mut positional = positional.into_iter();
    let username = positional.next().ok_or("missing USER")?;
    let password = match source {
        Some(source) => source,
        None => match positional.len() {
            0 => PasswordSource::Prompt,
            _ => PasswordSource::Argv(positional.next().expect("checked length")),
        },
    };
    let class = parse_class(positional.next().as_deref())?;
    let config = positional.next().map(PathBuf::from);
    if positional.next().is_some() {
        return Err("too many arguments".into());
    }
    Ok(UseraddArgs {
        username,
        password,
        class,
        config,
        allow_root,
    })
}

/// `guest|user|power|admin` → base class number (default `user`).
pub fn parse_class(class: Option<&str>) -> Result<i64, String> {
    match class {
        None | Some("user") => Ok(1),
        Some("guest") => Ok(0),
        Some("power") => Ok(2),
        Some("admin") => Ok(3),
        Some(other) => Err(format!(
            "unknown class '{other}' (expected guest|user|power|admin)"
        )),
    }
}

/// The rules a new username must meet (the same bound the login path uses).
pub fn validate_username(username: &str) -> Result<(), String> {
    if username.trim().is_empty() {
        return Err("username must not be empty".into());
    }
    if username.trim() != username {
        return Err("username must not start or end with whitespace".into());
    }
    if username.len() > MAX_USERNAME_LEN {
        return Err(format!("username is longer than {MAX_USERNAME_LEN} bytes"));
    }
    if username.chars().any(char::is_control) {
        return Err("username must not contain control characters".into());
    }
    Ok(())
}

pub fn validate_password(password: &str) -> Result<(), String> {
    if password.is_empty() {
        return Err("password must not be empty".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn run_args() {
        assert_eq!(
            parse_run(&args(&[])).unwrap(),
            RunArgs {
                config: None,
                allow_root: false
            }
        );
        assert_eq!(
            parse_run(&args(&["--allow-root", "/etc/kdx/kdxd.toml"])).unwrap(),
            RunArgs {
                config: Some("/etc/kdx/kdxd.toml".into()),
                allow_root: true
            }
        );
        assert!(parse_run(&args(&["a.toml", "b.toml"])).is_err());
        assert!(parse_run(&args(&["--bogus"])).is_err());
    }

    #[test]
    fn useradd_password_sources() {
        let only_user = parse_useradd(&args(&["bob"])).unwrap();
        assert_eq!(only_user.password, PasswordSource::Prompt);
        assert_eq!(only_user.class, 1);
        assert_eq!(only_user.config, None);

        let stdin = parse_useradd(&args(&["bob", "--password-stdin", "power", "k.toml"])).unwrap();
        assert_eq!(stdin.password, PasswordSource::Stdin);
        assert_eq!(stdin.class, 2);
        assert_eq!(stdin.config, Some("k.toml".into()));

        let prompt = parse_useradd(&args(&["--prompt", "bob", "admin", "--allow-root"])).unwrap();
        assert_eq!(prompt.password, PasswordSource::Prompt);
        assert_eq!(prompt.class, 3);
        assert!(prompt.allow_root);

        // The old positional form keeps working.
        let legacy = parse_useradd(&args(&["bob", "s3cret", "guest", "k.toml"])).unwrap();
        assert_eq!(legacy.password, PasswordSource::Argv("s3cret".into()));
        assert_eq!(legacy.class, 0);
        assert_eq!(legacy.config, Some("k.toml".into()));
    }

    #[test]
    fn useradd_rejects_bad_invocations() {
        assert!(parse_useradd(&args(&[])).is_err());
        assert!(parse_useradd(&args(&["bob", "--password-stdin", "wizard"])).is_err());
        assert!(parse_useradd(&args(&["bob", "--prompt", "--password-stdin"])).is_err());
        assert!(parse_useradd(&args(&["bob", "pw", "user", "k.toml", "extra"])).is_err());
        assert!(parse_useradd(&args(&["bob", "--pasword-stdin"])).is_err());
    }

    #[test]
    fn account_field_rules() {
        assert!(validate_username("phraq").is_ok());
        assert!(validate_username("").is_err());
        assert!(validate_username("   ").is_err());
        assert!(validate_username(" phraq").is_err());
        assert!(validate_username("ph\nraq").is_err());
        assert!(validate_username(&"u".repeat(MAX_USERNAME_LEN + 1)).is_err());
        assert!(validate_password("").is_err());
        assert!(validate_password(" ").is_ok());
    }
}
