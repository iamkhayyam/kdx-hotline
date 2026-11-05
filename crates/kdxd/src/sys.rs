//! Small OS-level helpers for the daemon binary: the umask, the root guard,
//! and password input for `kdxd useradd`.

use std::io::{self, BufRead};

/// Refuse to run as root unless the operator explicitly opted in. kdxd needs
/// no privilege (port 10700 is unprivileged); as root every bug in it is a
/// root bug, and the database, key and logs it creates end up root-owned,
/// which breaks a later start as the service user.
pub fn check_not_root(euid: u32, allow_root: bool) -> Result<(), String> {
    if euid == 0 && !allow_root {
        Err("refusing to run as root: kdxd needs no privileges, and files it creates \
             would be owned by root. Run it as its service user (for example \
             `sudo -u kdx kdxd ...`), or pass --allow-root to override."
            .to_string())
    } else {
        Ok(())
    }
}

/// The process's effective user id.
#[cfg(unix)]
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// Make every file and directory the process creates private to its owner
/// (umask 077): the database, its WAL/SHM files, uploads, the dev key.
#[cfg(unix)]
pub fn restrict_umask() {
    // SAFETY: umask has no preconditions and cannot fail.
    unsafe {
        libc::umask(0o077);
    }
}

/// One line from `input`, without its line ending.
pub fn read_password_line(input: &mut impl BufRead) -> io::Result<String> {
    let mut line = String::new();
    input.read_line(&mut line)?;
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(line)
}

/// Show `prompt` on the controlling terminal and read one line from it with
/// echo turned off.
#[cfg(unix)]
pub fn prompt_password(prompt: &str) -> io::Result<String> {
    use std::io::Write;
    use std::os::fd::AsRawFd;

    struct RestoreTerminal {
        fd: i32,
        original: libc::termios,
    }
    impl Drop for RestoreTerminal {
        fn drop(&mut self) {
            // SAFETY: `fd` is the open terminal; `original` came from tcgetattr.
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
            }
        }
    }

    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("no terminal to prompt on ({e}); use --password-stdin"),
            )
        })?;
    let fd = tty.as_raw_fd();
    let mut term = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: `fd` is open; tcgetattr fills `term` on success.
    if unsafe { libc::tcgetattr(fd, term.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: initialised by the successful tcgetattr above.
    let original = unsafe { term.assume_init() };
    let mut silent = original;
    silent.c_lflag &= !libc::ECHO;
    silent.c_lflag |= libc::ECHONL;

    tty.write_all(prompt.as_bytes())?;
    tty.flush()?;
    // SAFETY: `fd` is open and `silent` is a valid termios.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &silent) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let _restore = RestoreTerminal { fd, original };
    read_password_line(&mut io::BufReader::new(&tty))
}

/// No portable no-echo prompt here: point the operator at `--password-stdin`.
#[cfg(not(unix))]
pub fn prompt_password(_prompt: &str) -> io::Result<String> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "password prompt not available on this platform; use --password-stdin",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_guard() {
        assert!(check_not_root(0, false).is_err());
        assert!(check_not_root(0, true).is_ok());
        assert!(check_not_root(1000, false).is_ok());
        assert!(check_not_root(1000, true).is_ok());
    }

    #[test]
    fn password_line_strips_only_the_line_ending() {
        let read = |s: &str| read_password_line(&mut s.as_bytes()).unwrap();
        assert_eq!(read("s3cret\n"), "s3cret");
        assert_eq!(read("s3cret\r\n"), "s3cret");
        assert_eq!(read(" spaced out \n"), " spaced out ");
        assert_eq!(read("no newline"), "no newline");
        assert_eq!(read("first\nsecond\n"), "first");
        assert_eq!(read(""), "");
    }
}
