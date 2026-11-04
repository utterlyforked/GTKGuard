//! Everything that touches the system: tunnel names, up/down state, and privileged
//! operations via `sudo`. No GTK in here so it can be unit tested.
//!
//! Security rules:
//! - Config contents are never logged or returned in errors.
//! - Commands run via `Command` with discrete args (never a shell); names are validated first.
//! - Configs live in /etc/wireguard owned by root (0600), never in a user-writable dir.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Linux interface names are limited to 15 bytes.
pub const MAX_NAME: usize = 15;
const MAX_CONF_BYTES: u64 = 64 * 1024;

/// A password held in memory. Zeroed on drop (best effort).
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(s: &str) -> Self {
        Secret(s.as_bytes().to_vec())
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Clone for Secret {
    fn clone(&self) -> Self {
        Secret(self.0.clone())
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            // SAFETY: `b` is a valid, exclusive reference to a byte.
            unsafe { std::ptr::write_volatile(b as *mut u8, 0) };
        }
    }
}

#[derive(Debug)]
pub enum SudoError {
    BadPassword,
    Failed(String),
}

// ---------- names ----------

/// Same rule as wg-quick: `^[a-zA-Z0-9_=+.-]{1,15}$`, and we also refuse a leading '-'
/// so a name can never be mistaken for an option.
pub fn is_valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= MAX_NAME
        && !n.starts_with('-')
        && n.chars().all(|c| c.is_ascii_alphanumeric() || "_=+.-".contains(c))
}

/// Turn a file stem into a legal interface name (invalid chars -> '_', max 15, no leading '-').
pub fn sanitize_name(stem: &str) -> String {
    let s: String = stem
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || "_=+.-".contains(c) { c } else { '_' })
        .collect();
    let s = s.trim_start_matches('-');
    let s: String = s.chars().take(MAX_NAME).collect();
    if s.is_empty() { "tunnel".into() } else { s }
}

// ---------- app's own tunnel list (names only, not secret) ----------

fn list_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("gtkguard").join("tunnels")
}

pub fn load_names() -> Vec<String> {
    let text = fs::read_to_string(list_path()).unwrap_or_default();
    let mut names: Vec<String> = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if is_valid_name(l) && !names.iter().any(|n| n == l) {
            names.push(l.to_string());
        }
    }
    names
}

pub fn save_names(names: &[String]) -> std::io::Result<()> {
    let p = list_path();
    if let Some(dir) = p.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(p, names.join("\n") + "\n")
}

// ---------- state ----------

/// A WireGuard interface exists in sysfs exactly while the tunnel is up. No privileges needed.
pub fn is_up(name: &str) -> bool {
    is_valid_name(name) && PathBuf::from("/sys/class/net").join(name).exists()
}

// ---------- config validation ----------

/// Cheap structural check. Never echoes any value from the file.
pub fn validate_conf(text: &str) -> Result<(), String> {
    let (mut iface, mut peer, mut key) = (false, false, false);
    for line in text.lines() {
        let l = line.split('#').next().unwrap_or("").trim();
        if l.is_empty() {
            continue;
        }
        if l.eq_ignore_ascii_case("[interface]") {
            iface = true;
        } else if l.eq_ignore_ascii_case("[peer]") {
            peer = true;
        } else if let Some((k, _)) = l.split_once('=') {
            match k.trim().to_ascii_lowercase().as_str() {
                "preup" | "postup" | "predown" | "postdown" => {
                    return Err("It contains PreUp/PostUp/PreDown/PostDown commands, which would \
                                run as root. Refusing to import it."
                        .into());
                }
                "privatekey" => key = true,
                _ => {}
            }
        }
    }
    if !iface || !peer || !key {
        return Err("This doesn't look like a WireGuard config (needs [Interface] with a \
                    PrivateKey, and a [Peer])."
            .into());
    }
    Ok(())
}

pub fn read_conf(path: &std::path::Path) -> Result<String, String> {
    let meta = fs::metadata(path).map_err(|e| format!("Can't read the file: {e}"))?;
    if meta.len() > MAX_CONF_BYTES {
        return Err("File is too large to be a WireGuard config.".into());
    }
    fs::read_to_string(path).map_err(|e| format!("Can't read the file: {e}"))
}

// ---------- sudo ----------

struct Out {
    ok: bool,
    stderr: String,
}

fn tail(s: &str) -> String {
    let s = s.trim();
    let n = s.chars().count();
    if n > 800 { s.chars().skip(n - 800).collect() } else { s.to_string() }
}

/// Run `sudo -S -p "" <args>`, feeding the password on stdin.
fn sudo(pw: &Secret, args: &[&str]) -> Result<Out, SudoError> {
    let mut child = Command::new("sudo")
        .args(["-S", "-p", ""])
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| SudoError::Failed(format!("Couldn't run sudo: {e}")))?;

    if let Some(mut stdin) = child.stdin.take() {
        // sudo may use a cached credential and never read this; ignore EPIPE.
        let _ = stdin.write_all(&pw.0);
        let _ = stdin.write_all(b"\n");
    }
    let out = child
        .wait_with_output()
        .map_err(|e| SudoError::Failed(format!("sudo failed: {e}")))?;
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    if !out.status.success() {
        let l = stderr.to_ascii_lowercase();
        if l.contains("incorrect password")
            || l.contains("no password was provided")
            || l.contains("sorry, try again")
            || l.contains("a password is required")
        {
            return Err(SudoError::BadPassword);
        }
    }
    Ok(Out { ok: out.status.success(), stderr })
}

/// Bring a tunnel up or down with `wg-quick`.
pub fn set_tunnel(pw: &Secret, name: &str, up: bool) -> Result<(), SudoError> {
    if !is_valid_name(name) {
        return Err(SudoError::Failed("Invalid tunnel name.".into()));
    }
    let out = sudo(pw, &["wg-quick", if up { "up" } else { "down" }, name])?;
    if out.ok {
        Ok(())
    } else {
        Err(SudoError::Failed(tail(&out.stderr)))
    }
}

/// Install a validated config as /etc/wireguard/<name>.conf, root-owned, mode 0600.
/// The contents go through a private temp file in $XDG_RUNTIME_DIR (0700, 0600 file).
pub fn install_conf(pw: &Secret, name: &str, text: &str) -> Result<(), SudoError> {
    let fail = |m: String| SudoError::Failed(m);
    if !is_valid_name(name) {
        return Err(fail("Invalid tunnel name.".into()));
    }
    let dest = format!("/etc/wireguard/{name}.conf");

    // Doubles as the password check, and avoids silently overwriting an existing config.
    if sudo(pw, &["test", "-e", &dest])?.ok {
        return Err(fail(format!("{dest} already exists.")));
    }

    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .ok_or_else(|| fail("XDG_RUNTIME_DIR is not set.".into()))?;
    let tmp = PathBuf::from(runtime).join(format!("gtkguard-{}-{name}.conf", std::process::id()));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| fail(format!("Couldn't create temp file: {e}")))?;
    let written = f.write_all(text.as_bytes());
    drop(f);

    let result = (|| {
        written.map_err(|e| fail(format!("Couldn't write temp file: {e}")))?;
        let tmp_s = tmp.to_str().ok_or_else(|| fail("Bad temp path.".into()))?;
        let a = sudo(pw, &["install", "-d", "-m", "0700", "-o", "root", "-g", "root", "/etc/wireguard"])?;
        if !a.ok {
            return Err(fail(tail(&a.stderr)));
        }
        let b = sudo(pw, &["install", "-m", "0600", "-o", "root", "-g", "root", tmp_s, &dest])?;
        if !b.ok {
            return Err(fail(tail(&b.stderr)));
        }
        Ok(())
    })();
    let _ = fs::remove_file(&tmp);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = def\nEndpoint = 1.2.3.4:51820\n";

    #[test]
    fn names() {
        assert!(is_valid_name("office_vpn"));
        assert!(is_valid_name("a"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("my_long_tunnel_x")); // 16 chars
        assert!(!is_valid_name("-x"));
        assert!(!is_valid_name("a/b"));
        assert!(!is_valid_name("a b"));
        assert!(!is_valid_name("../x"));
    }

    #[test]
    fn sanitize() {
        assert_eq!(sanitize_name("my_long_tunnel_x"), "my_long_tunnel_");
        assert!(is_valid_name(&sanitize_name("my_long_tunnel_x")));
        assert_eq!(sanitize_name("my vpn!"), "my_vpn_");
        assert_eq!(sanitize_name("---"), "tunnel");
        assert_eq!(sanitize_name(""), "tunnel");
        assert!(is_valid_name(&sanitize_name("ünïcode name that is very long")));
    }

    #[test]
    fn conf_ok() {
        assert!(validate_conf(GOOD).is_ok());
    }

    #[test]
    fn conf_rejects_hooks() {
        for k in ["PostUp", "preup", "PostDown", "PREDOWN"] {
            let t = format!("{GOOD}{k} = rm -rf /\n");
            assert!(validate_conf(&t).is_err(), "{k}");
        }
        // A hook hidden after a comment marker is a comment, not a hook.
        assert!(validate_conf(&format!("{GOOD}# PostUp = x\n")).is_ok());
    }

    #[test]
    fn conf_rejects_garbage() {
        assert!(validate_conf("hello").is_err());
        assert!(validate_conf("[Interface]\nAddress=1.1.1.1/32\n[Peer]\n").is_err()); // no key
        assert!(validate_conf("[Interface]\nPrivateKey=x\n").is_err()); // no peer
    }

    #[test]
    fn errors_never_echo_contents() {
        let e = validate_conf("[Interface]\nPrivateKey = SECRETSECRET\nPostUp = x\n[Peer]\n").unwrap_err();
        assert!(!e.contains("SECRETSECRET"));
    }
}
