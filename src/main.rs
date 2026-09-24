// Rootless jailbreaks install under /var/jb; rootful ones use /. Set by build.rs.
macro_rules! installed {
    ($path:literal) => {
        concat!(env!("SLIPSTREAM_PREFIX"), $path)
    };
}
mod control;
mod per_app;
use serde::{Deserialize, Serialize};
use slipstream::app_routing::Mode;
use std::{
    ffi::{CStr, CString},
    fs,
    net::Ipv4Addr,
    os::unix::fs::OpenOptionsExt,
    process::Command,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const DIR: &str = installed!("/var/run/slipstream");
const CONFIG: &str = installed!("/etc/slipstream/config.json");
const ENABLED: &str = installed!("/etc/slipstream/enabled");
#[derive(Serialize, Deserialize)]
struct Config {
    proxy: String,
    proxy_ip: Ipv4Addr,
    proxy_port: u16,
}
unsafe extern "C" {
    fn slipstream_interface() -> *mut libc::c_char;
    fn slipstream_tunnel(
        action: *const libc::c_char,
        json: *const libc::c_char,
    ) -> *mut libc::c_char;
}
fn config() -> Result<Config> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::metadata(CONFIG)?;
    if m.uid() != 0 || m.mode() & 0o077 != 0 {
        return Err("config must be owned by root with mode 600".into());
    }
    let c: Config = serde_json::from_slice(&fs::read(CONFIG)?)?;
    if !(c.proxy.starts_with("http://") || c.proxy.starts_with("socks5://"))
        || c.proxy_port == 0
        || c.proxy_ip.is_unspecified()
        || c.proxy_ip.is_multicast()
        || c.proxy_ip.is_broadcast()
    {
        return Err("an HTTP CONNECT or SOCKS5 proxy is required".into());
    }
    Ok(c)
}

fn tunnel(action: &str) -> Result<serde_json::Value> {
    fs::create_dir_all(DIR)?;
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .open(format!("{DIR}/provider.lock"))?;
    if lock.try_lock().is_err() {
        return Err("Another tunnel change is in progress. Retry shortly.".into());
    }
    let settings = if matches!(action, "enable" | "restart") {
        let c = config()?;
        let parsed = slipstream::profiles::Proxy::from_url(&c.proxy)?;
        if parsed.host != c.proxy_ip || parsed.port != c.proxy_port {
            return Err("Proxy URL and endpoint differ.".into());
        }
        // App rules choose the flows iOS sends to the app proxy. All apps names every app the user
        // installed, so an app installed later joins at the next restart.
        let routing = per_app::load()?;
        let mut bundle_ids = match routing.mode {
            Mode::All => per_app::eligible()?,
            Mode::Selected => routing.bundle_ids,
        };
        // The app's exit-IP check must use the same path as the protected apps.
        if !bundle_ids.iter().any(|id| id == "local.slipstream.app") {
            bundle_ids.push("local.slipstream.app".into());
        }
        Some(CString::new(serde_json::to_string(
            &serde_json::json!({"proxy_url":c.proxy,"proxy_ip":c.proxy_ip,"bundle_ids":bundle_ids}),
        )?)?)
    } else {
        None
    };
    let action = CString::new(action)?;
    let raw = unsafe {
        slipstream_tunnel(
            action.as_ptr(),
            settings.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
        )
    };
    if raw.is_null() {
        return Err("Could not read the tunnel state.".into());
    }
    let parsed =
        serde_json::from_slice::<serde_json::Value>(unsafe { CStr::from_ptr(raw).to_bytes() });
    unsafe {
        libc::free(raw.cast());
    }
    let value = parsed?;
    if let Some(error) = value["error"].as_str() {
        return Err(error.to_owned().into());
    }
    Ok(value)
}
fn protection_status() -> Result<&'static str> {
    let state = tunnel("status")?;
    let pending = fs::read(ENABLED).is_ok_and(|b| b == b"starting\n");
    Ok(
        if state["enabled"] == true && state["status"] == 3 && !pending {
            "protected"
        } else if state["enabled"] == true {
            "starting (tunnel reconnecting)"
        } else if std::path::Path::new(ENABLED).exists() {
            "unavailable (tunnel configuration inactive)"
        } else {
            "disabled"
        },
    )
}
fn lifecycle(action: &str) -> Result<()> {
    if action == "disable" {
        tunnel(action)?;
        match fs::remove_file(ENABLED) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    } else {
        config()?;
        if action == "restart" && !std::path::Path::new(ENABLED).exists() {
            return Err("Protection is off.".into());
        }
        // Do not show a successful switch until the new provider has connected.
        let marker = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(ENABLED)?;
        use std::io::Write;
        (&marker).write_all(b"starting\n")?;
        marker.sync_all()?;
        tunnel(action)?;
        marker.set_len(0)?;
        marker.sync_all()?;
    }
    println!("{}", protection_status()?);
    Ok(())
}
fn network_label() -> Option<&'static str> {
    let raw = unsafe { slipstream_interface() };
    if raw.is_null() {
        return None;
    }
    let name = unsafe { CStr::from_ptr(raw) }.to_bytes();
    let label = if name == b"en0" {
        "Wi-Fi"
    } else if name.starts_with(b"pdp_ip") {
        "Cellular"
    } else {
        "Network"
    };
    unsafe {
        libc::free(raw.cast());
    }
    Some(label)
}
fn main() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("slipstream requires root");
        std::process::exit(1);
    }
    unsafe {
        libc::umask(0o077);
    }
    let action = std::env::args().nth(1).unwrap_or_else(|| "status".into());
    // Private session calls must not retain the lifecycle lock indefinitely.
    // Leave the UUID journal and pending marker intact if the deadline expires.
    unsafe {
        libc::alarm(if action == "manage" { 55 } else { 45 });
    }
    let result: Result<()> = match action.as_str() {
        "enable" | "restart" | "disable" => lifecycle(&action),
        "status" => protection_status().map(|s| println!("{s}")),
        "backend" => {
            println!("native");
            Ok(())
        }
        "manage" => {
            control::handle();
            Ok(())
        }
        _ => Err("usage: slipstream enable|restart|disable|status|manage".into()),
    };
    if let Err(error) = result {
        eprintln!("slipstream: {error}");
        std::process::exit(1);
    }
}
