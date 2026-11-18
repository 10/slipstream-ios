//! Turning protection on, off or over to new settings, and reading its state. Runs as root
//! under one lock, so changes from the app and from SSH do not interleave.
use crate::{Result, native, store};
use serde::Serialize;
use std::{
    fs,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::{Duration, Instant},
};

/// Present while protection is on. Holds `starting` until a change completes, so an old
/// connection is not reported as a completed switch.
const ENABLED: &str = installed!("/etc/slipstream/enabled");
const LOCK: &str = installed!("/var/run/slipstream/provider.lock");

#[derive(Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// The configuration is enabled and its session connected. The proxy may still be down.
    Protected,
    /// The session is reconnecting, or a change has not completed.
    Starting,
    /// Protection is on, but the configuration is missing or inactive.
    Unavailable,
    Disabled,
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            State::Protected => "protected",
            State::Starting => "starting (tunnel reconnecting)",
            State::Unavailable => "unavailable (tunnel configuration inactive)",
            State::Disabled => "disabled",
        })
    }
}

pub fn enabled() -> bool {
    Path::new(ENABLED).exists()
}

fn locked<T>(body: impl FnOnce() -> Result<T>) -> Result<T> {
    fs::create_dir_all(Path::new(LOCK).parent().unwrap())?;
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(LOCK)?;
    // Another call, such as a status read over SSH, usually holds the lock for a moment. The wait
    // leaves most of the 45-second deadline for this call's own work.
    let waiting = Instant::now();
    while lock.try_lock().is_err() {
        if waiting.elapsed() > Duration::from_secs(10) {
            return Err("Another tunnel change is in progress. Retry shortly.".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    body()
}

fn state() -> Result<State> {
    let tunnel = native::tunnel_status()?;
    let pending = fs::read(ENABLED).is_ok_and(|b| b == b"starting\n");
    Ok(if tunnel.enabled && tunnel.connected && !pending {
        State::Protected
    } else if tunnel.enabled {
        State::Starting
    } else if enabled() {
        State::Unavailable
    } else {
        State::Disabled
    })
}

pub fn status() -> Result<State> {
    locked(state)
}

/// Marks protection pending: on, with a change not yet applied.
fn mark_pending() -> Result<fs::File> {
    let marker = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(ENABLED)?;
    (&marker).write_all(b"starting\n")?;
    marker.sync_all()?;
    Ok(marker)
}

/// Saves settings for the next enable or restart to apply. While protection is on, the change is
/// marked pending first, so status never reports saved settings as applied before they are.
pub fn stage(save: impl FnOnce() -> Result<()>) -> Result<()> {
    locked(|| {
        if enabled() {
            mark_pending()?;
        }
        save()
    })
}

/// Runs `enable`, `restart` or `disable` and prints the resulting state.
pub fn run(action: &str) -> Result<()> {
    let state = locked(|| {
        if action == "disable" {
            native::tunnel_remove()?;
            match fs::remove_file(ENABLED) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                _ => (),
            }
        } else {
            if action == "restart" && !enabled() {
                return Err("Protection is off.".into());
            }
            let library = store::library()?;
            let proxy = library
                .selected_proxy()
                .ok_or("Import a list and select a proxy first.")?;
            // The saved selection may already name a proxy the provider does not use yet, so the
            // change is pending until it is applied.
            let marker = mark_pending()?;
            native::tunnel_apply(&native::Settings {
                proxy_url: proxy.url(),
                proxy_ip: proxy.host,
                bundle_ids: store::routing()?.routed(&native::catalog()?)?,
            })?;
            marker.set_len(0)?;
            marker.sync_all()?;
        }
        state()
    })?;
    println!("{state}");
    Ok(())
}
