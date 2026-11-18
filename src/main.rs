// Rootless jailbreaks install under /var/jb; rootful ones use /. Set by build.rs.
macro_rules! installed {
    ($path:literal) => {
        concat!(env!("SLIPSTREAM_PREFIX"), $path)
    };
}
mod control;
mod lifecycle;
mod native;
mod store;

use slipstream::check::UdpRelay;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

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
        "enable" | "restart" | "disable" => lifecycle::run(&action),
        "status" => lifecycle::status().map(|s| println!("{s}")),
        "check" => check(),
        "manage" => {
            control::handle();
            Ok(())
        }
        _ => Err("usage: slipstream enable|restart|disable|status|check|manage".into()),
    };
    if let Err(error) = result {
        eprintln!("slipstream: {error}");
        std::process::exit(1);
    }
}

/// Test Connection from SSH: the selected proxy's handshake latency and UDP relay.
fn check() -> Result<()> {
    if lifecycle::status()? != lifecycle::State::Protected {
        return Err("Protection is not connected.".into());
    }
    let check = native::provider_check()?;
    let udp = match check.udp {
        Some(UdpRelay::Relayed) => "relayed",
        Some(UdpRelay::Unsupported) => "not relayed",
        Some(UdpRelay::Blocked) => "blocked",
        None => "unknown",
    };
    println!("{} ms, UDP {udp}", check.latency_ms);
    Ok(())
}
