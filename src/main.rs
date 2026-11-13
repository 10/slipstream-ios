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
