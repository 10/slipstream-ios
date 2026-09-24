//! One-request, root-only API. Saved credentials go only to the authorized caller.
use super::*;
use serde_json::{Value, json};
use slipstream::profiles::{Library, MAX_IMPORT_BYTES, Proxy, ProxyKind, parse_list};
use std::{
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};
const LIBRARY: &str = installed!("/etc/slipstream/proxies.json");

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Status,
    Apps,
    SetAppRouting {
        routing: slipstream::app_routing::AppRouting,
    },
    TestConnection {
        id: u64,
    },
    Import {
        name: String,
        text: String,
        #[serde(default, rename = "type")]
        kind: ProxyKind,
    },
    Select {
        id: u64,
    },
    DeleteProxy {
        id: u64,
    },
    DeleteList {
        id: u64,
    },
    RenameList {
        id: u64,
        name: String,
    },
    Enable,
    Disable,
    Restart,
}
impl Request {
    fn context(&self) -> &'static str {
        match self {
            Self::Status => "refresh protection status",
            Self::Apps => "read installed apps",
            Self::SetAppRouting { .. } => "save app routing",
            Self::TestConnection { .. } => "test the proxy",
            Self::Import { .. } => "import the proxy list",
            Self::Select { .. } => "switch proxies",
            Self::DeleteProxy { .. } => "remove this proxy",
            Self::DeleteList { .. } => "delete this list",
            Self::RenameList { .. } => "rename this list",
            Self::Enable => "turn protection on",
            Self::Disable => "turn protection off",
            Self::Restart => "restart the connection",
        }
    }
}
fn public_error(error: &(dyn std::error::Error + 'static), context: &str) -> String {
    if error.is::<std::io::Error>() {
        format!(
            "Could not {context}. Refresh status, then retry. If this continues, reopen Slipstream after jailbreaking."
        )
    } else {
        error.to_string()
    }
}

pub(super) fn atomic_write<T: Serialize>(path: &str, value: &T) -> Result<()> {
    let temp = format!("{path}.new");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(&serde_json::to_vec(value)?)?;
    file.sync_all()?;
    fs::rename(temp, path)?;
    Ok(())
}
fn library() -> Result<Library> {
    let mut changed = !Path::new(LIBRARY).exists();
    let mut lib = if Path::new(LIBRARY).exists() {
        let m = fs::metadata(LIBRARY)?;
        if m.uid() != 0 || m.mode() & 0o077 != 0 {
            return Err("Saved lists need root ownership and private permissions.".into());
        }
        serde_json::from_slice::<Library>(&fs::read(LIBRARY)?)
            .map_err(|_| "Saved lists could not be read. They have not been replaced.")?
    } else {
        Library::default()
    };
    // Reconcile saved selection with configuration changes made through the CLI.
    if Path::new(CONFIG).exists() {
        let config = config().map_err(
            |_| "The saved connection could not be read. Its file has not been changed.",
        )?;
        let current = Proxy::from_url(&config.proxy)?;
        let matches = |p: &Proxy| {
            p.host == current.host
                && p.port == current.port
                && p.username == current.username
                && p.password == current.password
                && p.kind == current.kind
        };
        if !lib.selected.and_then(|id| lib.get(id)).is_some_and(matches) {
            changed = true;
            lib.selected = lib
                .lists
                .iter()
                .flat_map(|g| &g.proxies)
                .find(|p| matches(p))
                .map(|p| p.id);
            if lib.selected.is_none() {
                lib.add("Current proxy", vec![current.clone()])?;
                lib.selected = lib
                    .lists
                    .iter()
                    .flat_map(|g| &g.proxies)
                    .find(|p| matches(p))
                    .map(|p| p.id);
            }
        }
    } else {
        changed |= lib.selected.take().is_some();
    }
    if changed {
        atomic_write(LIBRARY, &lib)?;
    }
    Ok(lib)
}
fn snapshot(lib: &Library) -> Result<Value> {
    let status = protection_status()?;
    let state = status.split(' ').next().unwrap_or("unknown");
    Ok(
        json!({"state":state,"enabled":Path::new(ENABLED).exists(),"selected":lib.selected,"network":network_label(),"lists":lib.lists,"app_routing":per_app::load()?}),
    )
}
fn ctl(action: &str) -> Result<()> {
    // Commands are fixed enum values, never shell input or proxy credentials.
    let result = Command::new(installed!("/usr/local/bin/slipstream"))
        .arg(action)
        .output()?;
    if !result.status.success() {
        return Err(match action {
            "disable" => "Protection could not be turned off. Refresh status and retry.",
            _ => {
                "The change was saved, but the tunnel is not ready. Retry or choose another proxy."
            }
        }
        .into());
    }
    Ok(())
}
fn remove_selection(lib: &mut Library, removes_selected: bool) -> Result<()> {
    if removes_selected {
        if Path::new(ENABLED).exists() || protection_status()? != "disabled" {
            return Err(
                "Turn protection off or select another proxy before removing the selected proxy."
                    .into(),
            );
        }
        if Path::new(CONFIG).exists() {
            fs::remove_file(CONFIG)?;
        }
        lib.selected = None;
    }
    Ok(())
}
#[derive(Default)]
struct Outcome {
    message: Option<String>,
    latency_ms: Option<u64>,
    /// `relayed`, `unsupported` (SOCKS5 refused UDP ASSOCIATE) or `blocked` (HTTP).
    udp: Option<&'static str>,
}
fn apply(request: Request, lib: &mut Library) -> Result<Outcome> {
    match request {
        Request::Status | Request::Apps => return Ok(Outcome::default()),
        Request::SetAppRouting { routing } => {
            per_app::save(routing)?;
            if Path::new(ENABLED).exists() {
                ctl("restart")?;
            }
            return Ok(Outcome::default());
        }
        Request::TestConnection { id } => {
            if lib.selected != Some(id) || protection_status()? != "protected" {
                return Err("Select a proxy and enable protection before testing.".into());
            }
            let response = Command::new(installed!("/Applications/Slipstream.app/slipstream-helper"))
                .arg("--latency")
                .output()?;
            if !response.status.success() {
                return Err("Proxy did not respond.".into());
            }
            let text = String::from_utf8_lossy(&response.stdout);
            let mut fields = text.split_whitespace();
            let latency = fields
                .next()
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or("Proxy did not respond.")?;
            let word = fields.next();
            let udp = ["relayed", "unsupported", "blocked"]
                .into_iter()
                .find(|&v| Some(v) == word);
            return Ok(Outcome {
                latency_ms: Some(latency),
                udp,
                ..Outcome::default()
            });
        }
        Request::Import { name, text, kind } => {
            let entries = parse_list(&text, kind)?;
            let n = lib.add(&name, entries)?;
            atomic_write(LIBRARY, lib)?;
            return Ok(Outcome {
                message: Some(if n == 0 {
                    "These proxies are already in this list.".into()
                } else {
                    format!("Imported {n} {}.", if n == 1 { "proxy" } else { "proxies" })
                }),
                ..Outcome::default()
            });
        }
        Request::Select { id } => {
            let p = lib
                .get(id)
                .ok_or("This proxy is no longer saved. Refresh the list.")?;
            let c = Config {
                proxy: p.url(),
                proxy_ip: p.host,
                proxy_port: p.port,
            };
            atomic_write(CONFIG, &c)?;
            lib.selected = Some(id);
            atomic_write(LIBRARY, lib)?;
            ctl(if Path::new(ENABLED).exists() {
                "restart"
            } else {
                "enable"
            })?;
        }
        Request::Enable => {
            if lib.selected.is_none() {
                return Err("Import a list and select a proxy first.".into());
            }
            ctl("enable")?;
        }
        Request::Disable => ctl("disable")?,
        Request::Restart => ctl("restart")?,
        Request::DeleteProxy { id } => {
            if lib.get(id).is_none() {
                return Err("This proxy is no longer saved.".into());
            }
            remove_selection(lib, lib.selected == Some(id))?;
            for group in &mut lib.lists {
                group.proxies.retain(|p| p.id != id);
            }
        }
        Request::DeleteList { id } => {
            let group = lib
                .lists
                .iter()
                .find(|g| g.id == id)
                .ok_or("This list is no longer saved.")?;
            let selected = group.proxies.iter().any(|p| Some(p.id) == lib.selected);
            remove_selection(lib, selected)?;
            lib.lists.retain(|g| g.id != id);
        }
        Request::RenameList { id, name } => {
            let name = name.trim();
            if name.is_empty() || name.chars().count() > 40 || name.chars().any(char::is_control) {
                return Err("Use a list name of 1–40 characters.".into());
            }
            if lib
                .lists
                .iter()
                .any(|g| g.id != id && g.name.to_lowercase() == name.to_lowercase())
            {
                return Err("A list with this name already exists.".into());
            }
            lib.lists
                .iter_mut()
                .find(|g| g.id == id)
                .ok_or("This list is no longer saved.")?
                .name = name.into();
        }
    }
    atomic_write(LIBRARY, lib)?;
    Ok(Outcome::default())
}
fn request() -> Result<Value> {
    fs::create_dir_all(installed!("/etc/slipstream"))?;
    let file = fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(installed!("/etc/slipstream/control.lock"))?;
    if file.try_lock().is_err() {
        return Err("Another change is still in progress. Try again shortly.".into());
    }
    let mut input = vec![];
    std::io::stdin()
        .take((MAX_IMPORT_BYTES * 2 + 1) as u64)
        .read_to_end(&mut input)?;
    if input.len() > MAX_IMPORT_BYTES * 2 {
        return Err("The request is too large.".into());
    }
    let request: Request =
        serde_json::from_slice(&input).map_err(|_| "The app sent an invalid request.")?;
    // A damaged list/config must never prevent explicitly turning protection off.
    if matches!(request, Request::Disable) {
        ctl("disable")?;
        let lib = library().unwrap_or_default();
        return Ok(json!({"ok":true,"snapshot":snapshot(&lib)?}));
    }
    if matches!(request, Request::Apps) {
        return Ok(json!({"ok":true,"apps":per_app::apps()?}));
    }
    let mut lib = match library() {
        Ok(lib) => lib,
        Err(e) if matches!(request, Request::Status) => {
            return Ok(
                json!({"ok":false,"message":public_error(e.as_ref(), "read saved lists"),"snapshot":snapshot(&Library::default())?}),
            );
        }
        Err(e) => return Err(e),
    };
    let context = request.context();
    let result = apply(request, &mut lib);
    // Reflect saved selection and actual protection even when starting failed.
    let snapshot = snapshot(&lib)?;
    Ok(match result {
        Ok(outcome) => {
            json!({"ok":true,"snapshot":snapshot,"message":outcome.message,"latency_ms":outcome.latency_ms,"udp":outcome.udp})
        }
        Err(e) => {
            json!({"ok":false,"snapshot":snapshot,"message":public_error(e.as_ref(),context)})
        }
    })
}
pub fn handle() {
    let response = request().unwrap_or_else(|e| {
        json!({"ok":false,"message":public_error(e.as_ref(),"read the device’s state")})
    });
    println!("{response}");
}
