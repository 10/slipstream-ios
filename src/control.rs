//! The app's one-request API, run as root. Saved credentials go only to the authorized app.
use crate::{
    Result,
    lifecycle::{self, State, enabled},
    native, store,
};
use serde::Deserialize;
use serde_json::{Value, json};
use slipstream::{
    app_routing::{self, AppRouting, Mode},
    check::Check,
    profiles::{Library, MAX_IMPORT_BYTES, ProxyKind, parse_list},
};
use std::{fs, io::Read, os::unix::fs::OpenOptionsExt, process::Command};

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Status,
    Apps,
    SetAppRouting {
        routing: AppRouting,
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
    if error.is::<std::io::Error>() || error.is::<serde_json::Error>() {
        format!(
            "Could not {context}. Refresh status, then retry. If this continues, reopen Slipstream after jailbreaking."
        )
    } else {
        error.to_string()
    }
}

fn snapshot(lib: &Library) -> Result<Value> {
    Ok(json!({
        "state": lifecycle::status()?,
        "enabled": enabled(),
        "selected": lib.selected,
        "network": native::network(),
        "lists": lib.lists,
        "app_routing": store::routing()?,
    }))
}
/// Runs a lifecycle action in its own process, under its own deadline.
fn ctl(action: &str) -> Result<()> {
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
fn release_selection() -> Result<()> {
    if enabled() || lifecycle::status()? != State::Disabled {
        return Err(
            "Turn protection off or select another proxy before removing the selected proxy."
                .into(),
        );
    }
    Ok(())
}
#[derive(Default)]
struct Outcome {
    message: Option<String>,
    check: Option<Check>,
}
fn apply(request: Request, lib: &mut Library) -> Result<Outcome> {
    match request {
        Request::Status | Request::Apps => {}
        Request::SetAppRouting { mut routing } => {
            routing.validate()?;
            if routing.mode == Mode::Selected {
                routing.check_selection(&native::catalog()?)?;
            }
            lifecycle::stage(|| store::save_routing(&routing))?;
            if enabled() {
                ctl("restart")?;
            }
        }
        Request::TestConnection { id } => {
            if lib.selected != Some(id) || lifecycle::status()? != State::Protected {
                return Err("Select a proxy and enable protection before testing.".into());
            }
            let check = native::provider_check().map_err(|_| "Proxy did not respond.")?;
            return Ok(Outcome {
                check: Some(check),
                ..Outcome::default()
            });
        }
        Request::Import { name, text, kind } => {
            let n = lib.add(&name, parse_list(&text, kind)?)?;
            store::save_library(lib)?;
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
            lib.select(id)?;
            lifecycle::stage(|| store::save_library(lib))?;
            ctl("enable")?;
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
            if lib.selected == Some(id) {
                release_selection()?;
            }
            lib.remove_proxy(id);
            store::save_library(lib)?;
        }
        Request::DeleteList { id } => {
            lib.list(id).ok_or("This list is no longer saved.")?;
            if lib.list_holds_selection(id) {
                release_selection()?;
            }
            lib.remove_list(id);
            store::save_library(lib)?;
        }
        Request::RenameList { id, name } => {
            lib.rename_list(id, &name)?;
            store::save_library(lib)?;
        }
    }
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
    match request {
        Request::Apps => {
            return Ok(json!({"ok":true,"apps":app_routing::offered(native::catalog()?)}));
        }
        // Damaged saved lists must never prevent explicitly turning protection off.
        Request::Disable => {
            ctl("disable")?;
            let lib = store::library().unwrap_or_default();
            return Ok(json!({"ok":true,"snapshot":snapshot(&lib)?}));
        }
        _ => {}
    }
    let mut lib = match store::library() {
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
        Ok(Outcome { message, check }) => {
            let mut reply = json!({"ok": true, "snapshot": snapshot, "message": message});
            if let Some(Value::Object(fields)) = check.map(serde_json::to_value).transpose()? {
                reply.as_object_mut().unwrap().extend(fields);
            }
            reply
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
