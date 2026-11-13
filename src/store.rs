//! Saved settings: root-owned, mode-600 files under etc/slipstream, replaced atomically.
use crate::Result;
use serde::Serialize;
use slipstream::{app_routing::AppRouting, profiles::Library};
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
};

const LIBRARY: &str = installed!("/etc/slipstream/proxies.json");
const ROUTING: &str = installed!("/etc/slipstream/app-routing.json");

/// The saved proxy lists and selection; empty before the first import.
pub fn library() -> Result<Library> {
    match read(LIBRARY, "Saved lists")? {
        None => Ok(Library::default()),
        Some(bytes) => Ok(serde_json::from_slice(&bytes)
            .map_err(|_| "Saved lists could not be read. They have not been replaced.")?),
    }
}

pub fn save_library(library: &Library) -> Result<()> {
    write(LIBRARY, library)
}

/// The saved app selection; All apps before the first save.
pub fn routing() -> Result<AppRouting> {
    let Some(bytes) = read(ROUTING, "App routing")? else {
        return Ok(AppRouting::default());
    };
    let mut routing: AppRouting = serde_json::from_slice(&bytes)
        .map_err(|_| "Saved app routing could not be read. It has not been replaced.")?;
    routing.validate()?;
    Ok(routing)
}

pub fn save_routing(routing: &AppRouting) -> Result<()> {
    write(ROUTING, routing)
}

fn read(path: &str, what: &str) -> Result<Option<Vec<u8>>> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(format!("{what} must be root-owned and private.").into());
    }
    Ok(Some(fs::read(path)?))
}

fn write<T: Serialize>(path: &str, value: &T) -> Result<()> {
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
