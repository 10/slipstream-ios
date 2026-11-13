//! Calls into the Objective-C side: the app proxy's Network Extension configuration, session and
//! provider messages (tunnel.m), and the installed-app catalog (app_catalog.m).
use crate::Result;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use slipstream::{app_routing::App, check::Check};
use std::{
    ffi::{CStr, CString, c_char},
    net::Ipv4Addr,
};

unsafe extern "C" {
    fn slipstream_tunnel_status() -> *mut c_char;
    fn slipstream_tunnel_apply(settings: *const c_char) -> *mut c_char;
    fn slipstream_tunnel_remove() -> *mut c_char;
    fn slipstream_provider_check() -> *mut c_char;
    fn slipstream_network() -> *mut c_char;
    fn slipstream_app_catalog() -> *mut c_char;
}

#[derive(Deserialize)]
pub struct Tunnel {
    /// The configuration exists and is enabled.
    pub enabled: bool,
    /// Its session is connected.
    pub connected: bool,
}

/// What the configuration needs to route `bundle_ids` through `proxy_url`.
#[derive(Serialize)]
pub struct Settings {
    pub proxy_url: String,
    pub proxy_ip: Ipv4Addr,
    pub bundle_ids: Vec<String>,
}

pub fn tunnel_status() -> Result<Tunnel> {
    reply(unsafe { slipstream_tunnel_status() })
}

/// Saves the configuration and has its provider use it, starting the session when needed.
pub fn tunnel_apply(settings: &Settings) -> Result<()> {
    let settings = CString::new(serde_json::to_string(settings)?)?;
    reply::<serde::de::IgnoredAny>(unsafe { slipstream_tunnel_apply(settings.as_ptr()) })?;
    Ok(())
}

/// Removes the configuration and its UUID journal.
pub fn tunnel_remove() -> Result<()> {
    reply::<serde::de::IgnoredAny>(unsafe { slipstream_tunnel_remove() })?;
    Ok(())
}

/// Asks the connected provider to check its proxy.
pub fn provider_check() -> Result<Check> {
    reply(unsafe { slipstream_provider_check() })
}

/// `Wi-Fi`, `Cellular` or `Network` for the current path.
pub fn network() -> Option<String> {
    String::from_utf8(take(unsafe { slipstream_network() })?).ok()
}

pub fn catalog() -> Result<Vec<App>> {
    let apps = take(unsafe { slipstream_app_catalog() })
        .ok_or("Could not read installed apps. Retry after jailbreaking.")?;
    Ok(serde_json::from_slice(&apps)?)
}

/// Takes ownership of a malloc'd C string.
fn take(raw: *mut c_char) -> Option<Vec<u8>> {
    if raw.is_null() {
        return None;
    }
    let bytes = unsafe { CStr::from_ptr(raw) }.to_bytes().to_vec();
    unsafe { libc::free(raw.cast()) };
    Some(bytes)
}

/// A tunnel.m result: the value, or `{"error": message}`.
fn reply<T: DeserializeOwned>(raw: *mut c_char) -> Result<T> {
    let value: serde_json::Value =
        serde_json::from_slice(&take(raw).ok_or("Could not read the tunnel state.")?)?;
    if let Some(error) = value["error"].as_str() {
        return Err(error.into());
    }
    Ok(serde_json::from_value(value)?)
}
