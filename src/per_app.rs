//! Saved app selection and the installed-app picker. iOS owns executable attribution.
use super::*;
use slipstream::app_routing::{AppRouting, Mode, user_installed};
use std::path::Path;
const SETTINGS: &str = installed!("/etc/slipstream/app-routing.json");
#[derive(Deserialize, Serialize)]
pub struct App {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing)]
    hidden: bool,
    /// Per-app rules cannot name this app without domains. The name predates the app proxy.
    requires_all: bool,
}
unsafe extern "C" {
    fn slipstream_app_catalog() -> *mut libc::c_char;
}
pub fn load() -> Result<AppRouting> {
    use std::os::unix::fs::MetadataExt;
    if !Path::new(SETTINGS).exists() {
        return Ok(AppRouting::default());
    }
    let m = fs::metadata(SETTINGS)?;
    if m.uid() != 0 || m.mode() & 0o077 != 0 {
        return Err("App routing needs root ownership and private permissions.".into());
    }
    let mut settings: AppRouting = serde_json::from_slice(&fs::read(SETTINGS)?)
        .map_err(|_| "Saved app routing could not be read. It has not been replaced.")?;
    settings.validate()?;
    Ok(settings)
}
fn catalog() -> Result<Vec<App>> {
    let raw = unsafe { slipstream_app_catalog() };
    if raw.is_null() {
        return Err("Could not read installed apps. Retry after jailbreaking.".into());
    }
    let parsed = serde_json::from_slice(unsafe { CStr::from_ptr(raw).to_bytes() });
    unsafe {
        libc::free(raw.cast());
    }
    Ok(parsed?)
}
pub fn apps() -> Result<serde_json::Value> {
    let mut apps = catalog()?;
    apps.retain(|a| user_installed(&a.id, a.hidden) && a.id != "local.slipstream.app");
    apps.sort_by_cached_key(|a| a.name.to_lowercase());
    Ok(serde_json::to_value(apps)?)
}
/// Every app the user installed that per-app rules can name without domain restrictions.
pub fn eligible() -> Result<Vec<String>> {
    Ok(catalog()?
        .into_iter()
        .filter(|a| user_installed(&a.id, a.hidden) && !a.requires_all)
        .map(|a| a.id)
        .collect())
}
pub fn save(mut settings: AppRouting) -> Result<()> {
    settings.validate()?;
    if settings.mode == Mode::Selected {
        let catalog = catalog()?;
        for id in &settings.bundle_ids {
            if catalog.iter().any(|a| &a.id == id && a.requires_all) {
                return Err("Apps that require domain-specific rules cannot be protected.".into());
            }
            if !catalog.iter().any(|a| &a.id == id) {
                return Err("A selected app is no longer available. Refresh the app list.".into());
            }
        }
    }
    control::atomic_write(SETTINGS, &settings)
}
