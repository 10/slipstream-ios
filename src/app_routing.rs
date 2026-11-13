//! Which apps iOS diverts to the app proxy. iOS resolves executable identities on the phone.
use serde::{Deserialize, Serialize};

/// Slipstream's own app is always routed, so its exit-IP check follows the protected path.
pub const SLIPSTREAM_APP: &str = "local.slipstream.app";

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    All,
    Selected,
}

/// The saved app selection.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AppRouting {
    pub mode: Mode,
    pub bundle_ids: Vec<String>,
}

/// An installed app, as the phone's catalog reports it.
#[derive(Debug, Deserialize, Serialize)]
pub struct App {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing)]
    pub hidden: bool,
    /// iOS lets a per-app rule name this app only together with domains, which Slipstream does
    /// not use, so the app cannot be protected.
    pub requires_domains: bool,
}

impl App {
    /// Apple's own apps, including hidden system apps, are neither offered nor protected.
    fn user_installed(&self) -> bool {
        !self.hidden && !self.id.starts_with("com.apple.")
    }
}

/// The apps the picker offers, sorted by name.
pub fn offered(mut catalog: Vec<App>) -> Vec<App> {
    catalog.retain(|app| app.user_installed() && app.id != SLIPSTREAM_APP);
    catalog.sort_by_cached_key(|app| app.name.to_lowercase());
    catalog
}

impl AppRouting {
    pub fn validate(&mut self) -> Result<(), &'static str> {
        if self.bundle_ids.len() > 128 {
            return Err("Select up to 128 apps.");
        }
        for id in &self.bundle_ids {
            if id.is_empty()
                || id.len() > 255
                || !id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".-_".contains(&c))
            {
                return Err("An app identifier is invalid. Refresh the app list.");
            }
            if id == SLIPSTREAM_APP {
                return Err("Slipstream's connection check is included automatically.");
            }
        }
        self.bundle_ids.sort();
        self.bundle_ids.dedup();
        if self.mode == Mode::Selected && self.bundle_ids.is_empty() {
            return Err("Select at least one app.");
        }
        Ok(())
    }

    /// Rejects selected apps the phone no longer has or cannot protect.
    pub fn check_selection(&self, catalog: &[App]) -> Result<(), &'static str> {
        if self.bundle_ids.iter().any(|id| !catalog.iter().any(|app| &app.id == id)) {
            return Err("A selected app is no longer available. Refresh the app list.");
        }
        self.routed(catalog).map(drop)
    }

    /// The bundle IDs iOS diverts to the proxy. All apps names every app the user installed that
    /// a rule can protect, so an app installed later joins at the next restart.
    pub fn routed(&self, catalog: &[App]) -> Result<Vec<String>, &'static str> {
        let mut ids: Vec<String> = match self.mode {
            Mode::All => catalog
                .iter()
                .filter(|app| app.user_installed() && !app.requires_domains)
                .map(|app| app.id.clone())
                .collect(),
            Mode::Selected => {
                let unprotectable = |id: &String| {
                    catalog
                        .iter()
                        .any(|app| &app.id == id && app.requires_domains)
                };
                if self.bundle_ids.iter().any(unprotectable) {
                    return Err(
                        "A selected app requires a domain rule, which Slipstream cannot protect.",
                    );
                }
                self.bundle_ids.clone()
            }
        };
        if !ids.iter().any(|id| id == SLIPSTREAM_APP) {
            ids.push(SLIPSTREAM_APP.into());
        }
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(id: &str, hidden: bool, requires_domains: bool) -> App {
        App {
            id: id.into(),
            name: id.rsplit('.').next().unwrap().into(),
            hidden,
            requires_domains,
        }
    }

    fn catalog() -> Vec<App> {
        vec![
            app("com.zhiliaoapp.musically", false, false),
            app("com.burbn.instagram", false, false),
            app("com.apple.mobilesafari", false, true),
            app("com.apple.Preferences", false, false),
            app("com.APSQA.MetisTest", true, false),
            app("org.example.mailclient", false, true),
            app(SLIPSTREAM_APP, false, false),
        ]
    }

    #[test]
    fn all_apps_routes_every_protectable_app_the_user_installed() {
        let all = AppRouting::default();
        assert_eq!(
            all.routed(&catalog()).unwrap(),
            ["com.zhiliaoapp.musically", "com.burbn.instagram", SLIPSTREAM_APP]
        );
        let names: Vec<_> = offered(catalog()).into_iter().map(|app| app.id).collect();
        assert_eq!(
            names,
            ["com.burbn.instagram", "org.example.mailclient", "com.zhiliaoapp.musically"]
        );
    }

    #[test]
    fn selected_apps_always_include_slipstream_and_reject_domain_only_apps() {
        let mut selected = AppRouting {
            mode: Mode::Selected,
            bundle_ids: vec!["com.burbn.instagram".into()],
        };
        assert_eq!(
            selected.routed(&catalog()).unwrap(),
            ["com.burbn.instagram", SLIPSTREAM_APP]
        );
        assert!(selected.check_selection(&catalog()).is_ok());
        selected.bundle_ids.push("org.example.mailclient".into());
        assert!(selected.routed(&catalog()).is_err());
        assert!(selected.check_selection(&catalog()).is_err());
        selected.bundle_ids = vec!["com.example.uninstalled".into()];
        assert!(selected.check_selection(&catalog()).is_err());
    }
}
