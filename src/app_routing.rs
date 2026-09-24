//! Saved application selection; executable identities are resolved on the phone.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    All,
    Selected,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AppRouting {
    pub mode: Mode,
    pub bundle_ids: Vec<String>,
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
            if id == "local.slipstream.app" {
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
}
/// Whether an app is one the user installed. Apple's own apps, including hidden system apps, are
/// neither offered for selection nor protected by All apps.
pub fn user_installed(id: &str, hidden: bool) -> bool {
    !hidden && !id.starts_with("com.apple.")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_apps_the_user_installed_are_offered_or_protected() {
        for id in ["com.burbn.instagram", "com.zhiliaoapp.musically", "org.coolstar.SileoStore"] {
            assert!(user_installed(id, false), "{id}");
        }
        for id in ["com.apple.mobilemail", "com.apple.AppStore", "com.apple.AuthKitUIService"] {
            assert!(!user_installed(id, false), "{id}");
        }
        assert!(!user_installed("com.APSQA.MetisTest", true));
    }
}
