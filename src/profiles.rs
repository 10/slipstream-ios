//! Saved proxy lists and the selected proxy, stored root-only on the phone.
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::Ipv4Addr};

pub const MAX_PROXIES: usize = 5000;
pub const MAX_IMPORT_BYTES: usize = 1024 * 1024;

/// Upstream protocol. Libraries saved before 0.6.0 have no `type` and are HTTP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    #[default]
    Http,
    Socks5,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proxy {
    pub id: u64,
    pub host: Ipv4Addr,
    pub port: u16,
    pub username: String,
    pub password: String,
    #[serde(default, rename = "type")]
    pub kind: ProxyKind,
}

impl Proxy {
    /// The proxy as the engine reads it, with percent-encoded credentials.
    pub fn url(&self) -> String {
        let scheme = match self.kind {
            ProxyKind::Http => "http",
            ProxyKind::Socks5 => "socks5",
        };
        if self.username.is_empty() {
            format!("{scheme}://{}:{}", self.host, self.port)
        } else {
            let key = tun2proxy::UserKey::new(&self.username, &self.password);
            format!("{scheme}://{key}@{}:{}", self.host, self.port)
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ProxyList {
    pub id: u64,
    pub name: String,
    pub proxies: Vec<Proxy>,
}
#[derive(Serialize, Deserialize)]
pub struct Library {
    pub next_id: u64,
    pub selected: Option<u64>,
    pub lists: Vec<ProxyList>,
}
impl Default for Library {
    fn default() -> Self {
        Self {
            next_id: 1,
            selected: None,
            lists: vec![],
        }
    }
}
impl Library {
    pub fn get(&self, id: u64) -> Option<&Proxy> {
        self.lists
            .iter()
            .flat_map(|g| &g.proxies)
            .find(|p| p.id == id)
    }
    pub fn selected_proxy(&self) -> Option<&Proxy> {
        self.selected.and_then(|id| self.get(id))
    }
    pub fn select(&mut self, id: u64) -> Result<(), String> {
        self.get(id)
            .ok_or("This proxy is no longer saved. Refresh the list.")?;
        self.selected = Some(id);
        Ok(())
    }
    pub fn list(&self, id: u64) -> Option<&ProxyList> {
        self.lists.iter().find(|g| g.id == id)
    }
    /// Removes a proxy, and the selection with it.
    pub fn remove_proxy(&mut self, id: u64) {
        for group in &mut self.lists {
            group.proxies.retain(|p| p.id != id);
        }
        if self.selected == Some(id) {
            self.selected = None;
        }
    }
    pub fn list_holds_selection(&self, id: u64) -> bool {
        self.list(id)
            .is_some_and(|g| g.proxies.iter().any(|p| Some(p.id) == self.selected))
    }
    /// Removes a list, and the selection when the list holds it.
    pub fn remove_list(&mut self, id: u64) {
        if self.list_holds_selection(id) {
            self.selected = None;
        }
        self.lists.retain(|g| g.id != id);
    }
    pub fn rename_list(&mut self, id: u64, name: &str) -> Result<(), String> {
        let name = list_name(name)?;
        if self
            .lists
            .iter()
            .any(|g| g.id != id && g.name.to_lowercase() == name.to_lowercase())
        {
            return Err("A list with this name already exists.".into());
        }
        self.lists
            .iter_mut()
            .find(|g| g.id == id)
            .ok_or("This list is no longer saved.")?
            .name = name.into();
        Ok(())
    }
    /// Adds proxies to the list with this name, creating it when needed. Proxies already in that
    /// list are skipped; returns how many were added.
    pub fn add(&mut self, name: &str, entries: Vec<Proxy>) -> Result<usize, String> {
        let name = list_name(name)?;
        let group = self
            .lists
            .iter()
            .position(|g| g.name.to_lowercase() == name.to_lowercase());
        let mut seen: HashSet<String> = group
            .map(|i| self.lists[i].proxies.iter().map(Proxy::url).collect())
            .unwrap_or_default();
        let additions: Vec<_> = entries
            .into_iter()
            .filter(|p| seen.insert(p.url()))
            .collect();
        if self.lists.iter().map(|g| g.proxies.len()).sum::<usize>() + additions.len() > MAX_PROXIES
        {
            return Err(
                "Save up to 5,000 proxies. Remove an unused list before importing more.".into(),
            );
        }
        if additions.is_empty() {
            return Ok(0);
        }
        let i = group.unwrap_or_else(|| {
            let id = self.next_id;
            self.next_id += 1;
            self.lists.push(ProxyList {
                id,
                name: name.into(),
                proxies: vec![],
            });
            self.lists.len() - 1
        });
        let count = additions.len();
        for mut p in additions {
            p.id = self.next_id;
            self.next_id += 1;
            self.lists[i].proxies.push(p);
        }
        Ok(count)
    }
}

fn list_name(name: &str) -> Result<&str, String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 40 || name.chars().any(char::is_control) {
        return Err("Use a list name of 1–40 characters.".into());
    }
    Ok(name)
}

pub fn parse_list(text: &str, kind: ProxyKind) -> Result<Vec<Proxy>, String> {
    if text.len() > MAX_IMPORT_BYTES {
        return Err("Choose a text file smaller than 1 MB.".into());
    }
    let mut result = vec![];
    let mut seen = HashSet::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim().trim_start_matches('\u{feff}');
        if line.is_empty() {
            continue;
        }
        let parts: Vec<_> = line.splitn(4, ':').map(str::trim).collect();
        let error = |message: &str| format!("Line {}: {message}", i + 1);
        if parts.len() != 2 && parts.len() != 4 {
            return Err(error("Use ip:port or ip:port:user:pass."));
        }
        let host: Ipv4Addr = parts[0]
            .parse()
            .map_err(|_| error("Enter a numeric IPv4 address."))?;
        if host.is_unspecified() || host.is_multicast() || host.is_broadcast() || host.is_loopback()
        {
            return Err(error("Use a reachable proxy server address."));
        }
        let port = parts[1]
            .parse::<std::num::NonZeroU16>()
            .map_err(|_| error("Port must be 1–65535."))?
            .get();
        let (username, password) = if parts.len() == 4 {
            if parts[2].is_empty() || parts[3].is_empty() {
                return Err(error("Username and password are both required."));
            }
            if parts[2..].iter().any(|v| v.chars().any(char::is_control)) {
                return Err(error("Credentials contain a control character."));
            }
            (parts[2].to_owned(), parts[3].to_owned())
        } else {
            (String::new(), String::new())
        };
        let p = Proxy {
            id: 0,
            host,
            port,
            username,
            password,
            kind,
        };
        if seen.insert(p.url()) {
            result.push(p);
        }
        if result.len() > MAX_PROXIES {
            return Err("Import up to 5,000 proxies at a time.".into());
        }
    }
    if result.is_empty() {
        return Err("Paste at least one proxy, one per line.".into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The proxy as the engine parses its URL.
    fn engine_view(p: &Proxy) -> (tun2proxy::ProxyType, String, String, String) {
        let parsed = tun2proxy::ArgProxy::try_from(p.url().as_str()).unwrap();
        let key = parsed.credentials.unwrap_or_default();
        (parsed.proxy_type, parsed.addr.to_string(), key.username, key.password)
    }

    #[test]
    fn import_is_strict_private_and_round_trips_credentials() {
        let entries = parse_list(
            "\u{feff}203.0.113.1:3128:user:p@ss:word\r\n\n203.0.113.1:3128:user:p@ss:word\n198.51.100.2:80",
            ProxyKind::Http,
        )
        .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            engine_view(&entries[0]),
            (tun2proxy::ProxyType::Http, "203.0.113.1:3128".into(), "user".into(), "p@ss:word".into())
        );
        for bad in [
            "example.org:80",
            "0.0.0.0:80",
            "203.0.113.1:65536",
            "203.0.113.1:0",
            "203.0.113.1:80:user",
            "203.0.113.1:80::SECRET",
        ] {
            let error = parse_list(bad, ProxyKind::Http).err().unwrap();
            assert!(!error.contains("SECRET"));
            assert!(error.starts_with("Line 1:"));
        }
        let mut library = Library::default();
        assert_eq!(library.add("Work", entries.clone()).unwrap(), 2);
        library.select(library.lists[0].proxies[0].id).unwrap();
        assert_eq!(library.add("work", entries).unwrap(), 0);
        assert_eq!(library.lists.len(), 1);
        assert!(library.selected_proxy().is_some());
        assert!(library.add("", vec![]).is_err());
    }

    #[test]
    fn socks5_entries_keep_their_type_and_old_libraries_default_to_http() {
        let socks = parse_list("203.0.113.1:1080:user:pass\n203.0.113.2:1080", ProxyKind::Socks5).unwrap();
        assert_eq!(socks[0].url(), "socks5://user:pass@203.0.113.1:1080");
        assert_eq!(socks[1].url(), "socks5://203.0.113.2:1080");
        assert_eq!(engine_view(&socks[1]).0, tun2proxy::ProxyType::Socks5);
        // The same endpoint may be saved once per protocol.
        let http = parse_list("203.0.113.1:1080:user:pass", ProxyKind::Http).unwrap();
        let mut library = Library::default();
        assert_eq!(library.add("Mixed", socks).unwrap(), 2);
        assert_eq!(library.add("Mixed", http).unwrap(), 1);
        let legacy: Proxy = serde_json::from_str(r#"{"id":7,"host":"203.0.113.9","port":3128,"username":"","password":""}"#).unwrap();
        assert_eq!(legacy.kind, ProxyKind::Http);
        let saved = serde_json::to_string(&library.lists[0].proxies[0]).unwrap();
        assert!(saved.contains(r#""type":"socks5""#));
    }

    #[test]
    fn removing_the_selected_proxy_or_its_list_clears_the_selection() {
        let mut library = Library::default();
        library.add("Home", parse_list("203.0.113.1:80\n203.0.113.2:80", ProxyKind::Http).unwrap()).unwrap();
        library.add("Away", parse_list("203.0.113.3:80", ProxyKind::Http).unwrap()).unwrap();
        let [home, away] = [library.lists[0].id, library.lists[1].id];
        let first = library.lists[0].proxies[0].id;
        library.select(first).unwrap();
        library.remove_list(away);
        assert_eq!(library.selected, Some(first));
        library.remove_proxy(first);
        assert_eq!(library.selected, None);
        library.select(library.lists[0].proxies[0].id).unwrap();
        assert!(library.rename_list(home, " Office ").is_ok());
        assert_eq!(library.lists[0].name, "Office");
        library.remove_list(home);
        assert!(library.selected.is_none() && library.lists.is_empty());
    }
}
