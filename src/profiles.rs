//! Saved lists in root-only storage; control.rs exposes them to the authorized app.
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
    pub fn from_url(url: &str) -> Result<Self, String> {
        let p = tun2proxy::ArgProxy::try_from(url)
            .map_err(|_| "Saved proxy configuration is invalid.")?;
        let kind = match p.proxy_type {
            tun2proxy::ProxyType::Http => ProxyKind::Http,
            tun2proxy::ProxyType::Socks5 => ProxyKind::Socks5,
            _ => return Err("Use an HTTP or SOCKS5 proxy.".into()),
        };
        let std::net::IpAddr::V4(host) = p.addr.ip() else {
            return Err("Use an IPv4 proxy address.".into());
        };
        let (username, password) = p
            .credentials
            .map(|c| (c.username, c.password))
            .unwrap_or_default();
        Ok(Self {
            id: 0,
            host,
            port: p.addr.port(),
            username,
            password,
            kind,
        })
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
    pub fn add(&mut self, name: &str, entries: Vec<Proxy>) -> Result<usize, String> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 40 || name.chars().any(char::is_control) {
            return Err("Use a list name of 1–40 characters.".into());
        }
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
    #[test]
    fn import_is_strict_private_and_round_trips_credentials() {
        let entries=parse_list("\u{feff}203.0.113.1:3128:user:p@ss:word\r\n\n203.0.113.1:3128:user:p@ss:word\n198.51.100.2:80", ProxyKind::Http).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(Proxy::from_url(&entries[0].url()).unwrap() == entries[0]);
        assert!(entries[0].url().starts_with("http://"));
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
        library.selected = Some(library.lists[0].proxies[0].id);
        assert_eq!(library.add("work", entries).unwrap(), 0);
        assert_eq!(library.lists.len(), 1);
        assert!(library.get(library.selected.unwrap()).is_some());
        assert!(library.add("", vec![]).is_err());
    }

    #[test]
    fn socks5_entries_keep_their_type_and_old_libraries_default_to_http() {
        let socks = parse_list("203.0.113.1:1080:user:pass\n203.0.113.2:1080", ProxyKind::Socks5).unwrap();
        assert_eq!(socks[0].url(), "socks5://user:pass@203.0.113.1:1080");
        assert_eq!(socks[1].url(), "socks5://203.0.113.2:1080");
        for p in &socks {
            let parsed = Proxy::from_url(&p.url()).unwrap();
            assert!(parsed == *p && parsed.kind == ProxyKind::Socks5);
        }
        assert!(Proxy::from_url("socks4://203.0.113.1:1080").is_err());
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
}
