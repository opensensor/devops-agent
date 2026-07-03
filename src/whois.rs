use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct WhoisClient {
    client: reqwest::Client,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbuseContact {
    pub name: Option<String>,
    pub role: Option<String>,
    pub emails: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WhoisInfo {
    pub ip: String,
    pub registry_url: Option<String>,
    pub network_name: Option<String>,
    pub handle: Option<String>,
    pub country: Option<String>,
    pub start_address: Option<String>,
    pub end_address: Option<String>,
    pub organization: Option<String>,
    pub abuse_contacts: Vec<AbuseContact>,
}

#[derive(Debug, thiserror::Error)]
pub enum WhoisError {
    #[error("Invalid IP address: {0}")]
    InvalidIp(String),
    #[error("WHOIS/RDAP lookup failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("WHOIS/RDAP lookup returned HTTP {status}: {body}")]
    Http {
        status: reqwest::StatusCode,
        body: String,
    },
    #[error("No WHOIS/RDAP endpoint returned data for {0}")]
    NotFound(String),
}

impl WhoisClient {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .user_agent("devops-agent/0.1")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self { client }
    }

    pub async fn lookup_ip(&self, ip: &str) -> Result<WhoisInfo, WhoisError> {
        let parsed: IpAddr = ip
            .parse()
            .map_err(|_| WhoisError::InvalidIp(ip.to_string()))?;
        let ip = parsed.to_string();

        let mut last_error = None;
        for url in rdap_urls(parsed) {
            match self.lookup_rdap_url(&url).await {
                Ok(body) => return Ok(Self::parse_rdap_response(&ip, &body)),
                Err(e) => {
                    tracing::debug!("WHOIS/RDAP lookup via {} failed: {}", url, e);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| WhoisError::NotFound(ip)))
    }

    async fn lookup_rdap_url(&self, url: &str) -> Result<Value, WhoisError> {
        let response = self
            .client
            .get(url)
            .header(
                reqwest::header::ACCEPT,
                "application/rdap+json, application/json",
            )
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(WhoisError::Http { status, body });
        }

        Ok(response.json::<Value>().await?)
    }

    fn parse_rdap_response(ip: &str, body: &Value) -> WhoisInfo {
        let entities = body
            .get("entities")
            .and_then(|entities| entities.as_array())
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        WhoisInfo {
            ip: ip.to_string(),
            registry_url: self_link(body),
            network_name: string_field(body, "name"),
            handle: string_field(body, "handle"),
            country: string_field(body, "country"),
            start_address: string_field(body, "startAddress"),
            end_address: string_field(body, "endAddress"),
            organization: organization_name(entities),
            abuse_contacts: abuse_contacts(body),
        }
    }
}

fn rdap_urls(ip: IpAddr) -> Vec<String> {
    let ip_string = ip.to_string();
    let arin = format!("https://rdap.arin.net/registry/ip/{}", ip_string);
    let ripe = format!("https://rdap.db.ripe.net/ip/{}", ip_string);
    let apnic = format!("https://rdap.apnic.net/ip/{}", ip_string);
    let lacnic = format!("https://rdap.lacnic.net/rdap/ip/{}", ip_string);
    let afrinic = format!("https://rdap.afrinic.net/rdap/ip/{}", ip_string);
    let rdap_org = format!("https://rdap.org/ip/{}", ip_string);

    match ip {
        IpAddr::V4(ipv4) if likely_ripe_ipv4(ipv4) => {
            vec![ripe, arin, apnic, lacnic, afrinic, rdap_org]
        }
        _ => vec![arin, ripe, apnic, lacnic, afrinic, rdap_org],
    }
}

fn likely_ripe_ipv4(ip: Ipv4Addr) -> bool {
    matches!(
        ip.octets()[0],
        2 | 5 | 31 | 37 | 46 | 51 | 62 | 77 | 78 | 79 | 80
            ..=91
                | 93
                | 94
                | 95
                | 109
                | 141
                | 145
                | 151
                | 176
                | 178
                | 185
                | 188
                | 193
                | 194
                | 195
                | 212
                | 213
                | 217
    )
}

impl Default for WhoisClient {
    fn default() -> Self {
        Self::new()
    }
}

fn string_field(value: &Value, name: &str) -> Option<String> {
    value.get(name)?.as_str().map(str::to_string)
}

fn self_link(value: &Value) -> Option<String> {
    value
        .get("links")
        .and_then(|links| links.as_array())
        .and_then(|links| {
            links.iter().find_map(|link| {
                let rel = link.get("rel").and_then(|rel| rel.as_str());
                let href = link.get("href").and_then(|href| href.as_str());
                (rel == Some("self"))
                    .then(|| href.map(str::to_string))
                    .flatten()
            })
        })
}

fn organization_name(entities: &[Value]) -> Option<String> {
    let registrants: Vec<String> = entities
        .iter()
        .filter(|entity| entity_has_role(entity, "registrant"))
        .filter_map(entity_display_name)
        .collect();

    registrants
        .iter()
        .find(|name| !looks_like_maintainer_name(name))
        .cloned()
        .or_else(|| registrants.into_iter().next())
        .or_else(|| entities.iter().find_map(entity_display_name))
}

fn looks_like_maintainer_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.ends_with("-MNT") || upper.ends_with("-MAINT")
}

fn abuse_contacts(body: &Value) -> Vec<AbuseContact> {
    let mut contacts = BTreeMap::<String, AbuseContact>::new();
    collect_abuse_contacts(body.get("entities"), &mut contacts);
    contacts.into_values().collect()
}

fn collect_abuse_contacts(entities: Option<&Value>, contacts: &mut BTreeMap<String, AbuseContact>) {
    let Some(entities) = entities.and_then(|entities| entities.as_array()) else {
        return;
    };

    for entity in entities {
        let is_abuse_entity = entity_has_role(entity, "abuse");
        let email_values = vcard_values(entity, "email");
        let has_abuse_email = email_values
            .iter()
            .any(|entry| entry.types.iter().any(|t| t.eq_ignore_ascii_case("abuse")));

        if is_abuse_entity || has_abuse_email {
            let role = entity
                .get("roles")
                .and_then(|roles| roles.as_array())
                .map(|roles| {
                    roles
                        .iter()
                        .filter_map(|role| role.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|role| !role.is_empty());

            let emails: Vec<String> = email_values
                .iter()
                .map(|entry| entry.value.clone())
                .filter(|email| email.contains('@'))
                .collect();

            if !emails.is_empty() {
                let contact = AbuseContact {
                    name: entity_display_name(entity),
                    role,
                    emails: dedup(emails),
                };
                let key = contact.emails.join(",");
                contacts.entry(key).or_insert(contact);
            }
        }

        collect_abuse_contacts(entity.get("entities"), contacts);
    }
}

fn entity_has_role(entity: &Value, expected: &str) -> bool {
    entity
        .get("roles")
        .and_then(|roles| roles.as_array())
        .is_some_and(|roles| {
            roles
                .iter()
                .filter_map(|role| role.as_str())
                .any(|role| role.eq_ignore_ascii_case(expected))
        })
}

fn entity_display_name(entity: &Value) -> Option<String> {
    vcard_values(entity, "fn")
        .into_iter()
        .next()
        .or_else(|| vcard_values(entity, "org").into_iter().next())
        .map(|entry| entry.value)
}

#[derive(Debug)]
struct VcardValue {
    value: String,
    types: Vec<String>,
}

fn vcard_values(entity: &Value, field_name: &str) -> Vec<VcardValue> {
    let Some(entries) = entity
        .get("vcardArray")
        .and_then(|vcard| vcard.get(1))
        .and_then(|entries| entries.as_array())
    else {
        return vec![];
    };

    entries
        .iter()
        .filter_map(|entry| {
            let row = entry.as_array()?;
            let name = row.first()?.as_str()?;
            if !name.eq_ignore_ascii_case(field_name) {
                return None;
            }

            let value = row.get(3)?.as_str()?.to_string();
            let types = row
                .get(1)
                .and_then(|params| params.get("type"))
                .map(vcard_type_values)
                .unwrap_or_default();

            Some(VcardValue { value, types })
        })
        .collect()
}

fn vcard_type_values(value: &Value) -> Vec<String> {
    if let Some(value) = value.as_str() {
        return vec![value.to_string()];
    }

    value
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn dedup(values: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.to_lowercase()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_abuse_contacts_from_rdap_entities() {
        let body = serde_json::json!({
            "name": "EXAMPLE-NET",
            "handle": "NET-192-0-2-0-1",
            "country": "US",
            "startAddress": "192.0.2.0",
            "endAddress": "192.0.2.255",
            "links": [
                { "rel": "self", "href": "https://rdap.example/ip/192.0.2.1" }
            ],
            "entities": [
                {
                    "roles": ["registrant"],
                    "vcardArray": ["vcard", [
                        ["fn", {}, "text", "Example Networks LLC"]
                    ]]
                },
                {
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [
                        ["fn", {}, "text", "Example Abuse Desk"],
                        ["email", { "type": "abuse" }, "text", "abuse@example.net"]
                    ]]
                }
            ]
        });

        let info = WhoisClient::parse_rdap_response("192.0.2.1", &body);

        assert_eq!(info.network_name.as_deref(), Some("EXAMPLE-NET"));
        assert_eq!(info.organization.as_deref(), Some("Example Networks LLC"));
        assert_eq!(info.abuse_contacts.len(), 1);
        assert_eq!(
            info.abuse_contacts[0].emails,
            vec!["abuse@example.net".to_string()]
        );
    }

    #[test]
    fn parses_nested_abuse_contacts() {
        let body = serde_json::json!({
            "entities": [{
                "roles": ["registrant"],
                "entities": [{
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [
                        ["fn", {}, "text", "Nested Abuse Desk"],
                        ["email", { "type": ["internet", "abuse"] }, "text", "abuse@example.org"]
                    ]]
                }]
            }]
        });

        let info = WhoisClient::parse_rdap_response("203.0.113.4", &body);

        assert_eq!(info.abuse_contacts.len(), 1);
        assert_eq!(
            info.abuse_contacts[0].emails,
            vec!["abuse@example.org".to_string()]
        );
    }

    #[test]
    fn prefers_non_maintainer_registrant_as_organization() {
        let body = serde_json::json!({
            "entities": [
                {
                    "roles": ["registrant"],
                    "vcardArray": ["vcard", [
                        ["fn", {}, "text", "example-mnt"]
                    ]]
                },
                {
                    "roles": ["registrant"],
                    "vcardArray": ["vcard", [
                        ["fn", {}, "text", "Example Networks LLC"]
                    ]]
                }
            ]
        });

        let info = WhoisClient::parse_rdap_response("203.0.113.5", &body);

        assert_eq!(info.organization.as_deref(), Some("Example Networks LLC"));
    }
}
