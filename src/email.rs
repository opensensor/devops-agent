use crate::config::models::EmailConfig;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct EmailClient {
    client: reqwest::Client,
    config: EmailConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbuseReportEmail {
    pub recipients: Vec<String>,
    pub subject: String,
    pub text_body: String,
    pub html_body: String,
    pub custom_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSendResult {
    pub provider: String,
    pub recipients: Vec<String>,
    pub sandbox_mode: bool,
    pub provider_response: Value,
}

#[derive(Debug, thiserror::Error)]
pub enum EmailError {
    #[error("{0} credentials are not configured")]
    MissingCredentials(String),
    #[error("Email sender is invalid: {0}")]
    InvalidSender(String),
    #[error("No valid abuse-report recipients were found")]
    NoRecipients,
    #[error("Unsupported email provider: {0}")]
    UnsupportedProvider(String),
    #[error("{provider} request failed: {source}")]
    Request {
        provider: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("{provider} returned HTTP {status}: {body}")]
    Http {
        provider: String,
        status: reqwest::StatusCode,
        body: String,
    },
}

impl EmailClient {
    pub fn new(config: EmailConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            config,
        }
    }

    pub fn provider_name(&self) -> String {
        self.config.normalized_provider()
    }

    pub fn sender_name(&self) -> String {
        self.config.from_name.trim().to_string()
    }

    pub async fn send_abuse_report(
        &self,
        report: &AbuseReportEmail,
    ) -> Result<EmailSendResult, EmailError> {
        match self.config.normalized_provider().as_str() {
            "mailjet" => self.send_mailjet_abuse_report(report).await,
            "postmark" => self.send_postmark_abuse_report(report).await,
            provider => Err(EmailError::UnsupportedProvider(provider.to_string())),
        }
    }

    async fn send_mailjet_abuse_report(
        &self,
        report: &AbuseReportEmail,
    ) -> Result<EmailSendResult, EmailError> {
        let provider = "mailjet";
        let api_key = self
            .config
            .mailjet
            .api_key
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                EmailError::MissingCredentials(
                    "Mailjet; set MAILJET_API_KEY and MAILJET_API_SECRET".to_string(),
                )
            })?;
        let api_secret = self
            .config
            .mailjet
            .api_secret
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                EmailError::MissingCredentials(
                    "Mailjet; set MAILJET_API_KEY and MAILJET_API_SECRET".to_string(),
                )
            })?;

        let payload = self.build_mailjet_payload(report)?;
        let recipients = report.valid_recipients();

        let response = self
            .client
            .post(&self.config.mailjet.endpoint)
            .basic_auth(api_key, Some(api_secret))
            .json(&payload)
            .send()
            .await
            .map_err(|source| EmailError::Request {
                provider: provider.to_string(),
                source,
            })?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(EmailError::Http {
                provider: provider.to_string(),
                status,
                body,
            });
        }

        let provider_response = serde_json::from_str(&body).unwrap_or_else(|_| json!({}));
        Ok(EmailSendResult {
            provider: provider.to_string(),
            recipients,
            sandbox_mode: self.config.sandbox_mode,
            provider_response,
        })
    }

    async fn send_postmark_abuse_report(
        &self,
        report: &AbuseReportEmail,
    ) -> Result<EmailSendResult, EmailError> {
        let provider = "postmark";
        let token = self.postmark_token()?;
        let payloads = self.build_postmark_payloads(report)?;
        let recipients = report.valid_recipients();
        let mut responses = Vec::new();

        for payload in payloads {
            let response = self
                .client
                .post(&self.config.postmark.endpoint)
                .headers(postmark_headers(&token))
                .json(&payload)
                .send()
                .await
                .map_err(|source| EmailError::Request {
                    provider: provider.to_string(),
                    source,
                })?;

            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            if !status.is_success() {
                return Err(EmailError::Http {
                    provider: provider.to_string(),
                    status,
                    body,
                });
            }
            responses.push(serde_json::from_str(&body).unwrap_or_else(|_| json!({})));
        }

        Ok(EmailSendResult {
            provider: provider.to_string(),
            recipients,
            sandbox_mode: self.config.sandbox_mode,
            provider_response: Value::Array(responses),
        })
    }

    pub(crate) fn build_mailjet_payload(
        &self,
        report: &AbuseReportEmail,
    ) -> Result<Value, EmailError> {
        let sender = self.config.from_email.trim();
        if !is_valid_email(sender) {
            return Err(EmailError::InvalidSender(sender.to_string()));
        }

        let recipients = report.valid_recipients();
        if recipients.is_empty() {
            return Err(EmailError::NoRecipients);
        }

        let messages: Vec<Value> = recipients
            .iter()
            .map(|recipient| {
                let mut message = json!({
                    "From": {
                        "Email": sender,
                        "Name": self.config.from_name,
                    },
                    "To": [
                        {
                            "Email": recipient,
                        }
                    ],
                    "Subject": report.subject,
                    "TextPart": report.text_body,
                    "HTMLPart": report.html_body,
                });

                if let Some(custom_id) = report.custom_id.as_deref() {
                    message["CustomID"] = json!(custom_id);
                }

                message
            })
            .collect();

        let mut payload = json!({ "Messages": messages });
        if self.config.sandbox_mode {
            payload["SandboxMode"] = json!(true);
        }
        Ok(payload)
    }

    pub(crate) fn build_postmark_payloads(
        &self,
        report: &AbuseReportEmail,
    ) -> Result<Vec<Value>, EmailError> {
        let sender = self.config.from_email.trim();
        if !is_valid_email(sender) {
            return Err(EmailError::InvalidSender(sender.to_string()));
        }

        let recipients = report.valid_recipients();
        if recipients.is_empty() {
            return Err(EmailError::NoRecipients);
        }

        let from = format_sender(&self.config.from_name, sender);
        let message_stream = self.config.postmark.message_stream.trim();
        let message_stream = if message_stream.is_empty() {
            "outbound"
        } else {
            message_stream
        };

        let payloads = recipients
            .iter()
            .map(|recipient| {
                let mut payload = json!({
                    "From": from,
                    "To": recipient,
                    "Subject": report.subject,
                    "TextBody": report.text_body,
                    "HtmlBody": report.html_body,
                    "MessageStream": message_stream,
                    "Tag": "devops-agent-abuse-report",
                });

                if let Some(custom_id) = report.custom_id.as_deref() {
                    payload["Metadata"] = json!({
                        "incident_id": custom_id,
                    });
                }

                payload
            })
            .collect();

        Ok(payloads)
    }

    pub(crate) fn postmark_token(&self) -> Result<String, EmailError> {
        if self.config.sandbox_mode {
            return Ok("POSTMARK_API_TEST".to_string());
        }

        self.config
            .postmark
            .server_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                EmailError::MissingCredentials(
                    "Postmark; set POSTMARK_SERVER_TOKEN or enable EMAIL_SANDBOX_MODE".to_string(),
                )
            })
    }
}

impl AbuseReportEmail {
    fn valid_recipients(&self) -> Vec<String> {
        let mut seen = BTreeSet::new();
        self.recipients
            .iter()
            .map(|email| email.trim().to_ascii_lowercase())
            .filter(|email| is_valid_email(email))
            .filter(|email| seen.insert(email.clone()))
            .collect()
    }
}

fn postmark_headers(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if let Ok(value) = HeaderValue::from_str(token) {
        headers.insert("X-Postmark-Server-Token", value);
    }
    headers
}

fn format_sender(name: &str, email: &str) -> String {
    let name = name.trim();
    if name.is_empty() {
        return email.to_string();
    }

    let safe_name = name
        .replace(['\r', '\n'], " ")
        .replace(['<', '>'], "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    format!("{} <{}>", safe_name, email)
}

fn is_valid_email(email: &str) -> bool {
    let email = email.trim();
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };

    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !email.chars().any(char::is_whitespace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{EmailConfig, MailjetEmailConfig, PostmarkEmailConfig};

    fn test_report() -> AbuseReportEmail {
        AbuseReportEmail {
            recipients: vec![
                "abuse@example.net".to_string(),
                "ABUSE@example.net".to_string(),
                "bad-address".to_string(),
                "soc@example.org".to_string(),
            ],
            subject: "Abuse report".to_string(),
            text_body: "text".to_string(),
            html_body: "<p>text</p>".to_string(),
            custom_id: Some("incident-1".to_string()),
        }
    }

    fn test_client(provider: &str, sandbox_mode: bool) -> EmailClient {
        EmailClient::new(EmailConfig {
            provider: provider.to_string(),
            from_email: "abuse@example.com".to_string(),
            from_name: "DevOps Agent Abuse Reports".to_string(),
            sandbox_mode,
            mailjet: MailjetEmailConfig {
                api_key: Some("key".to_string()),
                api_secret: Some("secret".to_string()),
                endpoint: "https://api.mailjet.com/v3.1/send".to_string(),
            },
            postmark: PostmarkEmailConfig {
                server_token: Some("server-token".to_string()),
                endpoint: "https://api.postmarkapp.com/email".to_string(),
                message_stream: "outbound".to_string(),
            },
        })
    }

    #[test]
    fn mailjet_builds_one_message_per_valid_recipient() {
        let payload = test_client("mailjet", true)
            .build_mailjet_payload(&test_report())
            .unwrap();
        assert_eq!(payload["SandboxMode"], true);
        let messages = payload["Messages"].as_array().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["To"][0]["Email"], "abuse@example.net");
        assert_eq!(messages[1]["To"][0]["Email"], "soc@example.org");
        assert_eq!(messages[0]["From"]["Email"], "abuse@example.com");
        assert_eq!(messages[0]["CustomID"], "incident-1");
    }

    #[test]
    fn postmark_builds_single_email_payloads() {
        let payloads = test_client("postmark", false)
            .build_postmark_payloads(&test_report())
            .unwrap();
        assert_eq!(payloads.len(), 2);
        assert_eq!(
            payloads[0]["From"],
            "DevOps Agent Abuse Reports <abuse@example.com>"
        );
        assert_eq!(payloads[0]["To"], "abuse@example.net");
        assert_eq!(payloads[0]["MessageStream"], "outbound");
        assert_eq!(payloads[0]["Metadata"]["incident_id"], "incident-1");
        assert_eq!(payloads[1]["To"], "soc@example.org");
    }

    #[test]
    fn postmark_sandbox_uses_test_token_without_secret() {
        let mut config = test_client("postmark", true).config;
        config.postmark.server_token = None;
        let client = EmailClient::new(config);

        assert_eq!(client.postmark_token().unwrap(), "POSTMARK_API_TEST");
    }

    #[test]
    fn rejects_payload_without_valid_recipients() {
        let report = AbuseReportEmail {
            recipients: vec!["not-email".to_string()],
            subject: "Abuse report".to_string(),
            text_body: "text".to_string(),
            html_body: "<p>text</p>".to_string(),
            custom_id: None,
        };

        assert!(matches!(
            test_client("mailjet", false).build_mailjet_payload(&report),
            Err(EmailError::NoRecipients)
        ));
        assert!(matches!(
            test_client("postmark", false).build_postmark_payloads(&report),
            Err(EmailError::NoRecipients)
        ));
    }
}
