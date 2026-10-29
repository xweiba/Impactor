use std::collections::HashMap;
use std::time::SystemTime;

use omnisette::{AnisetteConfiguration, AnisetteHeaders, AnisetteHeadersProviderType};
use reqwest::header::{HeaderMap, HeaderValue};

use crate::Error;

#[derive(Debug, Clone)]
pub struct AnisetteData {
    pub base_headers: HashMap<String, String>,
    pub generated_at: SystemTime,
    pub config: AnisetteConfiguration,
}

impl AnisetteData {
    /// Shared GrandSlam headers for password authentication and app-token
    /// exchange. Local providers may omit client-info after upstream #303.
    pub(crate) fn gsa_headers(&self) -> Result<HeaderMap, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", HeaderValue::from_static("text/x-xml-plist"));
        headers.insert("Accept", HeaderValue::from_static("*/*"));
        headers.insert(
            "User-Agent",
            HeaderValue::from_static("akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"),
        );
        if let Ok(client_info) = self.get_header("x-mme-client-info") {
            headers.insert(
                "X-MMe-Client-Info",
                HeaderValue::from_str(&client_info).map_err(|_| Error::Parse)?,
            );
        }
        Ok(headers)
    }

    pub async fn new(config: AnisetteConfiguration) -> Result<Self, Error> {
        let mut b = AnisetteHeaders::get_anisette_headers_provider(config.clone())?;
        eprintln!(
            "PAOPAO_LOGIN_PROVIDER={}",
            match b.provider_type {
                AnisetteHeadersProviderType::Local => "local",
                AnisetteHeadersProviderType::Remote => "remote",
            }
        );
        let base_headers = b.provider.get_authentication_headers().await?;

        Ok(AnisetteData {
            base_headers,
            generated_at: SystemTime::now(),
            config,
        })
    }

    pub fn needs_refresh(&self) -> bool {
        let elapsed = self.generated_at.elapsed().unwrap();
        elapsed.as_secs() > 60
    }

    pub fn is_valid(&self) -> bool {
        let elapsed = self.generated_at.elapsed().unwrap();
        elapsed.as_secs() < 90
    }

    pub async fn refresh(&self) -> Result<Self, crate::Error> {
        Self::new(self.config.clone()).await
    }

    pub fn generate_headers(
        &self,
        cpd: bool,
        client_info: bool,
        app_info: bool,
    ) -> HashMap<String, String> {
        if !self.is_valid() {
            panic!("Invalid data!")
        }

        let mut headers = self.base_headers.clone();
        let old_client_info = headers.remove("X-Mme-Client-Info");

        if client_info && let Some(value) = old_client_info {
            // Local providers may omit client-info after upstream #303. That
            // must not suppress the independent application/CPD fields below.
            let client_info = match value
                .split('<')
                .nth(3)
                .and_then(|part| part.split('>').next())
            {
                Some(component) => {
                    value.replace(component, "com.apple.AuthKit/1 (com.apple.akd/1.0)")
                }
                None => value,
            };
            headers.insert("X-Mme-Client-Info".to_owned(), client_info.to_owned());
        }

        if app_info {
            headers.insert(
                "X-Apple-App-Info".to_owned(),
                "com.apple.gs.xcode.auth".to_owned(),
            );
            headers.insert("X-Xcode-Version".to_owned(), "11.2 (11B41)".to_owned());
        }

        if cpd {
            headers.insert("bootstrap".to_owned(), "true".to_owned());
            headers.insert("icscrec".to_owned(), "true".to_owned());
            headers.insert("loc".to_owned(), "en_GB".to_owned());
            headers.insert("pbe".to_owned(), "false".to_owned());
            headers.insert("prkgen".to_owned(), "true".to_owned());
            headers.insert("svct".to_owned(), "iCloud".to_owned());
        }

        headers
    }

    pub fn to_plist(&self, cpd: bool, client_info: bool, app_info: bool) -> plist::Dictionary {
        let mut plist = plist::Dictionary::new();
        for (key, value) in self.generate_headers(cpd, client_info, app_info).iter() {
            plist.insert(key.to_owned(), plist::Value::String(value.to_owned()));
        }

        plist
    }

    pub fn get_header(&self, header: &str) -> Result<String, Error> {
        let headers = self
            .generate_headers(true, true, true)
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.to_owned()))
            .collect::<HashMap<String, String>>();

        match headers.get(&header.to_lowercase()) {
            Some(v) => Ok(v.to_string()),
            None => Err(Error::DeveloperSessionRequestFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_provider_without_client_info_keeps_required_fields() {
        let data = AnisetteData {
            base_headers: HashMap::new(),
            generated_at: SystemTime::now(),
            config: AnisetteConfiguration::default(),
        };
        let headers = data.generate_headers(true, true, true);
        assert!(!headers.contains_key("X-Mme-Client-Info"));
        assert_eq!(
            headers.get("X-Apple-App-Info").map(String::as_str),
            Some("com.apple.gs.xcode.auth")
        );
        assert_eq!(headers.get("bootstrap").map(String::as_str), Some("true"));
        assert!(data.get_header("x-mme-client-info").is_err());
        let gsa = data.gsa_headers().unwrap();
        assert!(!gsa.contains_key("X-MMe-Client-Info"));
        assert_eq!(gsa.get("Content-Type").unwrap(), "text/x-xml-plist");
    }

    #[test]
    fn header_lookup_preserves_provider_identity_case() {
        let data = AnisetteData {
            base_headers: HashMap::from([(
                "X-Mme-Client-Info".into(),
                "<Mac> <macOS;26> <Provider/1>".into(),
            )]),
            generated_at: SystemTime::now(),
            config: AnisetteConfiguration::default(),
        };
        assert_eq!(
            data.get_header("x-mme-client-info").unwrap(),
            "<Mac> <macOS;26> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
        );
        assert_eq!(
            data.gsa_headers()
                .unwrap()
                .get("X-MMe-Client-Info")
                .unwrap(),
            "<Mac> <macOS;26> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
        );
    }
}
