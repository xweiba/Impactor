use omnisette::AnisetteConfiguration;
use plist::{Dictionary, Value};
use reqwest::header::{HeaderMap, HeaderValue};
use sha2::{Digest, Sha256};
use srp::groups::G2048;

use crate::Error;

use crate::auth::account::{check_error, parse_response};
use crate::auth::anisette_data::AnisetteData;
use crate::auth::{
    Account, ChallengeRequest, ChallengeRequestBody, GSA_ENDPOINT, InitRequest, InitRequestBody,
    LoginState, RequestHeader, TrustedPhoneNumber, TwoFactorAction, TwoFactorMethod,
    TwoFactorRequest,
};

#[macro_export]
macro_rules! plist_get_string {
    ($base:expr, $( $path:literal )+, $final_key:literal) => {{
        let mut current_val = $base;
        $(
            current_val = current_val
                .get($path)
                .expect(concat!("Missing dictionary key: ", $path))
                .as_dictionary()
                .expect(concat!("Key value is not a dictionary: ", $path));
        )+
        current_val
            .get($final_key)
            .expect(concat!("Missing string key: ", $final_key))
            .as_string()
            .expect(concat!("Value is not a string: ", $final_key))
            .to_string()
    }};

    ($base:expr, $key:literal) => {{
        $base
            .get($key)
            .expect(concat!("Missing key: ", $key))
            .as_string()
            .expect(concat!("Value is not a string: ", $key))
            .to_string()
    }};
}

fn srp_password_material(password: &str, protocol: Option<&str>) -> Result<Vec<u8>, Error> {
    let digest = Sha256::digest(password.as_bytes());

    match protocol {
        Some("s2k") | None => Ok(digest.to_vec()),
        Some("s2k_fo") => Ok(hex::encode(digest).into_bytes()),
        Some(protocol) => Err(Error::AuthSrpWithMessage(
            0,
            format!("Unsupported SRP password protocol: {protocol}"),
        )),
    }
}

impl Account {
    pub async fn login(
        appleid_closure: impl Fn() -> Result<(String, String), String>,
        tfa_closure: impl Fn(TwoFactorRequest) -> Result<TwoFactorAction, String>,
        config: AnisetteConfiguration,
    ) -> Result<Account, Error> {
        let anisette = AnisetteData::new(config).await?;
        Account::login_with_anisette(appleid_closure, tfa_closure, anisette).await
    }

    pub async fn login_with_anisette<
        F: Fn() -> Result<(String, String), String>,
        G: Fn(TwoFactorRequest) -> Result<TwoFactorAction, String>,
    >(
        appleid_closure: F,
        tfa_closure: G,
        anisette: AnisetteData,
    ) -> Result<Account, Error> {
        let mut _self = Account::new_with_anisette(anisette)?;
        let (username, password) = appleid_closure().map_err(|e| {
            Error::AuthSrpWithMessage(0, format!("Failed to get Apple ID credentials: {}", e))
        })?;

        let mut response = _self.login_email_pass(&username, &password).await?;
        // Cached so the caller can be offered an SMS fallback even when a trusted
        // device handled the push. Fetched lazily the first time 2FA is needed.
        let mut trusted_phone_numbers: Vec<TrustedPhoneNumber> = Vec::new();

        loop {
            match response {
                LoginState::NeedsDevice2FA => {
                    response = _self.send_2fa_to_devices().await?;
                    if trusted_phone_numbers.is_empty() {
                        if let Ok(extras) = _self.get_auth_extras().await {
                            trusted_phone_numbers = extras.trusted_phone_numbers;
                        }
                    }
                }
                LoginState::Needs2FAVerification => {
                    let request = TwoFactorRequest {
                        method: TwoFactorMethod::Device,
                        trusted_phone_numbers: trusted_phone_numbers.clone(),
                    };
                    match tfa_closure(request).map_err(|e| {
                        Error::AuthSrpWithMessage(0, format!("Failed to get 2FA code: {}", e))
                    })? {
                        TwoFactorAction::SubmitCode(code) => {
                            response = _self.verify_2fa(code).await?
                        }
                        TwoFactorAction::SendSms(id) => {
                            response = _self.send_sms_2fa_to_devices(id).await?
                        }
                    }
                }
                LoginState::NeedsSMS2FA => {
                    if trusted_phone_numbers.is_empty() {
                        if let Ok(extras) = _self.get_auth_extras().await {
                            trusted_phone_numbers = extras.trusted_phone_numbers;
                        }
                    }
                    let id = trusted_phone_numbers.first().map(|p| p.id).unwrap_or(1);
                    response = _self.send_sms_2fa_to_devices(id).await?;
                }
                LoginState::NeedsSMS2FAVerification(body) => {
                    let request = TwoFactorRequest {
                        method: TwoFactorMethod::Sms,
                        trusted_phone_numbers: trusted_phone_numbers.clone(),
                    };
                    match tfa_closure(request).map_err(|e| {
                        Error::AuthSrpWithMessage(
                            0,
                            format!("Failed to get SMS 2FA code: {}", e),
                        )
                    })? {
                        TwoFactorAction::SubmitCode(code) => {
                            response = _self.verify_sms_2fa(code, body).await?
                        }
                        TwoFactorAction::SendSms(id) => {
                            response = _self.send_sms_2fa_to_devices(id).await?
                        }
                    }
                }
                LoginState::NeedsLogin => {
                    response = _self.login_email_pass(&username, &password).await?
                }
                LoginState::LoggedIn => return Ok(_self),
                LoginState::NeedsExtraStep(step) => {
                    if _self.get_pet().is_some() {
                        return Ok(_self);
                    } else {
                        return Err(Error::ExtraStep(step));
                    }
                }
            }
        }
    }

    pub async fn login_email_pass(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<LoginState, Error> {
        let username_for_spd = username.to_string().to_lowercase();
        let srp_client = srp::Client::<G2048, Sha256>::new_with_options(false);
        let a: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let a_pub = srp_client.compute_public_ephemeral(&a);

        let anisette = self.get_anisette().await;

        let mut gsa_headers = HeaderMap::new();
        gsa_headers.insert(
            "Content-Type",
            HeaderValue::from_str("text/x-xml-plist").unwrap(),
        );
        gsa_headers.insert("Accept", HeaderValue::from_str("*/*").unwrap());
        gsa_headers.insert(
            "User-Agent",
            HeaderValue::from_str("akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0").unwrap(),
        );
        gsa_headers.insert(
            "X-MMe-Client-Info",
            HeaderValue::from_str(&anisette.get_header("x-mme-client-info")?).unwrap(),
        );

        let header = RequestHeader {
            version: "1.0.1".to_string(),
        };
        let init_body = InitRequestBody {
            a_pub: plist::Value::Data(a_pub),
            cpd: anisette.to_plist(true, false, false),
            operation: "init".to_string(),
            ps: vec!["s2k".to_string(), "s2k_fo".to_string()],
            username: username_for_spd.clone(),
        };

        let init_packet = InitRequest {
            header: header.clone(),
            request: init_body,
        };

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &init_packet)?;

        let res = self
            .client
            .post(GSA_ENDPOINT)
            .headers(gsa_headers.clone())
            .body(buffer)
            .send()
            .await;

        let res = parse_response(res).await?;
        check_error(&res)?;

        let protocol = match res.get("sp") {
            Some(Value::String(protocol)) => Some(protocol.as_str()),
            None => None,
            Some(_) => {
                return Err(Error::AuthSrpWithMessage(
                    0,
                    "Invalid SRP password protocol value".to_string(),
                ));
            }
        };
        // Older responses omitted `sp` and historically used s2k. Preserve that
        // compatibility, but reject unknown named protocols instead of deriving
        // credentials with the wrong algorithm.
        let password_material = srp_password_material(password, protocol)?;
        let protocol_name = protocol.unwrap_or("s2k");
        eprintln!("PAOPAO_LOGIN_STAGE=srp_init_ok:{protocol_name}");

        let salt = res.get("s").unwrap().as_data().unwrap();
        let b_pub = res.get("B").unwrap().as_data().unwrap();
        let iters = res.get("i").unwrap().as_signed_integer().unwrap();
        let c = res.get("c").unwrap().as_string().unwrap();

        let mut password_buf = [0u8; 32];
        pbkdf2::pbkdf2::<hmac::Hmac<Sha256>>(
            &password_material,
            salt,
            iters as u32,
            &mut password_buf,
        )?;

        let verifier = srp_client
            .process_reply(&a, username_for_spd.as_bytes(), &password_buf, salt, b_pub)
            .unwrap();

        let challenge_body = ChallengeRequestBody {
            m: plist::Value::Data(verifier.proof().to_vec()),
            c: c.to_string(),
            cpd: anisette.to_plist(true, false, false),
            operation: "complete".to_string(),
            username: username_for_spd.clone(),
        };

        let challenge_packet = ChallengeRequest {
            header,
            request: challenge_body,
        };

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &challenge_packet)?;

        gsa_headers.insert("Connection", HeaderValue::from_static("close"));

        let res = self
            .client
            .post(GSA_ENDPOINT)
            .headers(gsa_headers)
            .body(buffer)
            .send()
            .await;

        let res = parse_response(res).await?;
        eprintln!("PAOPAO_LOGIN_STAGE=srp_complete_response");
        check_error(&res)?;
        eprintln!("PAOPAO_LOGIN_STAGE=srp_complete_ok");

        let m2 = res.get("M2").unwrap().as_data().unwrap();
        verifier.verify_server(m2).unwrap();

        let spd_encrypted = res.get("spd").unwrap().as_data().unwrap();
        let spd_decrypted = super::decrypt_cbc(&verifier, spd_encrypted);
        let mut spd: Dictionary = plist::from_bytes(&spd_decrypted).unwrap();

        if !spd.contains_key("appleId") {
            spd.insert(
                "appleId".to_string(),
                plist::Value::String(username_for_spd),
            );
        }

        self.spd = Some(spd);

        let status = res.get("Status").unwrap().as_dictionary().unwrap();
        if let Some(Value::String(auth_type)) = status.get("au") {
            return match auth_type.as_str() {
                "trustedDeviceSecondaryAuth" => {
                    eprintln!("PAOPAO_LOGIN_STAGE=trusted_device_2fa");
                    Ok(LoginState::NeedsDevice2FA)
                }
                "secondaryAuth" => {
                    eprintln!("PAOPAO_LOGIN_STAGE=sms_2fa");
                    Ok(LoginState::NeedsSMS2FA)
                }
                other => {
                    eprintln!("PAOPAO_LOGIN_STAGE=extra_step");
                    Ok(LoginState::NeedsExtraStep(other.to_string()))
                }
            };
        }

        eprintln!("PAOPAO_LOGIN_STAGE=logged_in");
        Ok(LoginState::LoggedIn)
    }

    pub fn get_pet(&self) -> Option<String> {
        let base = self.spd.as_ref().unwrap();
        let token = base.get("t")?.as_dictionary()?;

        Some(plist_get_string!(token, "com.apple.gs.idms.pet", "token"))
    }

    pub fn get_name(&self) -> (String, String) {
        let base = self.spd.as_ref().unwrap();
        (plist_get_string!(base, "fn"), plist_get_string!(base, "ln"))
    }

    pub async fn get_anisette(&self) -> AnisetteData {
        let mut locked = self.anisette.lock().await;
        if locked.needs_refresh() {
            *locked = locked.refresh().await.unwrap();
        }
        locked.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::srp_password_material;

    const SHA256_PASSWORD: &[u8] = &[
        0x5e, 0x88, 0x48, 0x98, 0xda, 0x28, 0x04, 0x71, 0x51, 0xd0, 0xe5, 0x6f, 0x8d, 0xc6,
        0x29, 0x27, 0x73, 0x60, 0x3d, 0x0d, 0x6a, 0xab, 0xbd, 0xd6, 0x2a, 0x11, 0xef, 0x72,
        0x1d, 0x15, 0x42, 0xd8,
    ];

    #[test]
    fn s2k_uses_raw_sha256_password() {
        assert_eq!(
            srp_password_material("password", Some("s2k")).unwrap(),
            SHA256_PASSWORD
        );
    }

    #[test]
    fn s2k_fo_uses_lowercase_ascii_hex_of_sha256_password() {
        assert_eq!(
            srp_password_material("password", Some("s2k_fo")).unwrap(),
            b"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        );
    }

    #[test]
    fn missing_protocol_uses_legacy_s2k_but_unknown_protocol_is_rejected() {
        assert_eq!(
            srp_password_material("password", None).unwrap(),
            SHA256_PASSWORD
        );
        assert!(srp_password_material("password", Some("future_protocol")).is_err());
    }
}
