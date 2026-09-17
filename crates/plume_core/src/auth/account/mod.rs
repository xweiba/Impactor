mod login;
mod token;
mod two_factor_auth;

use aes::cipher::BlockModeDecrypt;
use cbc::cipher::{KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, KeyInit, Mac};
use reqwest::Response;
use sha2::Sha256;
use srp::ClientVerifier;

use crate::Error;

pub async fn parse_response(
    res: Result<Response, reqwest::Error>,
) -> Result<plist::Dictionary, Error> {
    let res = res?;
    let status = res.status().as_u16();
    let body = res.bytes().await?;

    eprintln!("PAOPAO_RESPONSE_FORMAT={}", response_format(&body));
    eprintln!("PAOPAO_HTTP_STATUS={status:03}");

    parse_response_bytes(&body)
}

fn response_format(body: &[u8]) -> &'static str {
    if body.starts_with(b"bplist00") {
        "binary"
    } else if body
        .iter()
        .copied()
        .skip_while(u8::is_ascii_whitespace)
        .take(5)
        .eq(b"<?xml".iter().copied())
    {
        "xml"
    } else {
        "other"
    }
}

fn parse_response_bytes(body: &[u8]) -> Result<plist::Dictionary, Error> {
    // Parse the original bytes so binary plist data is never lossy-decoded as text.
    let mut envelope: plist::Dictionary = plist::from_bytes(body)?;
    match envelope.remove("Response") {
        Some(plist::Value::Dictionary(response)) => Ok(response),
        _ => Err(Error::Parse),
    }
}

#[cfg(test)]
mod response_tests {
    use super::{check_error, parse_response_bytes, response_format};

    fn response_envelope() -> (plist::Dictionary, plist::Dictionary) {
        let mut response = plist::Dictionary::new();
        response.insert(
            "data".to_string(),
            plist::Value::Data(vec![0xff, 0x80, 0x00, 0xfe]),
        );
        let mut envelope = plist::Dictionary::new();
        envelope.insert(
            "Response".to_string(),
            plist::Value::Dictionary(response.clone()),
        );
        (envelope, response)
    }

    #[test]
    fn parses_binary_response_without_corrupting_data() {
        let (envelope, response) = response_envelope();
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &envelope).unwrap();

        assert_eq!(response_format(&body), "binary");
        assert_eq!(parse_response_bytes(&body).unwrap(), response);
    }

    #[test]
    fn parses_xml_response_without_corrupting_data() {
        let (envelope, response) = response_envelope();
        let mut body = Vec::new();
        plist::to_writer_xml(&mut body, &envelope).unwrap();

        assert_eq!(response_format(&body), "xml");
        assert_eq!(parse_response_bytes(&body).unwrap(), response);
    }

    #[test]
    fn rejects_plist_without_response_dictionary() {
        let mut body = Vec::new();
        plist::to_writer_xml(&mut body, &plist::Dictionary::new()).unwrap();

        assert!(parse_response_bytes(&body).is_err());
        assert_eq!(response_format(b"not a plist"), "other");
        assert!(check_error(&plist::Dictionary::new()).is_err());
    }
}

pub fn check_error(res: &plist::Dictionary) -> Result<(), Error> {
    let res = match res.get("Status") {
        Some(plist::Value::Dictionary(d)) => d,
        _ => &res,
    };

    let error_code = res
        .get("ec")
        .and_then(plist::Value::as_signed_integer)
        .ok_or(Error::Parse)?;

    if error_code != 0 {
        let message = res
            .get("em")
            .and_then(plist::Value::as_string)
            .ok_or(Error::Parse)?;
        return Err(Error::AuthSrpWithMessage(
            error_code.into(),
            message.to_owned(),
        ));
    }

    Ok(())
}

pub fn decrypt_cbc(usr: &ClientVerifier<Sha256>, data: &[u8]) -> Vec<u8> {
    let extra_data_key = create_session_key(usr, "extra data key:");
    let extra_data_iv = create_session_key(usr, "extra data iv:");
    let extra_data_iv = &extra_data_iv[..16];

    cbc::Decryptor::<aes::Aes256>::new_from_slices(&extra_data_key, extra_data_iv)
        .unwrap()
        .decrypt_padded_vec::<Pkcs7>(&data)
        .unwrap()
}

pub fn create_session_key(usr: &ClientVerifier<Sha256>, name: &str) -> Vec<u8> {
    Hmac::<Sha256>::new_from_slice(&usr.key())
        .unwrap()
        .chain_update(name.as_bytes())
        .finalize()
        .into_bytes()
        .to_vec()
}
