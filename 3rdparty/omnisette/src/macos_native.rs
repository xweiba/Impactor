//! Local AOSKit/AuthKit data. Native objects never escape their autorelease pool.

use std::{any::Any, collections::HashMap, ffi::c_char};

use objc::{
    Encode, EncodeArguments, Message, MessageArguments,
    rc::{StrongPtr, autoreleasepool},
    runtime::{BOOL, Class, NO, Object, Sel},
};
use objc_foundation::{INSString, NSString};

use crate::{
    AnisetteConfiguration, AnisetteError, AnisetteHeaders, AnisetteHeadersProviderRes,
    anisette_headers_provider::AnisetteHeadersProvider,
};

const REQUIRED_HEADERS: [&str; 10] = [
    "X-Apple-I-MD",
    "X-Apple-I-MD-M",
    "X-Apple-I-MD-RINFO",
    "X-Apple-I-MD-LU",
    "X-Apple-Locale",
    "X-Mme-Client-Info",
    "X-Mme-Device-Id",
    "X-Apple-I-SRL-NO",
    "X-Apple-I-Client-Time",
    "X-Apple-I-TimeZone",
];

/// Only copied Rust data survives the native autorelease pool.
pub(crate) struct MacOsNativeAnisetteProvider {
    first_headers: Option<HashMap<String, String>>,
    configuration: AnisetteConfiguration,
    fallback: Option<AnisetteHeadersProviderRes>,
    native_failed: bool,
}

impl MacOsNativeAnisetteProvider {
    pub(crate) fn new(configuration: AnisetteConfiguration) -> Result<Self, AnisetteError> {
        // Select native only after a complete, usable snapshot succeeds.
        let first_headers = Some(native_headers()?);
        Ok(Self {
            first_headers,
            configuration,
            fallback: None,
            native_failed: false,
        })
    }

    fn prepare_headers(
        &mut self,
        collect: impl FnOnce() -> Result<HashMap<String, String>, AnisetteError>,
        fallback: impl FnOnce(
            AnisetteConfiguration,
        ) -> Result<AnisetteHeadersProviderRes, AnisetteError>,
    ) -> Result<Option<HashMap<String, String>>, AnisetteError> {
        if let Some(headers) = self.first_headers.take() {
            return Ok(Some(headers));
        }
        if self.fallback.is_none() {
            if !self.native_failed {
                if let Ok(headers) = collect() {
                    return Ok(Some(headers));
                }
                self.native_failed = true;
            }
            self.fallback = Some(fallback(self.configuration.clone())?);
        }
        Ok(None)
    }
}

#[cfg_attr(feature = "async", async_trait::async_trait)]
impl AnisetteHeadersProvider for MacOsNativeAnisetteProvider {
    #[cfg_attr(not(feature = "async"), remove_async_await::remove_async_await)]
    async fn get_anisette_headers(
        &mut self,
        skip_provisioning: bool,
    ) -> Result<HashMap<String, String>, AnisetteError> {
        if let Some(headers) =
            self.prepare_headers(native_headers, AnisetteHeaders::get_compatibility_provider)?
        {
            return Ok(headers);
        }
        // Stay on the selected fallback for the rest of this provider's life.
        // No Apple login request or credential retry occurs here.
        self.fallback
            .as_mut()
            .ok_or(AnisetteError::Misc)?
            .provider
            .get_anisette_headers(skip_provisioning)
            .await
    }
}

fn validate_headers(headers: &HashMap<String, String>) -> Result<(), AnisetteError> {
    for name in REQUIRED_HEADERS {
        let value = headers.get(name).ok_or(AnisetteError::Misc)?;
        if value.trim().is_empty() || reqwest::header::HeaderValue::from_str(value).is_err() {
            return Err(AnisetteError::Misc);
        }
    }
    Ok(())
}

fn class(name: &str) -> Result<&'static Class, AnisetteError> {
    Class::get(name).ok_or(AnisetteError::UnsupportedDevice)
}

// Callers supply live pool-scoped receivers and the documented native signature.
// Verify selectors and ABI before dispatch; never format native errors or objects.
unsafe fn send<T, A, R>(receiver: &T, name: &str, args: A) -> Result<R, AnisetteError>
where
    T: Message,
    A: MessageArguments + EncodeArguments,
    R: Any + Encode,
{
    let selector = Sel::register(name);
    receiver
        .verify_message::<A, R>(selector)
        .map_err(|_| AnisetteError::UnsupportedDevice)?;
    unsafe { receiver.send_message(selector, args) }.map_err(|_| AnisetteError::Misc)
}

unsafe fn get(receiver: *mut Object, name: &str) -> Result<*mut Object, AnisetteError> {
    let receiver = unsafe { receiver.as_ref() }.ok_or(AnisetteError::Misc)?;
    unsafe { send(receiver, name, ()) }
}

unsafe fn string(value: *mut Object) -> Result<String, AnisetteError> {
    let value = unsafe { value.as_ref() }.ok_or(AnisetteError::Misc)?;
    let is_string: BOOL = unsafe { send(value, "isKindOfClass:", (class("NSString")?,))? };
    if is_string == NO {
        return Err(AnisetteError::Misc);
    }
    // Borrow only within this pool, then copy. Do not adopt a +0 pointer as owned.
    let value = unsafe { &*(value as *const Object as *const NSString) };
    let bytes: *const c_char = unsafe { send(value, "UTF8String", ())? };
    if bytes.is_null() {
        return Err(AnisetteError::Misc);
    }
    // INSString::as_str internally unwraps UTF-8; keep conversion fallible here.
    let length: usize = unsafe { send(value, "lengthOfBytesUsingEncoding:", (4usize,))? };
    let bytes = unsafe { std::slice::from_raw_parts(bytes.cast::<u8>(), length) };
    let value = std::str::from_utf8(bytes).map_err(|_| AnisetteError::Misc)?;
    if value.trim().is_empty() {
        return Err(AnisetteError::Misc);
    }
    Ok(value.to_owned())
}

fn native_headers() -> Result<HashMap<String, String>, AnisetteError> {
    autoreleasepool(|| {
        // All +0 objects below stay inside this pool. Only the formatter's +1
        // result is owned; its guard drops before the pool drains.
        unsafe {
            // The referenced native interface is not supported on macOS 27.
            // Fail closed there and preserve the existing compatibility route.
            let process_info: *mut Object = send(class("NSProcessInfo")?, "processInfo", ())?;
            let version = string(get(process_info, "operatingSystemVersionString")?)?;
            if !supported_os(&version) {
                return Err(AnisetteError::UnsupportedDevice);
            }
            for path in [
                "/System/Library/PrivateFrameworks/AOSKit.framework",
                "/System/Library/PrivateFrameworks/AuthKit.framework",
            ] {
                let path = NSString::from_str(path);
                let bundle: *mut Object = send(
                    class("NSBundle")?,
                    "bundleWithPath:",
                    (&*path as *const NSString as *const Object,),
                )?;
                let bundle = bundle.as_ref().ok_or(AnisetteError::UnsupportedDevice)?;
                let loaded: BOOL = send(bundle, "load", ())?;
                if loaded == NO {
                    return Err(AnisetteError::UnsupportedDevice);
                }
            }

            let utilities = class("AOSUtilities")?;
            let dsid = NSString::from_str("-2");
            let otp: *mut Object = send(
                utilities,
                "retrieveOTPHeadersForDSID:",
                (&*dsid as *const NSString as *const Object,),
            )?;
            let otp = otp.as_ref().ok_or(AnisetteError::Misc)?;
            let is_dictionary: BOOL = send(otp, "isKindOfClass:", (class("NSDictionary")?,))?;
            if is_dictionary == NO {
                return Err(AnisetteError::Misc);
            }
            let device: *mut Object = send(class("AKDevice")?, "currentDevice", ())?;
            let mut headers = HashMap::new();
            for (source, target) in [
                ("X-Apple-MD", "X-Apple-I-MD"),
                ("X-Apple-MD-M", "X-Apple-I-MD-M"),
            ] {
                let key = NSString::from_str(source);
                let value = send(
                    otp,
                    "objectForKey:",
                    (&*key as *const NSString as *const Object,),
                )?;
                headers.insert(target.to_owned(), string(value)?);
            }
            headers.insert("X-Apple-I-MD-RINFO".to_owned(), "0".to_owned());
            for (selector, header) in [
                ("localUserUUID", "X-Apple-I-MD-LU"),
                ("serverFriendlyDescription", "X-Mme-Client-Info"),
                ("uniqueDeviceIdentifier", "X-Mme-Device-Id"),
            ] {
                headers.insert(header.to_owned(), string(get(device, selector)?)?);
            }
            let locale = get(device, "locale")?;
            headers.insert(
                "X-Apple-Locale".to_owned(),
                string(get(locale, "localeIdentifier")?)?,
            );
            headers.insert(
                "X-Apple-I-SRL-NO".to_owned(),
                string(send(utilities, "machineSerialNumber", ())?)?,
            );

            let date: *mut Object = send(class("NSDate")?, "date", ())?;
            if date.is_null() {
                return Err(AnisetteError::Misc);
            }
            let formatter: *mut Object = send(class("NSISO8601DateFormatter")?, "new", ())?;
            if formatter.is_null() {
                return Err(AnisetteError::Misc);
            }
            let formatter = StrongPtr::new(formatter);
            let time = send(&**formatter, "stringFromDate:", (date,))?;
            headers.insert("X-Apple-I-Client-Time".to_owned(), string(time)?);
            let timezone: *mut Object = send(class("NSTimeZone")?, "localTimeZone", ())?;
            headers.insert(
                "X-Apple-I-TimeZone".to_owned(),
                string(get(timezone, "name")?)?,
            );
            validate_headers(&headers)?;
            Ok(headers)
        }
    })
}

fn supported_os(description: &str) -> bool {
    description
        .split(|c: char| !c.is_ascii_digit())
        .find(|part| !part.is_empty())
        .and_then(|major| major.parse::<u32>().ok())
        .is_some_and(|major| (10..27).contains(&major))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_interface_is_limited_to_supported_os_versions() {
        assert!(supported_os("Version 26.4.1 (Build 25E123)"));
        assert!(supported_os("版本26.4.1"));
        assert!(!supported_os("Version 27.0 (Build 26A123)"));
        assert!(!supported_os("unknown"));
    }

    fn fixture() -> HashMap<String, String> {
        REQUIRED_HEADERS
            .into_iter()
            .map(|name| (name.to_owned(), "synthetic".to_owned()))
            .collect()
    }

    fn synthetic_provider() -> MacOsNativeAnisetteProvider {
        MacOsNativeAnisetteProvider {
            first_headers: Some(fixture()),
            configuration: AnisetteConfiguration::new(),
            fallback: None,
            native_failed: false,
        }
    }

    #[test]
    fn first_snapshot_does_not_collect_again() {
        let mut provider = synthetic_provider();
        assert!(
            provider
                .prepare_headers(
                    || panic!("cached snapshot must be used"),
                    |_| panic!("fallback must not be built"),
                )
                .is_ok_and(|headers| headers.is_some())
        );
        assert!(provider.first_headers.is_none());
    }

    #[test]
    fn fallback_failure_does_not_reenter_native() {
        let mut provider = synthetic_provider();
        provider.first_headers = None;
        assert!(
            provider
                .prepare_headers(
                    || Err(AnisetteError::Misc),
                    |_| Err(AnisetteError::UnsupportedDevice),
                )
                .is_err()
        );
        assert!(provider.native_failed);
        assert!(
            provider
                .prepare_headers(
                    || panic!("native must remain disabled"),
                    |_| Err(AnisetteError::UnsupportedDevice),
                )
                .is_err()
        );
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn fallback_is_retained_and_receives_skip_provisioning() {
        struct SyntheticFallback;
        #[async_trait::async_trait]
        impl AnisetteHeadersProvider for SyntheticFallback {
            async fn get_anisette_headers(
                &mut self,
                skip: bool,
            ) -> Result<HashMap<String, String>, AnisetteError> {
                Ok(HashMap::from([("synthetic-skip".into(), skip.to_string())]))
            }
        }
        let mut provider = synthetic_provider();
        provider.first_headers = None;
        assert!(
            provider
                .prepare_headers(
                    || Err(AnisetteError::Misc),
                    |_| Ok(AnisetteHeadersProviderRes::local(Box::new(
                        SyntheticFallback
                    ))),
                )
                .is_ok_and(|headers| headers.is_none())
        );
        assert!(
            provider
                .prepare_headers(
                    || panic!("must keep fallback"),
                    |_| panic!("must not recreate fallback"),
                )
                .is_ok_and(|headers| headers.is_none())
        );
        for skip in [true, false] {
            let headers = provider.get_anisette_headers(skip).await;
            assert!(
                headers
                    .is_ok_and(|headers| headers.get("synthetic-skip") == Some(&skip.to_string()))
            );
        }
    }

    #[test]
    fn accepts_complete_headers() {
        assert!(validate_headers(&fixture()).is_ok());
    }

    #[test]
    fn rejects_each_missing_or_invalid_header() {
        for name in REQUIRED_HEADERS {
            let mut headers = fixture();
            headers.remove(name);
            assert!(validate_headers(&headers).is_err());
            for invalid in ["", "  ", "value\r\nInjected: value", "value\0"] {
                headers.insert(name.to_owned(), invalid.to_owned());
                assert!(validate_headers(&headers).is_err());
            }
        }
    }

    #[test]
    #[ignore = "opt-in macOS native framework smoke; generates local data only"]
    fn native_smoke() {
        assert!(MacOsNativeAnisetteProvider::new(AnisetteConfiguration::new()).is_ok());
        let result = native_headers();
        assert!(result.is_ok());
        assert!(
            result
                .as_ref()
                .is_ok_and(|headers| validate_headers(headers).is_ok())
        );
    }
}
