use std::convert::TryFrom;
use std::net::{SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;

// TODO: make this use all specific thiserror errors
use anyhow::{format_err, Result};
use itertools::Itertools;
use rustls::{
    Certificate, ClientConfig, RootCertStore, ServerCertVerified, ServerCertVerifier, TLSError,
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;
use webpki::DNSNameRef;

const REDIRECT_CAP: usize = 5;

/// Gemini response codes
///
/// See https://gemini.circumlunar.space/docs/specification.html
/// for more information.
#[derive(Debug)]
pub enum Status {
    // 10
    Input,
    // 11
    SensitiveInput,
    // 20
    Success,
    // 30
    TemporaryRedirect,
    // 31
    PermanentRedirect,
    // 40
    TemporaryFailure,
    // 41
    ServerUnavailable,
    // 42
    CgiError,
    // 43
    ProxyError,
    // 44
    SlowDown,
    // 50
    PermanentFailure,
    // 51
    NotFound,
    // 52
    Gone,
    // 53
    ProxyRequestRefused,
    // 59
    BadRequest,
    // 60
    ClientCertificateRequired,
    // 61
    CertificateNotAuthorized,
    // 62
    CertificateNotValid,
}

#[derive(Debug, Error)]
pub enum ParseStatusError {
    #[error("invalid status \"{0}\"")]
    InvalidStatus(String),
}

impl FromStr for Status {
    type Err = ParseStatusError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "10" => Ok(Status::Input),
            "11" => Ok(Status::SensitiveInput),
            "20" => Ok(Status::Success),
            "30" => Ok(Status::TemporaryRedirect),
            "31" => Ok(Status::PermanentRedirect),
            "40" => Ok(Status::TemporaryFailure),
            "41" => Ok(Status::ServerUnavailable),
            "42" => Ok(Status::CgiError),
            "43" => Ok(Status::ProxyError),
            "44" => Ok(Status::SlowDown),
            "50" => Ok(Status::PermanentFailure),
            "51" => Ok(Status::NotFound),
            "52" => Ok(Status::Gone),
            "53" => Ok(Status::ProxyRequestRefused),
            "59" => Ok(Status::BadRequest),
            "60" => Ok(Status::ClientCertificateRequired),
            "61" => Ok(Status::CertificateNotAuthorized),
            "62" => Ok(Status::CertificateNotValid),
            _ => Err(ParseStatusError::InvalidStatus(s.to_string())),
        }
    }
}

/// Gemini page's single header
///
/// See https://gemini.circumlunar.space/docs/specification.html
/// for more information.
#[derive(Debug)]
pub struct Header {
    /// Header's status
    pub status: Status,

    /// Header's metadata string
    pub meta: String,
}

#[derive(Debug, Error)]
pub enum ParseHeaderError {
    #[error("missing status")]
    MissingStatus,
    #[error("missing meta")]
    MissingMeta,
    #[error(transparent)]
    InvalidStatus(#[from] ParseStatusError),
}

impl FromStr for Header {
    type Err = ParseHeaderError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.trim().split(' ').collect();

        let status: Status = parts
            .get(0)
            .ok_or(ParseHeaderError::MissingStatus)?
            .parse()?;
        let meta = parts.get(1).ok_or(ParseHeaderError::MissingMeta)?;

        Ok(Header {
            status,
            meta: meta.to_string(),
        })
    }
}

/// Single Gemini page
///
/// See https://gemini.circumlunar.space/docs/specification.html
/// for more information.
#[derive(Debug)]
pub struct Page {
    /// Page's URL
    pub url: Url,

    /// Page's single header
    pub header: Header,

    /// Page's optional body
    pub body: Option<String>,
}

pub enum ServerTLSValidation {
    SelfSigned(CertificateFingerprint),
    Chained,
}

pub struct CertificateFingerprint {
    digest: [u8; ring::digest::SHA256_OUTPUT_LEN],
    not_after: i64,
}

fn map_sig_to_webpki_err(e: x509_signature::Error) -> webpki::Error {
    match e {
        x509_signature::Error::UnsupportedCertVersion => webpki::Error::UnsupportedCertVersion,
        x509_signature::Error::UnsupportedSignatureAlgorithm => {
            webpki::Error::UnsupportedSignatureAlgorithm
        }
        x509_signature::Error::UnsupportedSignatureAlgorithmForPublicKey => {
            webpki::Error::UnsupportedSignatureAlgorithmForPublicKey
        }
        x509_signature::Error::InvalidSignatureForPublicKey => {
            webpki::Error::InvalidSignatureForPublicKey
        }
        x509_signature::Error::SignatureAlgorithmMismatch => {
            webpki::Error::SignatureAlgorithmMismatch
        }
        x509_signature::Error::BadDER => webpki::Error::BadDER,
        x509_signature::Error::BadDERTime => webpki::Error::BadDERTime,
        x509_signature::Error::CertNotValidYet => webpki::Error::CertNotValidYet,
        x509_signature::Error::CertExpired => webpki::Error::CertExpired,
        x509_signature::Error::InvalidCertValidity => webpki::Error::InvalidCertValidity,
        x509_signature::Error::UnknownIssuer => webpki::Error::UnknownIssuer,
        // TODO: This is a shitty default, but this should be a "lossless" conversion - i.e. we
        // can't really give back an error of a different type
        _ => webpki::Error::UnknownIssuer,
    }
}

fn unix_now() -> Result<i64, rustls::TLSError> {
    let now = std::time::SystemTime::now();
    let unix_now = now
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| TLSError::FailedToGetCurrentTime)?
        .as_secs();

    i64::try_from(unix_now).map_err(|_| TLSError::FailedToGetCurrentTime)
}

fn verify_selfsigned_certificate(
    cert: &Certificate,
    _dns_name: DNSNameRef<'_>,
    now: i64,
) -> Result<ServerCertVerified, x509_signature::Error> {
    let xcert = x509_signature::parse_certificate(cert.as_ref())?;
    xcert.valid_at_timestamp(now)?;
    xcert.check_self_issued()?;
    // TODO: this doesn't check the subject name, but this is a self signed cert,
    // so this is basically the wild west anyways. do we care?
    Ok(ServerCertVerified::assertion())
}

struct ExpectSelfSignedVerifier {
    webpki: rustls::WebPKIVerifier,
    fingerprint: CertificateFingerprint,
}

impl ServerCertVerifier for ExpectSelfSignedVerifier {
    fn verify_server_cert(
        &self,
        roots: &RootCertStore,
        presented_certs: &[Certificate],
        dns_name: DNSNameRef<'_>,
        ocsp_response: &[u8],
    ) -> Result<ServerCertVerified, TLSError> {
        // This is a special case for when the client presents a self-signed certificate
        if presented_certs.len() == 1 {
            let now = unix_now()?;

            if now > self.fingerprint.not_after {
                // The fingerprint is valid - hash & compare the presented certificate
                let dig =
                    ring::digest::digest(&ring::digest::SHA256, presented_certs[0].0.as_ref());
                if let Ok(()) = ring::constant_time::verify_slices_are_equal(
                    dig.as_ref(),
                    &self.fingerprint.digest,
                ) {
                    return Ok(ServerCertVerified::assertion());
                }
            } else {
                return verify_selfsigned_certificate(&presented_certs[0], dns_name, now)
                    .map_err(map_sig_to_webpki_err)
                    .map_err(rustls::TLSError::WebPKIError);
            }
        }

        let verified =
            self.webpki
                .verify_server_cert(roots, presented_certs, dns_name, ocsp_response)?;

        Ok(verified)
    }
}

struct PossiblySelfSignedVerifier {
    webpki: rustls::WebPKIVerifier,
}

impl ServerCertVerifier for PossiblySelfSignedVerifier {
    fn verify_server_cert(
        &self,
        roots: &RootCertStore,
        presented_certs: &[Certificate],
        dns_name: DNSNameRef<'_>,
        ocsp_response: &[u8],
    ) -> Result<ServerCertVerified, TLSError> {
        // This is a special case for when it looks like the client presents a self-signed
        // certificate
        if presented_certs.len() == 1 {
            let verified =
                verify_selfsigned_certificate(&presented_certs[0], dns_name, unix_now()?)
                    .map_err(map_sig_to_webpki_err)
                    .map_err(TLSError::WebPKIError)?;

            return Ok(verified);
        }

        let verified =
            self.webpki
                .verify_server_cert(roots, presented_certs, dns_name, ocsp_response)?;

        Ok(verified)
    }
}

async fn build_tls_config<'a>(
    validation: Option<ServerTLSValidation>,
) -> Result<Arc<ClientConfig>> {
    let mut config = ClientConfig::new();
    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    match validation {
        None => {
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(PossiblySelfSignedVerifier {
                    webpki: rustls::WebPKIVerifier::new(),
                }));
        }
        Some(ServerTLSValidation::SelfSigned(fingerprint)) => {
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(ExpectSelfSignedVerifier {
                    fingerprint,
                    webpki: rustls::WebPKIVerifier::new(),
                }));
        }
        _ => {}
    }

    Ok(Arc::new(config))
}

#[derive(Debug, Error)]
pub enum FetchPageError {
    #[error("unsupported scheme \"{0}\", only gemini is supported")]
    UnsupportedScheme(String),
    #[error("missing host in URL \"{0}\"")]
    MissingHost(String),
    #[error("failed to resolve URL \"{0}\"")]
    FailedToResolve(String),
    #[error("response is missing its header")]
    MissingHeader,
}

impl Page {
    /// Fetch the given Gemini link.
    ///
    /// Does not follow redirects or other status codes.
    pub async fn fetch(url: &Url, tls_validation: Option<ServerTLSValidation>) -> Result<Page> {
        let host = url
            .host_str()
            .ok_or_else(|| FetchPageError::MissingHost(url.to_string()))?;

        let port = url.port().unwrap_or(1965);

        let addr = format!("{}:{}", host, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| FetchPageError::FailedToResolve(url.to_string()))?;

        Self::fetch_from(url, addr, tls_validation).await
    }

    /// Fetch the given Gemini link from the specified socket address (e.g. a proxy).
    ///
    /// Does not follow redirects or other status codes.
    pub async fn fetch_from(
        url: &Url,
        addr: SocketAddr,
        tls_validation: Option<ServerTLSValidation>,
    ) -> Result<Page> {
        if url.scheme() != "gemini" {
            return Err(FetchPageError::UnsupportedScheme(url.to_string()).into());
        }

        let host = url
            .host_str()
            .ok_or_else(|| FetchPageError::MissingHost(url.to_string()))?;

        let dns_name = DNSNameRef::try_from_ascii_str(&host)?;
        let socket = TcpStream::connect(&addr).await?;
        let config = TlsConnector::from(build_tls_config(tls_validation).await?);

        let mut socket = config.connect(dns_name, socket).await?;

        socket.write_all(format!("{}\r\n", url).as_bytes()).await?;

        let mut data = Vec::new();
        socket.read_to_end(&mut data).await?;

        let response = String::from_utf8(data)?;
        let mut response_lines = response.lines();

        let header: Header = response_lines
            .next()
            .ok_or(FetchPageError::MissingHeader)?
            .parse()?;

        let body = response_lines.join("\n");

        Ok(Page {
            url: url.clone(),
            header,
            body: if body.is_empty() { None } else { Some(body) },
        })
    }

    /// Fetch the given Gemini link while following redirects
    pub async fn fetch_and_handle_redirects(url: &Url) -> Result<Page> {
        let mut url = url.clone();

        let mut attempts = 0;
        while attempts < REDIRECT_CAP {
            // TODO: verification
            let page = Page::fetch(&url, None).await?;

            if let Status::TemporaryRedirect | Status::PermanentRedirect = page.header.status {
                attempts += 1;
                url = Url::parse(&page.header.meta)?;
            } else {
                return Ok(page);
            }
        }

        Err(format_err!(
            "reached maximum redirect cap of {}",
            REDIRECT_CAP
        ))
    }
}
