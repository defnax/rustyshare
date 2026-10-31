//! Verification of RetroShare SSL certificates, following libretroshare's
//! `AuthSSLimpl::VerifyX509Callback()` / `AuthX509WithGPG()` (pqi/authssl.cc):
//!
//! 1. the certificate's issuer CN is the peer's PGP id (or PGP fingerprint)
//! 2. the certificate's "signature" is an OpenPGP signature by that PGP key over the
//!    DER encoded TBSCertificate (0.6 certificates: over SHA1(TBSCertificate))
//! 3. the SSL id is derived from the signature (sha256 for new certificates, last
//!    16 bytes for old ones) and must match the location we expect / know
//! 4. the TLS handshake signature is checked with the certificate's RSA key
//!    (webpki can't do it because RetroShare certificates are X509 v1)

use openpgp::{parse::Parse, Cert, Packet};
use openssl::{
    hash::MessageDigest,
    nid::Nid,
    rsa::Padding,
    sign::{RsaPssSaltlen, Verifier},
    x509::X509,
};
use retroshare_compat::basics::SslId;
use rustls::SignatureScheme;
use sequoia_openpgp as openpgp;

/// libretroshare: `RS_CERTIFICATE_VERSION_NUMBER_06_0001`
const CERT_VERSION_06_0001: u64 = 0x0006_0001;
/// libretroshare: `RS_CERTIFICATE_VERSION_NUMBER_07_0001`
const CERT_VERSION_07_0001: u64 = 0x0007_0001;
/// libretroshare: `CERTSIGNLEN`
const CERTSIGNLEN: usize = 16;

pub type VerifyResult<T> = Result<T, String>;

/// Reads one DER TLV header at `pos`, returns (header length, content length).
fn der_header(data: &[u8], pos: usize) -> VerifyResult<(usize, usize)> {
    let first = *data.get(pos + 1).ok_or("DER: truncated")?;
    if first & 0x80 == 0 {
        return Ok((2, first as usize));
    }
    let n = (first & 0x7f) as usize;
    let bytes = data.get(pos + 2..pos + 2 + n).ok_or("DER: truncated")?;
    let len = bytes.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize);
    Ok((2 + n, len))
}

/// Splits a DER encoded certificate into (TBSCertificate incl. header, signature bytes).
pub fn split_cert(der: &[u8]) -> VerifyResult<(&[u8], &[u8])> {
    let (outer_hl, _) = der_header(der, 0)?;
    let tbs_start = outer_hl;
    let (hl, len) = der_header(der, tbs_start)?;
    let alg_start = tbs_start + hl + len;
    let (hl, len) = der_header(der, alg_start)?;
    let sig_start = alg_start + hl + len;
    let (hl, len) = der_header(der, sig_start)?;
    let bits = der
        .get(sig_start + hl..sig_start + hl + len)
        .ok_or("DER: truncated signature")?;
    // first byte of a BIT STRING = number of unused bits
    let sig = bits.get(1..).ok_or("DER: empty signature")?;
    Ok((
        der.get(tbs_start..alg_start).ok_or("DER: truncated TBS")?,
        sig,
    ))
}

fn serial_number(cert: &X509) -> u64 {
    cert.serial_number()
        .to_bn()
        .map(|bn| {
            let bytes = bn.to_vec();
            // like BN_get_word(): values wider than 64 bit don't fit
            if bytes.len() > 8 {
                u64::MAX
            } else {
                bytes.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64)
            }
        })
        .unwrap_or(0)
}

/// SSL id (location id) of a RetroShare certificate, like `getX509id()`.
pub fn cert_ssl_id(der: &[u8]) -> VerifyResult<SslId> {
    let cert = X509::from_der(der).map_err(|e| format!("invalid certificate: {e}"))?;
    let (_, sig) = split_cert(der)?;

    // like getX509RetroshareCertificateVersion(): only these exact serial numbers mark
    // new certificates, older ones have random serials and use the old method
    let serial = serial_number(&cert);
    let id: Vec<u8> = if serial == CERT_VERSION_06_0001 || serial == CERT_VERSION_07_0001 {
        openssl::sha::sha256(sig)[..16].to_vec()
    } else {
        if sig.len() < CERTSIGNLEN {
            return Err("certificate signature too short".into());
        }
        sig[sig.len() - CERTSIGNLEN..].to_vec()
    };
    Ok(SslId(id.try_into().expect("16 bytes")))
}

/// Issuer CN of the certificate (the PGP id in hex).
pub fn cert_issuer(der: &[u8]) -> VerifyResult<String> {
    let cert = X509::from_der(der).map_err(|e| format!("invalid certificate: {e}"))?;
    let entry = cert
        .issuer_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .ok_or("certificate has no issuer CN")?;
    Ok(String::from_utf8_lossy(entry.data().as_slice()).to_string())
}

/// Checks that the certificate is signed by the given PGP key.
pub fn verify_cert_pgp(der: &[u8], pgp: &Cert) -> VerifyResult<()> {
    let (tbs, sig_bytes) = split_cert(der)?;
    let sig = match Packet::from_bytes(sig_bytes) {
        Ok(Packet::Signature(sig)) => sig,
        Ok(_) => return Err("certificate signature is not a PGP signature".into()),
        Err(e) => return Err(format!("can't parse certificate PGP signature: {e}")),
    };

    // current certificates sign the TBS directly, 0.6 certificates sign SHA1(TBS)
    let sha1 = openssl::sha::sha1(tbs);
    let candidates: [&[u8]; 2] = [tbs, &sha1];

    for data in candidates {
        for key in pgp.keys() {
            #[allow(unused_mut)]
            let mut sig = sig.clone();
            if sig.verify_message(key.key(), data).is_ok() {
                return Ok(());
            }
        }
    }
    Err("PGP signature on the certificate is invalid".into())
}

/// Full check of a peer certificate against the PGP key of the friend it claims to be.
/// Returns the certificate's SSL id.
pub fn check_peer_cert(
    der: &[u8],
    pgp: &Cert,
    expected_id: Option<&SslId>,
) -> VerifyResult<SslId> {
    // 1. issuer must be the friend's PGP id or fingerprint
    let issuer = cert_issuer(der)?;
    let keyid = pgp.keyid().to_hex();
    let fpr = pgp.fingerprint().to_hex();
    if !issuer.eq_ignore_ascii_case(&keyid) && !issuer.eq_ignore_ascii_case(&fpr) {
        return Err(format!(
            "certificate issuer {issuer} does not match the friend's PGP id {keyid}"
        ));
    }

    // 2. PGP signature
    verify_cert_pgp(der, pgp)?;

    // 3. SSL id
    let id = cert_ssl_id(der)?;
    if let Some(expected) = expected_id {
        if &id != expected {
            return Err(format!(
                "certificate is for location {id}, expected {expected}"
            ));
        }
    }
    Ok(id)
}

/// Verifies a TLS handshake signature (CertificateVerify / ServerKeyExchange) made with
/// the certificate's key.
pub fn verify_handshake_sig(
    cert_der: &[u8],
    message: &[u8],
    scheme: SignatureScheme,
    sig: &[u8],
) -> VerifyResult<()> {
    let cert = X509::from_der(cert_der).map_err(|e| format!("invalid certificate: {e}"))?;
    let pkey = cert
        .public_key()
        .map_err(|e| format!("certificate has no public key: {e}"))?;

    let (digest, pss) = match scheme {
        SignatureScheme::RSA_PSS_SHA256 => (MessageDigest::sha256(), true),
        SignatureScheme::RSA_PSS_SHA384 => (MessageDigest::sha384(), true),
        SignatureScheme::RSA_PSS_SHA512 => (MessageDigest::sha512(), true),
        SignatureScheme::RSA_PKCS1_SHA256 => (MessageDigest::sha256(), false),
        SignatureScheme::RSA_PKCS1_SHA384 => (MessageDigest::sha384(), false),
        SignatureScheme::RSA_PKCS1_SHA512 => (MessageDigest::sha512(), false),
        other => return Err(format!("unsupported signature scheme {other:?}")),
    };

    let mut verifier = Verifier::new(digest, &pkey).map_err(|e| e.to_string())?;
    if pss {
        verifier
            .set_rsa_padding(Padding::PKCS1_PSS)
            .map_err(|e| e.to_string())?;
        verifier
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(|e| e.to_string())?;
    }
    match verifier.verify_oneshot(sig, message) {
        Ok(true) => Ok(()),
        Ok(false) => Err("TLS handshake signature is invalid".into()),
        Err(e) => Err(format!("TLS handshake signature check failed: {e}")),
    }
}
