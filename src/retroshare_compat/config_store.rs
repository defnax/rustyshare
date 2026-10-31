use byteorder::{ByteOrder, NetworkEndian};
use log::warn;
use openssl::{
    envelope,
    pkey::{self, PKey},
    symm::Cipher,
};
use std::{fs::File, io::Read, path};

use super::ssl_key::SslKey;

pub fn decrypt_file(file: &path::Path, keys: SslKey) -> Result<Vec<u8>, std::io::Error> {
    let read_u32 = |data: &Vec<u8>, offset: &mut usize| -> u32 {
        const SIZE: usize = 4;
        let r = NetworkEndian::read_u32(&data[*offset..*offset + SIZE]);
        *offset += SIZE;
        r
    };

    let cipher = Cipher::aes_128_cbc();

    let mut enc_file = match File::open(&file) {
        Ok(file) => file,
        Err(why) => {
            warn!("couldn't open {}: {why}", file.display());
            return Err(why);
        }
    };
    let mut data_enc = Vec::new();
    let size = match enc_file.read_to_end(&mut data_enc) {
        Ok(s) => s,
        Err(why) => {
            warn!("failed to load ssl_{}: {why}", file.display());
            return Err(why);
        }
    };
    let data_enc = data_enc;

    let mut offset: usize = 0;
    // read encryption key size
    let size_et = read_u32(&data_enc, &mut offset) as usize;
    // read key
    let encrypted_key = &data_enc[offset..offset + size_et];
    offset += size_et;
    // read IV
    let iv = &data_enc[offset..offset + 16];
    offset += 16;
    // dbg!(size, offset);

    // start decryption
    let key: PKey<pkey::Private> = keys.into();
    let mut env = envelope::Open::new(cipher, &key, Some(iv), encrypted_key).unwrap();
    // we meed at least space for "size" many bytes
    let mut data_dec = vec![];
    data_dec.resize(size, 0);
    let size_dec = match env.update(&data_enc[offset..], &mut data_dec) {
        Ok(s) => s,
        Err(why) => {
            warn!("failed to decrypt ssl_{}: {}", file.display(), why);
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }
    };
    // now shrink to actually read bytes.
    data_dec.resize(size_dec, 0);

    // finish him
    let mut data_dec_remaining = vec![];
    data_dec_remaining.resize(cipher.block_size(), 0);
    let size_dec_remaining = env.finalize(&mut data_dec_remaining).unwrap();

    data_dec.append(&mut data_dec_remaining);
    let size_dec = size_dec + size_dec_remaining;

    // now shrink to actually read bytes again.
    data_dec.resize(size_dec, 0);
    // println!("{:?}", data_dec);
    assert_eq!(&size_dec, &data_dec.len());

    return Ok(data_dec);
}

/// Encrypts `data` with our own SSL public key, in the format libretroshare's
/// `AuthSSL::encrypt()` writes (and `decrypt_file()` reads):
/// `[u32 BE key length][encrypted key][16 byte IV][AES-128-CBC data]`
pub fn encrypt_data(data: &[u8], keys: &SslKey) -> Result<Vec<u8>, std::io::Error> {
    let to_io = |e: openssl::error::ErrorStack| std::io::Error::new(std::io::ErrorKind::Other, e);

    let cert: openssl::x509::X509 = keys.to_owned().into();
    let public = cert.public_key().map_err(to_io)?;
    let cipher = Cipher::aes_128_cbc();

    let mut seal = envelope::Seal::new(cipher, &[public]).map_err(to_io)?;
    let encrypted_key = seal.encrypted_keys()[0].to_owned();
    let iv = seal.iv().expect("AES-CBC has an IV").to_owned();

    let mut encrypted = vec![0u8; data.len() + cipher.block_size()];
    let mut len = seal.update(data, &mut encrypted).map_err(to_io)?;
    len += seal.finalize(&mut encrypted[len..]).map_err(to_io)?;
    encrypted.truncate(len);

    let mut out = Vec::with_capacity(4 + encrypted_key.len() + iv.len() + encrypted.len());
    let mut size = [0u8; 4];
    NetworkEndian::write_u32(&mut size, encrypted_key.len() as u32);
    out.extend_from_slice(&size);
    out.extend_from_slice(&encrypted_key);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&encrypted);
    Ok(out)
}

/// Signature file content, like libretroshare's `p3Config::saveConfig()`:
/// hex(RSA-SHA1 signature over SHA1(encrypted file)).
pub fn sign_data(encrypted: &[u8], keys: &SslKey) -> Result<String, std::io::Error> {
    let to_io = |e: openssl::error::ErrorStack| std::io::Error::new(std::io::ErrorKind::Other, e);

    let key: PKey<pkey::Private> = keys.to_owned().into();
    let hash = openssl::sha::sha1(encrypted);
    let mut signer =
        openssl::sign::Signer::new(openssl::hash::MessageDigest::sha1(), &key).map_err(to_io)?;
    signer.update(&hash).map_err(to_io)?;
    Ok(hex::encode(signer.sign_to_vec().map_err(to_io)?))
}

/// Verifies a config file against its `.sgn` file.
pub fn verify_file(file: &path::Path, keys: &SslKey) -> bool {
    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let mut sgn = file.as_os_str().to_owned();
    sgn.push(".sgn");
    let sig = match std::fs::read_to_string(&sgn)
        .ok()
        .and_then(|s| hex::decode(s.trim()).ok())
    {
        Some(s) => s,
        None => return false,
    };
    let cert: openssl::x509::X509 = keys.to_owned().into();
    let public = match cert.public_key() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let hash = openssl::sha::sha1(&data);
    openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha1(), &public)
        .and_then(|mut v| v.verify_oneshot(&sig, &hash))
        .unwrap_or(false)
}

/// Saves a config file the way libretroshare does: encrypt + sign, write `<file>_new`
/// and `<file>.sgn_new`, move the current files to `.tmp` (backup), then rename.
pub fn save_file(file: &path::Path, plaintext: &[u8], keys: &SslKey) -> Result<(), std::io::Error> {
    let encrypted = encrypt_data(plaintext, keys)?;
    let signature = sign_data(&encrypted, keys)?;

    let with = |suffix: &str| {
        let mut p = file.as_os_str().to_owned();
        p.push(suffix);
        path::PathBuf::from(p)
    };
    let (cfg_new, sgn_new) = (with("_new"), with(".sgn_new"));
    let (cfg_tmp, sgn_tmp) = (with(".tmp"), with(".sgn.tmp"));
    let sgn = with(".sgn");

    std::fs::write(&cfg_new, &encrypted)?;
    std::fs::write(&sgn_new, signature.as_bytes())?;

    if file.exists() {
        std::fs::rename(file, &cfg_tmp)?;
    }
    if sgn.exists() {
        std::fs::rename(&sgn, &sgn_tmp)?;
    }
    std::fs::rename(&cfg_new, file)?;
    std::fs::rename(&sgn_new, &sgn)?;
    Ok(())
}

/// Loads a config file, checking its signature first and falling back to the `.tmp`
/// backup if the signature is wrong (like libretroshare).
pub fn load_file(file: &path::Path, keys: &SslKey) -> Result<Vec<u8>, std::io::Error> {
    if verify_file(file, keys) {
        return decrypt_file(file, keys.to_owned());
    }
    let mut tmp = file.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = path::PathBuf::from(tmp);
    if tmp.exists() && verify_file(&tmp, keys) {
        warn!(
            "signature of {} is invalid, using backup {}",
            file.display(),
            tmp.display()
        );
        return decrypt_file(&tmp, keys.to_owned());
    }
    warn!(
        "signature of {} could not be verified, loading it anyway",
        file.display()
    );
    decrypt_file(file, keys.to_owned())
}
