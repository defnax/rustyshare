//! Creating own GXS identities, like libretroshare's `p3IdService::createIdentity()`
//! + `RsGenExchange::publishGrps()` / `createGroup()`:
//!
//! - two RSA-2048 key pairs (admin + publish), key id = first 16 bytes of
//!   SHA1(modulus || exponent), group id = admin key id
//! - group data = serialised `RsGxsIdGroupItem` (PGP hash + PGP signature for signed
//!   identities, empty recognition tags, empty image)
//! - group meta = `RsGxsGrpMetaData` (api version 0xaf01) with only the public keys
//! - admin signature = RSA-SHA1 over (group data || meta without signatures)
//!
//! Keys inside the meta are written sorted by key id, because RetroShare re-serialises
//! the meta from a sorted map when it checks the signature.

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use openpgp::{
    crypto::Password, packet::signature::SignatureBuilder, serialize::SerializeInto,
    types::{HashAlgorithm, SignatureType},
    Cert,
};
use openssl::{hash::MessageDigest, pkey::PKey, rsa::Rsa, sign::Signer};
use retroshare_compat::{
    basics::{GxsCircleId, GxsGroupId, GxsId},
    gxs::sqlite::types::{
        AuthenFlags, GroupFlags, GxsCircleType, GxsGroup, GxsGrpDataSql, GxsGrpMetaSql,
        SignFlags, SubscribeFlags,
    },
    serde::to_retroshare_wire,
    tlv::{
        tags::*,
        tlv_keys::{
            KeyId, KeySignType, TlvKeyFlags, TlvKeySignatureInner, TlvKeySignatureSet,
            TlvPrivateRSAKey, TlvPublicRSAKey, TlvRSAKeyInner, TlvSecurityKeySet,
        },
        tlv_map::TlvMap,
        tlv_string::StringTagged,
        Tlv,
    },
};
use sequoia_openpgp as openpgp;

/// libretroshare: `RS_GXS_GRP_META_DATA_VERSION_ID_0002`
const META_VERSION: u32 = 0xaf01;
/// RsItem header of a `RsGxsIdGroupItem`: version 2, service 0x0211, subtype 0x02
const ID_GROUP_ITEM_HEADER: [u8; 4] = [0x02, 0x02, 0x11, 0x02];
const KEY_VALIDITY: u32 = 60 * 60 * 24 * 365 * 5; // ~5 years, like RetroShare

type Res<T> = Result<T, String>;

fn now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

fn tlv(tag: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 6);
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&((body.len() + 6) as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

struct KeyPair {
    id: GxsId,
    public: TlvPublicRSAKey,
    private: TlvPrivateRSAKey,
    rsa: Rsa<openssl::pkey::Private>,
}

/// Like `GxsSecurity::generateKeyPair()`.
fn generate_key_pair(distribution: TlvKeyFlags) -> Res<KeyPair> {
    let rsa = Rsa::generate(2048).map_err(|e| e.to_string())?;

    // key id: first 16 bytes of SHA1(n || e)
    let mut ne = rsa.n().to_vec();
    ne.extend(rsa.e().to_vec());
    let id: GxsId = openssl::sha::sha1(&ne)[..16].to_vec().into();

    let ts = now();
    let public = TlvRSAKeyInner {
        key_id: KeyId::from(id),
        key_flags: TlvKeyFlags::TYPE_PUBLIC_ONLY | distribution,
        start_ts: ts,
        end_ts: ts + KEY_VALIDITY,
        key_data: rsa.public_key_to_der_pkcs1().map_err(|e| e.to_string())?.into(),
    };
    let private = TlvRSAKeyInner {
        key_id: KeyId::from(id),
        key_flags: TlvKeyFlags::TYPE_FULL | distribution,
        start_ts: ts,
        end_ts: 0,
        key_data: rsa.private_key_to_der().map_err(|e| e.to_string())?.into(),
    };

    Ok(KeyPair {
        id,
        public: Tlv::<TLV_TYPE_SECURITY_KEY, _>(public).into(),
        private: Tlv::<TLV_TYPE_SECURITY_KEY, _>(private).into(),
        rsa,
    })
}

/// `RsTlvSecurityKeySet` with public keys only, sorted by key id.
fn public_keyset_bytes(keys: &[&TlvPublicRSAKey]) -> Vec<u8> {
    let mut sorted: Vec<_> = keys.to_vec();
    sorted.sort_by_key(|k| {
        let id: &GxsId = &k.key_id;
        id.0
    });

    let mut body = to_retroshare_wire(&StringTagged::<TLV_TYPE_STR_GROUPID>::from(""));
    for key in sorted {
        body.extend(to_retroshare_wire(key));
    }
    tlv(TLV_TYPE_SECURITYKEYSET, &body)
}

/// `RsGxsGrpMetaData::serialise()` for api version 0xaf01.
fn meta_bytes(
    meta: &GxsGrpMetaSql,
    sign_set: &TlvKeySignatureSet,
    public_keys: &[&TlvPublicRSAKey],
) -> Vec<u8> {
    meta_bytes_version(meta, sign_set, public_keys, META_VERSION)
}

/// `RsGxsGrpMetaData::serialise()`; version 0x0000 has no sign flags at the end.
fn meta_bytes_version(
    meta: &GxsGrpMetaSql,
    sign_set: &TlvKeySignatureSet,
    public_keys: &[&TlvPublicRSAKey],
    version: u32,
) -> Vec<u8> {
    let mut body = vec![];
    body.extend(to_retroshare_wire(&meta.group_id));
    body.extend(to_retroshare_wire(&meta.orig_grp_id));
    body.extend(to_retroshare_wire(&meta.parent_grp_id));
    body.extend(to_retroshare_wire(&StringTagged::<0>::from(meta.group_name.as_str())));
    body.extend(meta.group_flags.bits().to_be_bytes());
    body.extend((meta.publish_ts as u32).to_be_bytes());
    body.extend((meta.circle_type.to_owned() as u32).to_be_bytes());
    body.extend(meta.authen_flags.bits().to_be_bytes());
    body.extend(to_retroshare_wire(&meta.author_id));
    body.extend(to_retroshare_wire(&StringTagged::<0>::from(""))); // service string, always empty
    body.extend(to_retroshare_wire(&meta.circle_id));
    body.extend(to_retroshare_wire(sign_set));
    body.extend(public_keyset_bytes(public_keys));
    if version == META_VERSION {
        body.extend(meta.sign_flags.bits().to_be_bytes());
    }

    let mut out = Vec::with_capacity(body.len() + 8);
    out.extend(version.to_be_bytes());
    out.extend(((body.len() + 8) as u32).to_be_bytes());
    out.extend(body);
    out
}

/// Serialised `RsGxsIdGroupItem` (incl. its RsItem header).
fn id_group_item(pgp_hash: &[u8; 20], pgp_sign: &[u8]) -> Vec<u8> {
    let mut body = vec![];
    body.extend_from_slice(pgp_hash);
    body.extend(tlv(TLV_TYPE_STR_SIGN, pgp_sign));
    body.extend(tlv(TLV_TYPE_RECOGNSET, &[])); // no recognition tags
    // empty image: type 0 + empty binary data
    let mut image = 0u32.to_be_bytes().to_vec();
    image.extend(tlv(TLV_TYPE_BIN_IMAGE, &[]));
    body.extend(tlv(TLV_TYPE_IMAGE, &image));

    let mut out = ID_GROUP_ITEM_HEADER.to_vec();
    out.extend(((body.len() + 8) as u32).to_be_bytes());
    out.extend(body);
    out
}

fn rsa_sha1_sign(rsa: &Rsa<openssl::pkey::Private>, data: &[u8]) -> Res<Vec<u8>> {
    let pkey = PKey::from_rsa(rsa.to_owned()).map_err(|e| e.to_string())?;
    let mut signer = Signer::new(MessageDigest::sha1(), &pkey).map_err(|e| e.to_string())?;
    signer.update(data).map_err(|e| e.to_string())?;
    signer.sign_to_vec().map_err(|e| e.to_string())
}

/// Creates a new own identity. `pgp` = (own secret PGP key, PGP password) for an identity
/// signed by (linked to) the profile, `None` for an anonymous (pseudonymous) one.
pub fn create_identity(name: &str, pgp: Option<(&Cert, &str)>) -> Res<GxsGroup> {
    let name = name.trim();
    if name.is_empty() {
        return Err("the identity needs a name".into());
    }

    let admin = generate_key_pair(TlvKeyFlags::DISTRIBUTE_ADMIN)?;
    let publish = generate_key_pair(TlvKeyFlags::DISTRIBUTE_PUBLISH)?;
    let group_id: GxsGroupId = admin.id.to_vec().into();

    // PGP link, like p3IdService::service_CreateGroup()
    let (flags, pgp_hash, pgp_sign) = match pgp {
        Some((cert, password)) => {
            // hash = SHA1(gxs id as lower case hex string || PGP fingerprint)
            let mut data = hex::encode(admin.id.0).into_bytes();
            data.extend(cert.fingerprint().as_bytes());
            let hash = openssl::sha::sha1(&data);

            let mut signer = cert
                .primary_key()
                .key()
                .clone()
                .parts_into_secret()
                .map_err(|_| "no secret PGP key for this profile")?
                .decrypt_secret(&Password::from(password))
                .map_err(|_| "wrong profile password")?
                .into_keypair()
                .map_err(|e| e.to_string())?;
            let sig = SignatureBuilder::new(SignatureType::Binary)
                .set_hash_algo(HashAlgorithm::SHA256)
                .sign_message(&mut signer, &hash)
                .map_err(|e| e.to_string())?;
            let sig = openpgp::Packet::from(sig)
                .to_vec()
                .map_err(|e| e.to_string())?;

            (
                GroupFlags::PRIVACY_PRIVATE | GroupFlags::REALID,
                hash,
                sig,
            )
        }
        None => (GroupFlags::PRIVACY_PUBLIC, [0u8; 20], vec![]),
    };

    let group_data = id_group_item(&pgp_hash, &pgp_sign);
    let ts = now() as i64;

    let mut meta = GxsGrpMetaSql {
        group_id,
        group_name: name.to_owned(),
        group_flags: flags,
        publish_ts: ts,
        recv_ts: ts,
        circle_type: GxsCircleType::Public,
        circle_id: GxsCircleId::default(),
        author_id: GxsId::default(),
        authen_flags: AuthenFlags::empty(),
        sign_flags: SignFlags::empty(),
        subscribe_flags: SubscribeFlags::ADMIN | SubscribeFlags::SUBSCRIBED | SubscribeFlags::PUBLISH,
        hash: openssl::sha::sha1(&group_data).to_vec().into(),
        ..Default::default()
    };

    // admin signature over group data + meta (without signatures, public keys only)
    let public_keys = [&admin.public, &publish.public];
    let unsigned_meta = meta_bytes(&meta, &TlvKeySignatureSet::default(), &public_keys);
    let mut to_sign = group_data.clone();
    to_sign.extend(&unsigned_meta);
    let signature = rsa_sha1_sign(&admin.rsa, &to_sign)?;

    let sign_set: TlvKeySignatureSet = TlvMap(HashMap::from([(
        Tlv(KeySignType::IndexAuthenAdmin),
        Tlv(TlvKeySignatureInner {
            key_id: KeyId::from(admin.id),
            sign_data: signature.into(),
        }),
    )]));
    let meta_blob = meta_bytes(&meta, &sign_set, &public_keys);

    // the database keeps the private keys too (the meta blob doesn't)
    let mut keys = TlvSecurityKeySet::default();
    keys.public_keys.insert(admin.public.clone());
    keys.public_keys.insert(publish.public.clone());
    keys.private_keys.insert(admin.private.clone());
    keys.private_keys.insert(publish.private.clone());
    meta.keys = keys;
    meta.sign_set = sign_set;

    let mut group: GxsGroup = meta.into();
    group.set_blobs(GxsGrpDataSql {
        group_id,
        nxs_data_len: group_data.len(),
        nxs_data: group_data,
        meta_data: meta_blob,
    });

    // sanity check: our own group must pass the same check RetroShare does
    check_group_signature(&group).map_err(|e| format!("self check failed: {e}"))?;
    Ok(group)
}

/// The received meta data with an empty signature set, taken from the original bytes
/// (what RetroShare signs: `RsGxsGrpMetaData::serialise()` with `signSet` cleared).
/// Independent of how well rustyshare parses the meta data.
fn meta_without_signatures(meta: &[u8]) -> Res<Vec<u8>> {
    let u16_at = |pos: usize| -> Res<usize> {
        meta.get(pos..pos + 2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
            .ok_or_else(|| "meta data too short".to_string())
    };
    let u32_at = |pos: usize| -> Res<usize> {
        meta.get(pos..pos + 4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
            .ok_or_else(|| "meta data too short".to_string())
    };
    // TLV: u16 type, u32 length incl. the 6 header bytes
    let skip_tlv = |pos: usize| -> Res<usize> {
        let len = u32_at(pos + 2)?;
        if len < 6 {
            return Err("broken TLV in meta data".into());
        }
        Ok(pos + len)
    };

    let mut pos = 8; // version + size
    pos += 16 * 3; // group id, original group id, parent group id
    pos = skip_tlv(pos)?; // group name
    pos += 4 * 4; // group flags, publish ts, circle type, authen flags
    pos += 16; // author id
    pos = skip_tlv(pos)?; // service string
    pos += 16; // circle id
    let sig_type = u16_at(pos)?;
    let sig_end = skip_tlv(pos)?;
    if sig_end > meta.len() {
        return Err("meta data too short".into());
    }

    let mut out = meta[..pos].to_vec();
    out.extend((sig_type as u16).to_be_bytes());
    out.extend(6u32.to_be_bytes()); // empty set
    out.extend(&meta[sig_end..]);
    let size = out.len() as u32;
    out[4..8].copy_from_slice(&size.to_be_bytes());
    Ok(out)
}

/// Result of [`check_group_signature`] when it is not a full match.
#[derive(Debug)]
pub enum GroupCheckError {
    /// the group is not correctly signed (or can't be checked): don't accept it
    Invalid(String),
    /// the group is fine, only rustyshare's own serialisation of it differs
    FormatDiffers(String),
}

impl std::fmt::Display for GroupCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GroupCheckError::Invalid(s) => write!(f, "invalid group: {s}"),
            GroupCheckError::FormatDiffers(s) => write!(f, "signature valid, but {s}"),
        }
    }
}

/// Checks the admin signature of a group (identity) like RetroShare does when it
/// receives one (GxsSecurity::validateNxsGrp: RSA-SHA1 over group data || meta
/// without signatures), then tells whether rustyshare's own meta serialisation (used for the
/// identities it creates) produces the same bytes.
pub fn check_group_signature(group: &GxsGroup) -> Result<(), GroupCheckError> {
    check_group_signature_inner(group)
}

fn check_group_signature_inner(group: &GxsGroup) -> Result<(), GroupCheckError> {
    use GroupCheckError::Invalid;
    use openssl::sign::Verifier;
    use retroshare_compat::gxs::sqlite::types::GxsGrpMetaSql as Meta;

    let blobs = group.get_blobs();
    let meta = Meta::from_nxs(&mut blobs.meta_data.to_owned());

    let admin_sig = meta
        .sign_set
        .0
        .iter()
        .find(|(k, _)| k.0 == KeySignType::IndexAuthenAdmin)
        .map(|(_, v)| v.to_owned())
        .ok_or_else(|| Invalid("group has no admin signature".into()))?;
    let public_keys: Vec<&TlvPublicRSAKey> = meta.keys.public_keys.iter().collect();
    let admin_key = public_keys
        .iter()
        .find(|k| k.key_flags.contains(TlvKeyFlags::DISTRIBUTE_ADMIN))
        .ok_or_else(|| Invalid("group has no public admin key".into()))?;

    let rsa = Rsa::public_key_from_der_pkcs1(admin_key.key_data.as_slice())
        .map_err(|e| Invalid(e.to_string()))?;
    let pkey = PKey::from_rsa(rsa).map_err(|e| Invalid(e.to_string()))?;
    let verify = |unsigned: &[u8]| -> bool {
        let mut data = blobs.nxs_data.clone();
        data.extend(unsigned);
        Verifier::new(MessageDigest::sha1(), &pkey)
            .and_then(|mut v| v.verify_oneshot(admin_sig.sign_data.as_slice(), &data))
            .unwrap_or(false)
    };

    // 1. the signature itself, over the original bytes
    let original = meta_without_signatures(&blobs.meta_data).map_err(Invalid)?;
    let valid = verify(&original);

    // 2. does our serialisation give the same bytes?
    for version in [META_VERSION, 0x0000] {
        let ours = meta_bytes_version(&meta, &TlvKeySignatureSet::default(), &public_keys, version);
        if ours == original || verify(&ours) {
            return Ok(());
        }
    }

    let ours = meta_bytes_version(&meta, &TlvKeySignatureSet::default(), &public_keys, META_VERSION);
    let diff = original
        .iter()
        .zip(ours.iter())
        .position(|(a, b)| a != b)
        .unwrap_or(original.len().min(ours.len()));
    let detail = format!(
        "rustyshare's serialisation differs at byte {diff} (lengths {} / {}); RS meta version {:#06x}",
        original.len(),
        ours.len(),
        u32::from_be_bytes(original[0..4].try_into().unwrap_or_default()),
    );
    if valid {
        // the identity is fine, only our re-serialisation is off
        Err(GroupCheckError::FormatDiffers(detail))
    } else {
        Err(Invalid(format!("admin signature does not verify ({detail})")))
    }
}
