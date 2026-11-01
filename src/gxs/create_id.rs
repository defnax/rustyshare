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
    let _ = group_id;
    build_own_group(name, flags, SignFlags::empty(), admin, publish, group_data)
}

/// Creates a new forum like p3GxsForums::createForumV2() (public, no author):
/// group data = RsGxsForumGroupItem (description, empty admin list, no pinned posts).
pub fn create_forum(name: &str, description: &str) -> Res<GxsGroup> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Forum name is required".into());
    }
    let admin = generate_key_pair(TlvKeyFlags::DISTRIBUTE_ADMIN)?;
    let publish = generate_key_pair(TlvKeyFlags::DISTRIBUTE_PUBLISH)?;

    // RsGxsForumGroupItem: version 2, service 0x0215, sub type 0x02; description,
    // admin list (RsTlvGxsIdSet, empty), pinned posts (RsTlvGxsMsgIdSet, empty)
    let mut body = tlv(TLV_TYPE_STR_DESCR, description.as_bytes());
    body.extend(tlv(TLV_TYPE_GXSIDSET, &[]));
    body.extend(tlv(TLV_TYPE_GXSMSGIDSET, &[]));
    let mut group_data = vec![0x02, 0x02, 0x15, 0x02];
    group_data.extend(((body.len() + 8) as u32).to_be_bytes());
    group_data.extend(body);

    build_own_group(
        name,
        GroupFlags::PRIVACY_PUBLIC,
        SignFlags::GROUP_SIGN_PUBLISH_NONEREQ | SignFlags::AUTHOR_AUTHENTICATION_REQUIRED,
        admin,
        publish,
        group_data,
    )
}

/// Meta data, admin signature and keys for a group we create (RsGenExchange::
/// publishGrps / createGroup): group id = admin key id, meta version 0xaf01.
fn build_own_group(
    name: &str,
    flags: GroupFlags,
    sign_flags: SignFlags,
    admin: KeyPair,
    publish: KeyPair,
    group_data: Vec<u8>,
) -> Res<GxsGroup> {
    let group_id: GxsGroupId = admin.id.to_vec().into();
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
        sign_flags,
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

/// The received meta data with an empty signature set and an empty service string,
/// taken from the original bytes. That is what current RetroShare signs and checks:
/// `RsGxsGrpMetaData::serialise()` with `signSet` cleared, and since the security fix
/// of April 2026 (libretroshare d82c7b5) always with an empty service string. Groups
/// that older RetroShare versions signed together with their local service string
/// therefore fail here, exactly like in current RetroShare (their owner has to save
/// them again). Independent of how well rustyshare parses the meta data.
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
    let service_pos = pos;
    let service_type = u16_at(pos)?;
    pos = skip_tlv(pos)?; // service string
    let circle_pos = pos;
    pos += 16; // circle id
    let sig_pos = pos;
    let sig_type = u16_at(pos)?;
    let sig_end = skip_tlv(pos)?;
    if sig_end > meta.len() {
        return Err("meta data too short".into());
    }

    let mut out = meta[..service_pos].to_vec();
    out.extend((service_type as u16).to_be_bytes());
    out.extend(6u32.to_be_bytes()); // empty service string
    out.extend(&meta[circle_pos..sig_pos]); // circle id
    out.extend((sig_type as u16).to_be_bytes());
    out.extend(6u32.to_be_bytes()); // empty signature set
    out.extend(&meta[sig_end..]);
    let size = out.len() as u32;
    out[4..8].copy_from_slice(&size.to_be_bytes());
    Ok(out)
}

/// Why [`check_group_signature`] refused a group.
#[derive(Debug)]
pub enum GroupCheckError {
    /// the group is not correctly signed (or can't be checked): don't accept it
    Invalid(String),
}

impl std::fmt::Display for GroupCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GroupCheckError::Invalid(s) => write!(f, "invalid group: {s}"),
        }
    }
}

/// Checks the admin signature of a group (identity) like RetroShare does when it
/// receives one (GxsSecurity::validateNxsGrp: RSA-SHA1 over group data || meta
/// without signatures and service string).
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

    // like GxsSecurity::validateNxsGrp(): signature over the received meta data with
    // the signature set and the service string emptied
    let original = meta_without_signatures(&blobs.meta_data).map_err(Invalid)?;
    if verify(&original) {
        Ok(())
    } else {
        Err(Invalid("admin signature does not verify".into()))
    }
}

/// Offset of the signature set in `RsGxsMsgMetaData`: header (8), group id (16),
/// message, thread, parent and original message id (4 x 20), author id (16).
const MSG_META_SIGNSET_POS: usize = 8 + 16 + 4 * 20 + 16;

/// Checks the author signature of a message (e.g. a forum post) like
/// `GxsSecurity::validateNxsMsg()`: RSA-SHA1 by the author identity's key over
/// (message data || meta data with an empty signature set).
/// `Ok(false)` = signature wrong, `Err` = can't be checked (e.g. no author signature).
pub fn verify_msg_author_signature(
    meta: &[u8],
    data: &[u8],
    author_key: &TlvPublicRSAKey,
) -> Res<bool> {
    use openssl::sign::Verifier;
    use retroshare_compat::serde::from_retroshare_wire_result;

    let pos = MSG_META_SIGNSET_POS;
    let header = meta.get(pos..pos + 6).ok_or("meta data too short")?;
    let sig_type = [header[0], header[1]];
    let sig_len = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
    if sig_len < 6 || pos + sig_len > meta.len() {
        return Err("broken signature set".into());
    }

    let set: TlvKeySignatureSet = from_retroshare_wire_result(&mut meta[pos..pos + sig_len].to_vec())
        .map_err(|e| format!("can't read signature set: {e:?}"))?;
    let sig = set
        .0
        .iter()
        .find(|(k, _)| k.0 == KeySignType::IndexAuthenIdentity)
        .map(|(_, v)| v.sign_data.to_vec())
        .ok_or("message has no author signature")?;

    // like validateNxsMsg(): the signature is made before the message id exists, so the
    // message id is cleared, and so is the original message id when it equals the
    // message id (not an edited post)
    let mut unsigned = meta[..pos].to_vec();
    const MSG_ID: std::ops::Range<usize> = 24..44;
    const ORIG_MSG_ID: std::ops::Range<usize> = 84..104;
    if unsigned[ORIG_MSG_ID] == unsigned[MSG_ID] {
        unsigned[ORIG_MSG_ID].fill(0);
    }
    unsigned[MSG_ID].fill(0);
    unsigned.extend(sig_type);
    unsigned.extend(6u32.to_be_bytes());
    unsigned.extend(&meta[pos + sig_len..]);
    let size = unsigned.len() as u32;
    unsigned[4..8].copy_from_slice(&size.to_be_bytes());

    let rsa = Rsa::public_key_from_der_pkcs1(author_key.key_data.as_slice()).map_err(|e| e.to_string())?;
    let pkey = PKey::from_rsa(rsa).map_err(|e| e.to_string())?;
    let mut signed = data.to_vec();
    signed.extend(&unsigned);
    let mut v = Verifier::new(MessageDigest::sha1(), &pkey).map_err(|e| e.to_string())?;
    Ok(v.verify_oneshot(&sig, &signed).unwrap_or(false))
}

/// A new message (e.g. a forum post), built and signed like RsGenExchange::publishMsgs()
/// / createMessage(): returns (message id, service data, meta data).
///
/// - `service_item_header`: the RsItem header of the service's message item, e.g.
///   `[0x02, 0x02, 0x15, 0x03]` for RsGxsForumMsgItem; the body is the text as a
///   TLV_TYPE_STR_MSG string
/// - signed by the author identity (MSG_AUTHEN_*_AUTHOR_SIGN, enough for public forums)
/// - message id = SHA1(data || meta with empty signatures and message id), computed
///   before signing; the original message id is set to the message id afterwards
pub fn create_message(
    service_item_header: [u8; 4],
    group_id: &GxsGroupId,
    thread_id: &[u8; 20],
    parent_id: &[u8; 20],
    author_id: &GxsId,
    author_key: &TlvPrivateRSAKey,
    title: &str,
    text: &str,
) -> Res<([u8; 20], Vec<u8>, Vec<u8>)> {
    // service data: RsItem header + TLV string
    let body = tlv(TLV_TYPE_STR_MSG, text.as_bytes());
    let mut data = service_item_header.to_vec();
    data.extend(((body.len() + 8) as u32).to_be_bytes());
    data.extend(body);

    let publish_ts = now();
    let meta_with = |msg_id: &[u8; 20], orig_id: &[u8; 20], sign_set: &TlvKeySignatureSet| -> Vec<u8> {
        let mut b = vec![];
        b.extend(to_retroshare_wire(group_id));
        b.extend(msg_id);
        b.extend(thread_id);
        b.extend(parent_id);
        b.extend(orig_id);
        b.extend(to_retroshare_wire(author_id));
        b.extend(to_retroshare_wire(sign_set));
        b.extend(to_retroshare_wire(&StringTagged::<0>::from(title)));
        b.extend(publish_ts.to_be_bytes());
        b.extend(0u32.to_be_bytes()); // msg flags
        // RS_GXS_MSG_META_DATA_VERSION_ID_0002 = 0x0000
        let mut out = 0u32.to_be_bytes().to_vec();
        out.extend(((b.len() + 8) as u32).to_be_bytes());
        out.extend(b);
        out
    };

    let zero = [0u8; 20];
    let unsigned = meta_with(&zero, &zero, &TlvKeySignatureSet::default());
    let mut all = data.clone();
    all.extend(&unsigned);
    let msg_id: [u8; 20] = openssl::sha::sha1(&all);

    let rsa = Rsa::private_key_from_der(author_key.key_data.as_slice()).map_err(|e| e.to_string())?;
    let signature = rsa_sha1_sign(&rsa, &all)?;
    let sign_set: TlvKeySignatureSet = TlvMap(HashMap::from([(
        Tlv(KeySignType::IndexAuthenIdentity),
        Tlv(TlvKeySignatureInner {
            key_id: KeyId::from(*author_id),
            sign_data: signature.into(),
        }),
    )]));
    let meta = meta_with(&msg_id, &msg_id, &sign_set);
    Ok((msg_id, data, meta))
}
