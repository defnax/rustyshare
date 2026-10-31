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
    body.extend(meta.sign_flags.bits().to_be_bytes());

    let mut out = Vec::with_capacity(body.len() + 8);
    out.extend(META_VERSION.to_be_bytes());
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
    Ok(group)
}
