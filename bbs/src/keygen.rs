use crate::ciphersuite::*;
use hacspec_bls12_381::*;
use hacspec_lib::*;

use crate::utils::hash_to_scalar;

use crate::error::Error;

const KEYGEN_DST: &'static str = "KEYGEN_DST_";

/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-secret-key>
///
/// This operation generates a secret key (SK) deterministically from a
/// secret octet string (key_material).
///
/// Inputs:
/// - key_material (REQUIRED), a secret octet string. See requirements
///                            above.
/// - key_info (OPTIONAL), an octet string. Defaults to an empty string if
///                        not supplied.
/// - key_dst (OPTIONAL), an octet string representing the domain separation
///                       tag. Defaults to the octet string
///                       ciphersuite_id || "KEYGEN_DST_" if not supplied.
///
/// Outputs:
/// - SK, a uniformly random integer such that 0 < SK < r.
pub fn keygen(
    key_material: &ByteSeq,
    key_info: Option<&ByteSeq>,
    key_dst: Option<&ByteSeq>,
) -> Result<BBSSecretKey, Error> {
    let default_key_info = &ByteSeq::from_public_slice(b"");
    let default_key_dst = &ByteSeq::from_public_slice(KEYGEN_DST.as_bytes());

    let key_info = key_info.unwrap_or(default_key_info);
    let key_dst = key_dst.unwrap_or(default_key_dst);

    // 1. if length(key_material) < 32, return INVALID
    if key_material.len() < 32 {
        return Err(Error::InvalidKeyGen);
    }
    // 2. if length(key_info) > 65535, return INVALID
    if key_info.len() > 65535 {
        return Err(Error::InvalidKeyGen);
    }
    // 3. derive_input = key_material || I2OSP(length(key_info), 2) || key_info
    let mut i2osp_key_info_2 = ByteSeq::new(2);
    i2osp_key_info_2[0] = U8_from_usize(key_info.len() / 256);
    i2osp_key_info_2[1] = U8_from_usize(key_info.len());
    let derive_input = key_material.concat(&i2osp_key_info_2).concat(key_info);
    // 4. SK = hash_to_scalar(derive_input, key_dst)
    // 5. if SK is INVALID, return INVALID
    let sk = hash_to_scalar(&derive_input, &key_dst);
    println!("Secret Key: {:?}", sk.to_byte_seq_be().to_hex());
    // 6. return SK
    Ok(sk)
}

/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-public-key>
///
/// This operation takes a secret key (SK) and outputs a corresponding
/// public key (PK).
///
/// Inputs:
/// - SK (REQUIRED), a secret integer such that 0 < SK < r.
///
/// Outputs:
/// - PK, a public key encoded as an octet string.
pub fn sk_to_pk(sk: BBSSecretKey) -> Result<BBSPublicKey, Error> {
    // 1. W = SK * BP2
    let bp2 = base_g2();
    let w = g2mul(sk, bp2);
    // 2. return point_to_octets_E2(W)
    // TODO: Implement point_to_octets_E2
    Ok(w)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_keygen() {
        let key_material = ByteSeq::from_hex("746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579");
        let key_info = ByteSeq::from_hex("746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e");
        let key_dst =
            ByteSeq::from_hex("4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f4b455947454e5f4453545f");
        let sk = keygen(&key_material, Some(&key_info), Some(&key_dst)).unwrap();
        assert_eq!(
            sk.to_byte_seq_be().to_hex(),
            "60e55110f76883a13d030b2f6bd11883422d5abde71756a236761f51237469fc"
        );

        let pk = sk_to_pk(sk).unwrap();
        println!("{:?}", pk);
    }
}
