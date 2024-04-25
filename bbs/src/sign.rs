use crate::{
    ciphersuite::*,
    error::Error,
    utils::{calculate_domain, create_generators, hash_to_scalar, message_to_scalar},
};
use hacspec_bls12_381::*;
use hacspec_lib::*;

const CIPHERSUITE_ID: &'static str = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";

/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-signature-generation-sign>
///
/// Inputs:
/// - SK (REQUIRED), a secret key in the form outputted by the KeyGen
///                  operation.
/// - PK (REQUIRED), an octet string of the form outputted by SkToPk
///                  provided the above SK as input.
/// - header (OPTIONAL), an octet string containing context and application
///                      specific information. If not supplied, it defaults
///                      to the empty octet string ("").
/// - messages (OPTIONAL), a vector of octet strings. If not supplied, it
///                        defaults to the empty array ("()").
///
/// Parameters:
/// - api_id, the octet string ciphersuite_id || "H2G_HM2S_", where
///           ciphersuite_id is defined by the ciphersuite and "H2G_HM2S_"is
///           an ASCII string comprised of 9 bytes.
///
/// Outputs:
/// - signature, a signature encoded as an octet string; or INVALID.
pub fn sign(
    sk: &BBSSecretKey,
    pk: &BBSPublicKey,
    header: Option<&ByteSeq>,
    messages: Option<&Seq<ByteSeq>>,
) -> Result<BBSSignature, Error> {
    let default_header = &ByteSeq::from_public_slice(b"");
    let default_messages = &Seq::new(0);
    let api_id = &ByteSeq::from_public_slice(CIPHERSUITE_ID.as_bytes())
        .concat(&ByteSeq::from_public_slice(b"H2G_HM2S_"));
    let messages = messages.unwrap_or(default_messages);
    let header = header.unwrap_or(default_header);

    // 1. message_scalars = messages_to_scalars(messages, api_id)
    let message_scalars = message_to_scalar(messages, Some(api_id));
    // 2. generators = create_generators(length(messages)+1, api_id)
    let generators = create_generators(messages.len() + 1, Some(api_id));
    // 3. signature = CoreSign(SK, PK, header, message_scalars, generators, api_id)
    let signature = core_sign(
        sk,
        pk,
        &generators,
        Some(header),
        Some(&message_scalars),
        Some(api_id),
    );
    // 4. if signature is INVALID, return INVALID
    match signature {
        // 5. return signature
        Ok(signature) => Ok(signature),
        Err(_) => {
            return Err(Error::InvalidCoreSign);
        }
    }
}

/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-signature-verification-veri>
///
/// The Verify operation validates a BBS signature, given a public key
/// (PK), a header and a set of messages.
///
/// Inputs:
/// - PK (REQUIRED), an octet string of the form outputted by the SkToPk
/// operation.
/// - signature (REQUIRED), an octet string of the form outputted by the
///        Sign operation.
/// - header (OPTIONAL), an octet string containing context and application
///     specific information. If not supplied, it defaults
///     to the empty octet string ("").
/// - messages (OPTIONAL), a vector of octet strings. If not supplied, it
///       defaults to the empty array ("()").
///
/// Parameters:
/// - api_id, the octet string ciphersuite_id || "H2G_HM2S_", where
/// ciphersuite_id is defined by the ciphersuite and "H2G_HM2S_"is
/// an ASCII string comprised of 9 bytes.
///
/// Outputs:
/// - result, either VALID or INVALID.
pub fn verify(
    pk: &BBSPublicKey,
    signature: &BBSSignature,
    header: Option<&ByteSeq>,
    messages: Option<&Seq<ByteSeq>>,
) -> Result<bool, Error> {
    let default_header = &ByteSeq::from_public_slice(b"");
    let default_messages = &Seq::new(0);
    let api_id = &ByteSeq::from_public_slice(CIPHERSUITE_ID.as_bytes())
        .concat(&ByteSeq::from_public_slice(b"H2G_HM2S_"));
    let messages = messages.unwrap_or(default_messages);
    let header = header.unwrap_or(default_header);
    // let mut map_dst = ByteSeq::new(api_id.len() + 26);

    // 1. message_scalars = messages_to_scalars(messages, api_id)
    let message_scalars = message_to_scalar(messages, Some(api_id));
    // 2. generators = create_generators(length(messages)+1, api_id)
    let generators = create_generators(messages.len() + 1, Some(api_id));
    // 3. result = CoreVerify(PK, signature, generators, header, message_scalars, api_id)
    let result = core_verify(
        pk,
        signature,
        &generators,
        Some(header),
        Some(&message_scalars),
        Some(api_id),
    );
    // 4. return result
    match result {
        Ok(result) => Ok(result),
        Err(_) => {
            return Err(Error::InvalidCoreVerify);
        }
    }
}

// fn egcd(a: Scalar, b: Scalar) -> (Scalar, Scalar, Scalar) {
//     if b == Scalar::ZERO() {
//         (a, Scalar::ONE(), Scalar::ZERO())
//     } else {
//         let (g, x, y) = egcd(b, a % b);
//         (g, y, x - (a / b) * y)
//     }
// }

// fn modinv(a: Scalar, m: Scalar) -> Scalar {
//     let (g, x, _) = egcd(a, m);
//     if g != Scalar::ONE() {
//         panic!("Inverse does not exist");
//     }
//     x % m
// }
/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-coresign>
///
/// This operation computes a deterministic signature from a secret key
/// (SK), a set of generators (points of G1) and optionally a header and
/// a vector of messages.
/// Inputs:
/// - SK (REQUIRED), a secret key in the form outputted by the KeyGen
///                  operation.
/// - PK (REQUIRED), an octet string of the form outputted by SkToPk
///                  provided the above SK as input.
/// - generators (REQUIRED), vector of pseudo-random points in G1.
/// - header (OPTIONAL), an octet string containing context and application
///                      specific information. If not supplied, it defaults
///                      to the empty octet string ("").
/// - messages (OPTIONAL), a vector of scalars representing the messages.
///                        If not supplied, it defaults to the empty
///                        array ("()").
/// - api_id (OPTIONAL), an octet string. If not supplied it defaults to the
///                      empty octet string ("").
///
/// Parameters:
/// - P1, fixed point of G1, defined by the ciphersuite.
///
/// Outputs:
/// - signature, a vector comprised of a point of G1 and a scalar.
///
/// Definitions:
/// 1. signature_dst, an octet string representing the domain separation
///                   tag: api_id || "H2S_" where "H2S_" is an ASCII string
///                   comprised of 4 bytes.
pub fn core_sign(
    sk: &BBSSecretKey,
    pk: &BBSPublicKey,
    generators: &Seq<G1>,
    header: Option<&ByteSeq>,
    messages: Option<&Seq<Scalar>>,
    api_id: Option<&ByteSeq>,
) -> Result<BBSSignature, Error> {
    let default_header = &ByteSeq::from_public_slice(b"");
    let default_api_id = &ByteSeq::from_public_slice(b"");
    let default_messages = &Seq::new(0);
    let header = header.unwrap_or(default_header);
    let api_id = api_id.unwrap_or(default_api_id);
    let messages = messages.unwrap_or(default_messages);

    let p1 = base_g1();

    let signature_dst = api_id.concat(&ByteSeq::from_public_slice(b"H2S_"));

    // L = length(messages)
    let l = messages.len();
    // if length(generators) != L + 1, return INVALID
    if generators.len() != l + 1 {
        return Err(Error::InvalidCoreSign);
    }
    // (Q_1, H_1, ..., H_L) = generators
    let q1 = generators[0];
    let h_points = &generators.slice(1, l);

    // 1. domain = calculate_domain(PK, generators, header, api_id)
    let domain = calculate_domain(pk, &q1, &h_points, Some(header), Some(api_id));
    // 2. e = hash_to_scalar(serialize((SK, domain, msg_1, ..., msg_L)), signature_dst)
    // TODO: serialize((SK, domain, msg_1, ..., msg_L))
    let e = hash_to_scalar(&Seq::from_hex("1234567890abcdef"), &signature_dst);
    // 3. B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let mut b = g1add(p1, g1mul(domain, q1));
    for i in 0..l {
        b = g1add(b, g1mul(messages[i], h_points[i]));
    }
    // 4. A = B * (1 / (SK + e))
    let a = g1mul((*sk + e).inv(), b);
    // 5. return signature_to_octets((A, e))
    Ok((a, e))
}

/// Inputs:
/// - PK (REQUIRED), an octet string of the form outputted by the SkToPk
///                  operation.
/// - signature (REQUIRED), an octet string of the form outputted by the
///                         Sign operation.
/// - generators (REQUIRED), vector of pseudo-random points in G1.
/// - header (OPTIONAL), an octet string containing context and application
///                      specific information. If not supplied, it defaults
///                      to the empty octet string ("").
/// - messages (OPTIONAL), a vector of scalars representing the messages.
///                        If not supplied, it defaults to the empty
///                        array ("()").
/// - api_id (OPTIONAL), an octet string. If not supplied it defaults to the
///                      empty octet string ("").
///
/// Parameters:
/// - P1, fixed point of G1, defined by the ciphersuite.
///
/// Outputs:
/// - result, either VALID or INVALID.
pub fn core_verify(
    pk: &BBSPublicKey,
    signature: &BBSSignature,
    generators: &Seq<G1>,
    header: Option<&ByteSeq>,
    messages: Option<&Seq<Scalar>>,
    api_id: Option<&ByteSeq>,
) -> Result<bool, Error> {
    let default_header = &ByteSeq::from_public_slice(b"");
    let default_api_id = &ByteSeq::from_public_slice(b"");
    let default_messages = &Seq::new(0);
    let header = header.unwrap_or(default_header);
    let api_id = api_id.unwrap_or(default_api_id);
    let messages = messages.unwrap_or(default_messages);

    let p1 = base_g1();
    let bp2 = base_g2();

    // TODO: octets_to_signature
    let (a, e) = *signature;
    // TODO: W = octets_to_pubkey(PK)
    let w = *pk;
    // L = length(messages)
    let l = messages.len();
    // if length(generators) != L + 1, return INVALID
    if generators.len() != l + 1 {
        return Err(Error::InvalidCoreVerify);
    }
    // (Q_1, H_1, ..., H_L) = generators
    let q1 = &generators[0];
    let h_points = &generators.slice(1, l);

    // 1. domain = calculate_domain(PK, generators, header, api_id)
    let domain = calculate_domain(pk, q1, h_points, Some(header), Some(api_id));
    // 2. B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let mut b = g1add(p1, g1mul(domain, *q1));
    for i in 0..l {
        b = g1add(b, g1mul(messages[i], h_points[i]));
    }
    // 3. if e(A, W + BP2 * e) * e(B, -BP2) != Identity_GT, return INVALID
    let pairing1 = pairing(a, g2add(w, g2mul(e, bp2)));
    let pairing2 = pairing(b, g2neg(bp2));
    let pairing_comp = fp12mul(pairing1, pairing2);
    println!("{:?}", pairing_comp);
    if pairing_comp != identity_gt() {
        return Err(Error::InvalidCoreVerify);
    }
    // 4. return VALID
    Ok(true)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::keygen::*;

    #[test]
    fn test_sign_correctness() {
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

        let header = ByteSeq::from_public_slice(b"");
        let messages = Seq::new(1);
        messages.push(&ByteSeq::from_public_slice(b"message1"));

        println!("{:?}", messages);
        let signature = sign(&sk, &pk, Some(&header), Some(&messages)).unwrap();
        println!("{:?}", signature);

        let result = verify(&pk, &signature, Some(&header), Some(&messages)).unwrap();
        assert_eq!(result, true);
    }

    #[test]
    fn test_sign_soundness() {
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

        let header = ByteSeq::from_public_slice(b"");
        let messages = Seq::new(1);
        messages.push(&ByteSeq::from_public_slice(b"message1"));

        println!("{:?}", messages);
        let signature = sign(&sk, &pk, Some(&header), Some(&messages)).unwrap();
        println!("{:?}", signature);

        let malicious_messages = Seq::new(1);
        malicious_messages.push(&ByteSeq::from_public_slice(b"malicious_message"));
        let result = verify(&pk, &signature, Some(&header), Some(&malicious_messages)).unwrap();
        assert_eq!(result, false);
    }
}
