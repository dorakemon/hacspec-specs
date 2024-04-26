use hacspec_bls12_381::*;
use hacspec_bls12_381_hash::*;
use hacspec_lib::*;

use crate::ciphersuite::*;

const EXPAND_LEN: usize = 48;

///　<https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-generators-calculation>
///
/// The create_generators procedure defines how to create a set of
/// randomly sampled points from the G1 subgroup, called the generators.
/// It makes use of the primitives defined in [RFC9380] (more
/// specifically of hash_to_curve and expand_message) to hash a seed to a
/// set of generators.  Those primitives are implicitly defined by the
/// ciphersuite, through the choice of a hash-to-curve suite (see the
/// hash_to_curve_suite parameter in Section 7.1).
///
/// Inputs:
/// - count (REQUIRED), unsigned integer. Number of generators to create.
/// - api_id (OPTIONAL), octet string. If not supplied it defaults to the
///                      empty octet string ("").
///
/// Parameters:
/// - hash_to_curve_g1, the hash_to_curve operation for the G1 subgroup,
///                     defined by the suite specified by the
///                     hash_to_curve_suite parameter of the ciphersuite.
/// - expand_message, the expand_message operation defined by the suite
///                   specified by the hash_to_curve_suite parameter of the
///                   ciphersuite.
/// - expand_len, defined by the ciphersuite.
///
/// Outputs:
/// - generators, an array of generators.
///
/// Definitions:
/// 1. seed_dst, an octet string representing the domain separation tag:
///              api_id || "SIG_GENERATOR_SEED_" where "SIG_GENERATOR_SEED_"
///              is an ASCII string comprised of 19 bytes.
/// 2. generator_dst, an octet string representing the domain separation
///                   tag: api_id || "SIG_GENERATOR_DST_", where
///                   "SIG_GENERATOR_DST_" is an ASCII string comprised of
///                   18 bytes.
/// 3. generator_seed, an octet string representing the domain separation
///                    tag: api_id || "MESSAGE_GENERATOR_SEED", where
///                    "MESSAGE_GENERATOR_SEED" is an ASCII string comprised
///                    of 22 bytes.
pub fn create_generators(count: usize, api_id: Option<&ByteSeq>) -> Seq<G1> {
    // if (count as u64) > 2u64.pow(64) - 1 {
    //     panic!("Count is too big");
    // }

    let default_api_id = &ByteSeq::from_public_slice(b"");
    let api_id = api_id.unwrap_or(default_api_id);
    let mut seed_dst = ByteSeq::new(api_id.len() + 19);
    seed_dst = seed_dst
        .concat(api_id)
        .concat(&ByteSeq::from_public_slice(b"SIG_GENERATOR_SEED_"));
    let mut generator_dst = ByteSeq::new(api_id.len() + 18);
    generator_dst = generator_dst
        .concat(api_id)
        .concat(&ByteSeq::from_public_slice(b"SIG_GENERATOR_DST_"));
    let mut generator_seed = ByteSeq::new(api_id.len() + 22);
    generator_seed = generator_seed
        .concat(api_id)
        .concat(&ByteSeq::from_public_slice(b"MESSAGE_GENERATOR_SEED"));
    let mut generators = Seq::<G1>::new(count);

    // 1. v = expand_message(generator_seed, seed_dst, expand_len)
    let v = expand_message_xmd(&generator_seed, &seed_dst, EXPAND_LEN);
    // 2. for i in (1, 2, ..., count):
    for i in 1..count + 1 {
        // 3.    v = expand_message(v || I2OSP(i, 8), seed_dst, expand_len)
        let i_bytes = i.to_be_bytes();
        let v = expand_message_xmd(
            &v.concat(&ByteSeq::from_public_slice(&i_bytes)),
            &seed_dst,
            EXPAND_LEN,
        );
        // 4. generator_i = hash_to_curve_g1(v, generator_dst)
        generators[i - 1] = g1_hash_to_curve_sswu(&v, &generator_dst);
    }
    // 5. return (generator_1, ..., generator_count)
    generators
}

/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-messages-to-scalars>
///
/// The messages_to_scalars operation is used to map a list of messages
/// to their respective scalar values, which are required by the core BBS
/// operations defined in Section 3.6.
///
/// Inputs:
/// - messages (REQUIRED), a vector of octet strings.
/// - api_id (OPTIONAL), octet string. If not supplied it defaults to the
///                      empty octet string ("").
///
/// Outputs:
/// - msg_scalars, a list of scalars.
///
/// Definitions:
/// 1. map_dst, an octet string representing the domain separation tag:
///             api_id || "MAP_MSG_TO_SCALAR_AS_HASH_" where
///             "MAP_MSG_TO_SCALAR_AS_HASH_" is an ASCII string comprised of
///             26 bytes.
pub fn message_to_scalar(messages: &Seq<ByteSeq>, api_id: Option<&ByteSeq>) -> Seq<Scalar> {
    let default_api_id = &ByteSeq::from_public_slice(b"");
    let api_id = api_id.unwrap_or(default_api_id);
    let mut map_dst = ByteSeq::new(api_id.len() + 26);
    map_dst = map_dst
        .concat(api_id)
        .concat(&ByteSeq::from_public_slice(b"MAP_MSG_TO_SCALAR_AS_HASH_"));

    // 1. L =  length(messages)
    let l = messages.len();
    // 2. for i in (1, ..., L):
    // 3.     msg_scalar_i = hash_to_scalar(messages[i], map_dst)
    let mut msg_scalars: Seq<Scalar> = Seq::new(l);
    for i in 0..l {
        let msg_scalar_i = hash_to_scalar(&messages[i], &map_dst);
        msg_scalars[i] = msg_scalar_i;
    }
    msg_scalars
}

/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-hash-to-scalar>
///
/// This operation describes how to hash an arbitrary octet string to a
/// scalar values in the multiplicative group of integers mod r (i.e.,
/// values in the range from 1 to r - 1).  This procedure acts as a
/// helper function, used internally in various places within the
/// operations described in the spec.
///
///  Inputs:
///  - msg_octets (REQUIRED), an octet string. The message to be hashed.
///  - dst (REQUIRED), an octet string representing a domain separation tag.
///
///  Parameters:
///  - hash_to_curve_suite, the hash to curve suite id defined by the
///                         ciphersuite.
///  - expand_message, the expand_message operation defined by the suite
///                    specified by the hash_to_curve_suite parameter.
///  - expand_len, defined by the ciphersuite.
///
///  Outputs:
///  - hashed_scalar, a scalar.
pub fn hash_to_scalar(msg_octects: &ByteSeq, dst: &ByteSeq) -> Scalar {
    if dst.len() > 255 {
        panic!("Destination length is too big");
    }
    // 1. uniform_bytes = expand_message(msg_octets, dst, expand_len)
    let uniform_bytes = expand_message_xmd(msg_octects, dst, EXPAND_LEN);
    // 2. return OS2IP(uniform_bytes) mod r
    // OS2IP: https://datatracker.ietf.org/doc/html/rfc8017#section-4.2
    let r = Fp::from_hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    let hex_data_fp = Fp::from_byte_seq_be(&uniform_bytes).modulo(r);
    let hex_data_fp_bytes = hex_data_fp.to_be_bytes();
    Scalar::from_be_bytes(&hex_data_fp_bytes[16..48])
}

/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-domain-calculation>
///
/// This operation calculates the domain value, a scalar representing the
/// distillation of all essential contextual information for a signature.
/// The same domain value must be calculated by all parties (the Signer,
/// the Prover and the Verifier) for both the signature and proofs to be
/// validated.
/// Inputs:
/// - PK (REQUIRED), an octet string, representing the public key of the
///                  Signer of the form outputted by the SkToPk operation.
/// - Q_1 (REQUIRED), point of G1 (the first point returned from
///                   create_generators).
/// - H_Points (REQUIRED), array of points of G1.
/// - header (OPTIONAL), an octet string. If not supplied, it must default
///                      to the empty octet string ("").
///- api_id (OPTIONAL), octet string. If not supplied it defaults to the
///                     empty octet string ("").
///
/// Outputs:
/// - domain, a scalar.
pub fn calculate_domain(
    pk: &BBSPublicKey,
    q1: &G1,
    h_points: &Seq<G1>,
    header: Option<&ByteSeq>,
    api_id: Option<&ByteSeq>,
) -> Scalar {
    let default_header = &ByteSeq::from_public_slice(b"");
    let default_api_id = &ByteSeq::from_public_slice(b"");
    let header = header.unwrap_or(default_header);
    let api_id = api_id.unwrap_or(default_api_id);

    let mut domain_dst = ByteSeq::new(api_id.len() + 4);
    domain_dst = domain_dst
        .concat(api_id)
        .concat(&ByteSeq::from_public_slice(b"H2S_"));

    let l = h_points.len();

    // TODO
    // 1. dom_array = (L, Q_1, H_1, ..., H_L)
    // let mut dom_array = Seq::<G1>::new(l + 2);
    // dom_array.push(l);
    // dom_array.push(q1);

    // 2. dom_octs = serialize(dom_array) || api_id
    // 3. dom_input = PK || dom_octs || I2OSP(length(header), 8) || header
    // 4. return hash_to_scalar(dom_input, domain_dst)

    let temp_domain = Scalar::from_hex("1230");
    temp_domain
}
