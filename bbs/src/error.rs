#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidKeyGen,
    InvalidHashToScalar,
    InvalidCoreSign,
    InvalidCoreVerify,
}
