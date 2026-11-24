use super::password::Password;
use zeroize::Zeroizing;

pub struct CryptoInitBySignSeq {
    pub sequence: Zeroizing<Vec<u8>>,
    pub container: Vec<u8>,
    pub signature: Vec<u8>,
    pub password: Password,
    pub need_random_block: bool,
}
impl CryptoInitBySignSeq {
    pub fn new(
        sequence: Vec<u8>,
        container: Vec<u8>,
        signature: Vec<u8>,
        password: Password,
    ) -> Self {
        Self {
            sequence: Zeroizing::new(sequence),
            container,
            signature,
            password,
            need_random_block: false,
        }
    }
}
