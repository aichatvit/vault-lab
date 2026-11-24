use super::password::Password;

pub struct CryptoInitByCont {
    pub container: Vec<u8>,
    pub password: Password,
    pub need_random_block: bool,
}
impl CryptoInitByCont {
    pub fn new(container: Vec<u8>, password: Password) -> Self {
        Self {
            container,
            password,
            need_random_block: false,
        }
    }
}
