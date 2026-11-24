use super::{
    crypto_init_by_cont::CryptoInitByCont, crypto_init_by_seq::CryptoInitBySeq,
    crypto_init_by_sign_seq::CryptoInitBySignSeq, init_method_type::InitMethodType,
};

pub enum InitParams {
    BySeq(CryptoInitBySeq),
    BySignSeq(CryptoInitBySignSeq),
    Cont(CryptoInitByCont),
}
impl InitParams {
    pub fn method(&self) -> InitMethodType {
        match self {
            Self::BySeq(_) => InitMethodType::BySeq,
            Self::BySignSeq(_) => InitMethodType::BySignSeq,
            Self::Cont(_) => InitMethodType::Cont,
        }
    }
}
impl From<CryptoInitBySeq> for InitParams {
    fn from(v: CryptoInitBySeq) -> Self {
        Self::BySeq(v)
    }
}
impl From<CryptoInitBySignSeq> for InitParams {
    fn from(v: CryptoInitBySignSeq) -> Self {
        Self::BySignSeq(v)
    }
}
impl From<CryptoInitByCont> for InitParams {
    fn from(v: CryptoInitByCont) -> Self {
        Self::Cont(v)
    }
}
