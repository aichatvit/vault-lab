use zeroize::Zeroizing;

/// Энтропия для инициализации должна поступать из доверенного источника, как требует API плагина.
pub struct CryptoInitBySeq {
    pub sequence: Zeroizing<Vec<u8>>,
    pub need_random_block: bool,
}
impl CryptoInitBySeq {
    pub fn new(sequence: Vec<u8>) -> Self {
        Self {
            sequence: Zeroizing::new(sequence),
            need_random_block: false,
        }
    }
}
