#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestLength {
    Bits256,
    Bits512,
}
impl DigestLength {
    pub fn bytes(self) -> usize {
        match self {
            Self::Bits256 => 32,
            Self::Bits512 => 64,
        }
    }
    pub(super) fn id(self) -> i32 {
        match self {
            Self::Bits256 => 0,
            Self::Bits512 => 1,
        }
    }
}
