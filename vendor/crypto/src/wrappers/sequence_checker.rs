use super::internal::secret_copy;
use super::{base_crypt::BaseCrypt, error::Result, internal::checked, internal::length, symbol};

pub struct SequenceChecker {
    parent: BaseCrypt,
}
impl SequenceChecker {
    pub fn new(parent: &BaseCrypt) -> Result<Self> {
        let _ = symbol!(parent.0.plugin(), checkSequence_port);
        Ok(Self {
            parent: parent.clone(),
        })
    }
    pub fn check(&mut self, sequence: &[u8]) -> Result<()> {
        let f = symbol!(self.parent.0.plugin(), checkSequence_port);
        let mut data = secret_copy(sequence);
        let mut error = 0;
        checked(
            unsafe {
                f(
                    self.parent.0.ptr.as_ptr(),
                    data.as_mut_ptr().cast(),
                    length(data.len())?,
                    &mut error,
                )
            },
            error,
            "checkSequence_port",
        )
    }
}
