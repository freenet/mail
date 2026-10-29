// A deterministic rand_core 0.10 RNG for the ML-KEM vectors: 0, 1, 2, ...
// as bytes. `include!`d by the UI's crypto tests and by wire-v1/capture, so
// both encapsulate with the same "random" bytes. Never for real use.

#[derive(Default)]
struct KemFixedRng(u8);

impl rand_core::TryRng for KemFixedRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for b in dst {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for KemFixedRng {}
