#![forbid(unsafe_code)]

pub const CRT_RAND_MULT: u32 = 214_013;
pub const CRT_RAND_INC: u32 = 2_531_011;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrtRand {
    state: u32,
}

impl CrtRand {
    pub fn new(seed: u32) -> Self {
        Self { state: seed }
    }

    pub fn state(&self) -> u32 {
        self.state
    }

    pub fn srand(&mut self, seed: u32) {
        self.state = seed;
    }

    pub fn rand(&mut self) -> u32 {
        self.state = self
            .state
            .wrapping_mul(CRT_RAND_MULT)
            .wrapping_add(CRT_RAND_INC);
        (self.state >> 16) & 0x7fff
    }
}
