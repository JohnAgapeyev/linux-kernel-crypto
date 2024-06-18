use std::io::{Read, Write};

use rand_core::{Error, RngCore, SeedableRng};

use crate::transform::*;

impl RngCore for TransformInstance<RngTransform> {
    fn next_u32(&mut self) -> u32 {
        let mut out = [0u8; 4];
        self.read_exact(&mut out).unwrap();
        u32::from_ne_bytes(out)
    }
    fn next_u64(&mut self) -> u64 {
        let mut out = [0u8; 8];
        self.read_exact(&mut out).unwrap();
        u64::from_ne_bytes(out)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).unwrap()
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        const MAX_BLOCK: usize = 128;

        for chunk in dest.chunks_mut(MAX_BLOCK) {
            self.read_exact(chunk).map_err(rand_core::Error::new)?;
        }

        Ok(())
    }
}

//impl SeedableRng for TransformInstance<RngTransform> {
//    type Seed = [u8; 32];
//
//    fn from_seed(seed: Self::Seed) -> Self {
//        //
//    }
//}

#[cfg(test)]
mod rand_traits_tests {
    use super::*;
    use rand::Rng;
    use std::os::fd::AsFd;

    #[test]
    fn rng_works() {
        let init_buf = [0u8; 133];
        let mut buf = init_buf.clone();
        let rng_seed = [0u8; 0];

        let mut tf = Transform::new(RngTransform {
            base: TransformBase {
                name: "stdrng".to_string(),
                driver: "drbg_pr_ctr_aes256".to_string(),
                module: "kernel".to_string(),
                priority: 100,
                ref_cnt: 1,
                self_test: true,
                internal: false,
                ttype: TransformType::Rng,
            },
            seed_size: 0,
        });

        //You have to seed the algorithm, not the instance, even if the seedsize is zero!
        tf.set_key(&rng_seed).unwrap();

        let mut kernel_rng = tf.instance().unwrap();

        //Test uses the Rng trait method to fill the buffer instead of relying on std::io::Read
        kernel_rng.fill(buf.as_mut_slice());

        assert!(buf != init_buf);
    }
}
