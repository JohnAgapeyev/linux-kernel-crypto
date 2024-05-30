pub mod socket;
pub use crate::socket::*;
pub mod parsing;
pub use crate::parsing::*;

#[cfg(feature = "crypto-traits")]
pub mod traits;
#[cfg(feature = "crypto-traits")]
pub use crate::traits::*;

#[cfg(feature = "rand-traits")]
pub mod rand_traits;
#[cfg(feature = "rand-traits")]
pub use crate::rand_traits::*;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
