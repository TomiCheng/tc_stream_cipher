mod key_fixed;
#[cfg(feature = "alloc")]
mod key_owned;
mod key_ref;
mod key_with_iv_fixed;
#[cfg(feature = "alloc")]
mod key_with_iv_owned;
mod key_with_iv_ref;

pub use key_fixed::KeyFixed;
#[cfg(feature = "alloc")]
pub use key_owned::KeyOwned;
pub use key_ref::KeyRef;
pub use key_with_iv_fixed::KeyWithIvFixed;
#[cfg(feature = "alloc")]
pub use key_with_iv_owned::KeyWithIvOwned;
pub use key_with_iv_ref::KeyWithIvRef;

#[cfg(test)]
mod tests {
    use tc_zeroize::Zeroize;

    use super::{KeyFixed, KeyRef, KeyWithIvFixed, KeyWithIvRef};
    use crate::{IvParams, KeyParams};

    #[test]
    fn the_borrowing_containers_return_the_slices_they_were_given() {
        let (key, iv) = ([1u8, 2, 3], [4u8, 5]);
        assert_eq!(KeyRef::new(&key).key(), &key);
        let params = KeyWithIvRef::new(&key, &iv);
        assert_eq!(params.key(), &key);
        assert_eq!(params.iv(), &iv);
    }

    #[test]
    fn the_owning_containers_wipe_their_key_and_iv() {
        let mut fixed = KeyFixed::new([0x42u8; 16]);
        assert_eq!(fixed.key(), &[0x42; 16]);
        fixed.zeroize();
        assert_eq!(fixed.key(), &[0; 16]);

        let mut fixed = KeyWithIvFixed::new([0x42u8; 32], [0x24u8; 12]);
        assert_eq!(
            (fixed.key(), fixed.iv()),
            (&[0x42; 32][..], &[0x24; 12][..])
        );
        fixed.zeroize();
        assert_eq!((fixed.key(), fixed.iv()), (&[0; 32][..], &[0; 12][..]));

        #[cfg(feature = "alloc")]
        {
            let mut owned = super::KeyOwned::new(alloc::vec![0x42u8; 20]);
            owned.zeroize();
            assert!(owned.key().iter().all(|&byte| byte == 0));

            let mut owned =
                super::KeyWithIvOwned::new(alloc::vec![0x42u8; 32], alloc::vec![0x24u8; 24]);
            assert_eq!(owned.iv(), &[0x24; 24]);
            owned.zeroize();
            assert!(owned.key().iter().chain(owned.iv()).all(|&byte| byte == 0));
        }
    }
}
