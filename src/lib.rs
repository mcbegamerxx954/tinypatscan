#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(feature = "simd")]
use wide::u8x16;
/// A byte pattern.
/// This type needs you to specify the total size of your pattern in order to work
#[derive(Debug)]
pub struct Pattern<const SIZE: usize> {
    data: [u8; SIZE],
    mask: [u8; SIZE],
}

macro_rules! const_unwrap {
    ($call:expr, $message:literal) => {
        match $call {
            Ok(sucess) => sucess,
            Err(_) => panic!($message),
        }
    };
}
impl<const SIZE: usize> Pattern<SIZE> {
    /// Construct a pattern from a string at compiletime
    /// Usually pattern strings have this format: (FF D8 00 03) , each byte has to be encoded in base16 like ida patterns
    /// you can also add ?? instead of a byte, which makes it match any byte
    ///
    /// Failing to choose the correct pattern size will result in a compiletime error in a const context
    pub const fn from_str(sus: &str) -> Self {
        let mut data = [0u8; SIZE];
        let mut mask = [u8::MAX; SIZE];
        let mut i = 0;
        let mut pattern_i = 0;
        let mut hexbytes = [0u8; 2];
        let mut found_huh = false;
        while i < sus.len() {
            let char = sus.as_bytes()[i];
            match char {
                b' ' => {
                    if found_huh {
                        found_huh = false;
                    } else {
                        assert!(hexbytes[0] != 0 && hexbytes[1] != 0);
                        let duo_str = const_unwrap!(core::str::from_utf8(&hexbytes), "not utf8");
                        let parsed = const_unwrap!(u8::from_str_radix(duo_str, 16), "Bad pattern");
                        data[pattern_i] = parsed;
                        pattern_i += 1;
                    }
                    hexbytes = [0, 0];
                }
                b'?' => {
                    if !found_huh {
                        assert!(hexbytes[0] == 0 && hexbytes[1] == 0);
                        mask[pattern_i] = 0;
                        pattern_i += 1;
                    }
                    found_huh = true;
                }
                char @ _ => {
                    let index = if hexbytes[0] != 0 { 1 } else { 0 };
                    hexbytes[index] = char;
                }
            }
            i += 1;
            if i == sus.len() {
                assert!(hexbytes[0] != 0);
                if hexbytes[0] == b'?' {
                    mask[pattern_i] = 0;
                    continue;
                }
                assert!(hexbytes[1] != 0);
                let duo_str = const_unwrap!(core::str::from_utf8(&hexbytes), "not utf8");
                let parsed = const_unwrap!(u8::from_str_radix(duo_str, 16), "Bad pattern");
                data[pattern_i] = parsed;
            }
        }
        Self { data, mask }
    }

    /// Search pattern inside bytes
    pub fn search(&self, bytes: &[u8]) -> Option<usize> {
        'search: for (i, slice) in bytes.windows(SIZE).enumerate() {
            'compare: for index in 0..SIZE {
                if self.mask[index] == u8::MAX {
                    continue 'compare;
                }
                if self.data[index] != slice[index] {
                    continue 'search;
                }
            }
            return Some(i);
        }
        None
    }
    /// Search pattern inside bytes with SIMD
    #[cfg(feature = "simd")]
    pub fn simd_search(&self, bytes: &[u8]) -> Option<usize> {
        'search: for (i, slice) in bytes.windows(SIZE).enumerate() {
            let slice_chunks = slice.chunks_exact(16);
            let mut pattern_chunks = self.data.chunks_exact(16);
            let mut mask_chunks = self.mask.chunks_exact(16);
            for chunk in slice_chunks {
                let chunk = u8x16::new(chunk.try_into().unwrap());
                let pattern_chunk = u8x16::new(pattern_chunks.next()?.try_into().unwrap());
                let mask_chunk = u8x16::new(mask_chunks.next()?.try_into().unwrap());
                let masked = chunk & mask_chunk;
                if masked != pattern_chunk {
                    continue 'search;
                }
            }
            let rem_start = slice.len() - slice.chunks_exact(16).remainder().len();
            'remainder: for (i, byte) in slice.chunks_exact(16).remainder().iter().enumerate() {
                if self.mask[rem_start + i] == u8::MAX {
                    continue 'remainder;
                }
                if self.data[rem_start + i] != *byte {
                    continue 'search;
                }
            }
            return Some(i);
        }
        None
    }
    /// Search pattern inside bytes with multiple threads
    #[cfg(feature = "multithreading")]
    pub fn par_search(&self, bytes: &[u8]) -> Option<usize> {
        use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
        use rayon::slice::ParallelSlice;
        let gah = bytes
            .par_windows(SIZE)
            .enumerate()
            .map(|(i, slice)| {
                'compare: for index in 0..SIZE {
                    if self.mask[index] == u8::MAX {
                        continue 'compare;
                    }
                    if self.data[index] != slice[index] {
                        return None;
                    }
                }
                Some(i)
            })
            .find_any(|e| e.is_some());
        gah.flatten()
    }
}
