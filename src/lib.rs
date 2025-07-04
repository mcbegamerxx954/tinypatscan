#![cfg_attr(not(feature = "std"), no_std)]
// use const_format::concatcp;
#[cfg(feature = "simd")]
use wide::u8x16;
/// A byte pattern.
/// This type needs you to specify the total size of your pattern in order to work
#[derive(Debug)]
pub struct Pattern<const SIZE: usize> {
    data: [u8; SIZE],
    mask: [u8; SIZE],
    pattern_i: usize,
    no_mask: bool,
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
        assert!(
            SIZE > get_pattern_size(sus),
            "The const pattern size is wrong, use get_pattern_size to get it"
        );
        let mut data = [0u8; SIZE];
        let mut mask = [u8::MAX; SIZE];
        let mut i = 0;
        let mut pattern_i = 0;
        let mut hexbytes = [0u8; 2];
        let mut found_huh = false;
        let mut no_mask = true;
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
                    no_mask = false;
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
                pattern_i += 1;
            }
        }
        Self {
            data,
            mask,
            pattern_i,
            no_mask,
        }
    }

    /// Search pattern inside bytes
    pub fn search(&self, bytes: &[u8]) -> Option<usize> {
        assert!(self.pattern_i <= SIZE);
        #[cfg(feature = "memchr")]
        if self.no_mask {
            return memchr::memmem::find(bytes, &self.data[..self.pattern_i]);
        }
        'search: for (i, slice) in bytes.windows(self.pattern_i).enumerate() {
            'compare: for index in 0..self.pattern_i {
                if self.mask[index] == 0 {
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
    #[inline(never)]
    #[cfg(feature = "simd")]
    pub fn simd_search(&self, bytes: &[u8]) -> Option<usize> {
        assert!(self.pattern_i <= SIZE);
        #[cfg(feature = "memchr")]
        if self.no_mask {
            return memchr::memmem::find(bytes, &self.data[..self.pattern_i]);
        }
        let mut pattern_chunks = self.data[..self.pattern_i].chunks_exact(16);
        let mut mask_chunks = self.mask[..self.pattern_i].chunks_exact(16);
        'search: for (i, slice) in bytes.windows(self.pattern_i).enumerate() {
            let slice_chunks = slice.chunks_exact(16);
            let mut pchunks = pattern_chunks.clone();
            let mut mchunks = mask_chunks.clone();
            for chunk in slice_chunks {
                let chunk = u8x16::new(chunk.try_into().unwrap());
                let pattern_chunk = u8x16::new(pchunks.next()?.try_into().unwrap());
                let mask_chunk = u8x16::new(mchunks.next()?.try_into().unwrap());
                let masked = chunk & mask_chunk;
                if masked != pattern_chunk {
                    continue 'search;
                }
            }
            // println!("got to rem");
            let rem_chunk = slice.chunks_exact(16).remainder();
            let rem_start = slice.len() - rem_chunk.len();
            assert!(rem_chunk.len() + rem_start <= SIZE);
            'remainder: for (i, byte) in rem_chunk.iter().enumerate() {
                if self.mask[rem_start + i] == 0 {
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
        assert!(self.pattern_i <= SIZE);
        #[cfg(feature = "memchr")]
        if self.no_mask {
            return memchr::memmem::find(bytes, &self.data[..self.pattern_i]);
        }
        use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
        use rayon::slice::ParallelSlice;
        let gah = bytes
            .par_windows(self.pattern_i)
            .enumerate()
            .map(|(i, slice)| {
                'compare: for index in 0..self.pattern_i {
                    if self.mask[index] == 0 {
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

const fn get_pattern_size(pattern: &str) -> usize {
    let mut i = 0;
    let mut non_whitespace = true;
    let mut pattern_len = 0;
    let chars = pattern.as_bytes();
    while i < pattern.len() {
        if chars[i] == b' ' && non_whitespace {
            pattern_len += 1;
            non_whitespace = false;
        } else if chars[i] != b' ' {
            non_whitespace = true;
        }
        i += 1;
    }
    pattern_len + 1
}
#[cfg(test)]
//const MCLIB: &[u8] = include_bytes!("libminecraftpe.so");
#[cfg(test)]
const pat: Pattern<65> = Pattern::from_str(
    "?? ?? ?? D1 ?? ?? ?? A9 ?? ?? ?? 91 ?? ?? ?? A9 ?? ?? ?? A9 ?? ?? ?? A9 ?? ?? ?? D5 F5 03 03 2A ?? ?? ?? F9 F6 03 02 2A F3 03 01 AA F4 03 00 AA ?? ?? ?? F8 ?? ?? ?? F9 ?? ?? ?? B4 9F 00 08 EB",
);
#[cfg(test)]
extern crate std;
#[test]
fn scalar() {
    let sus = std::fs::read("libminecraftpe.so").unwrap();
    assert_eq!(pat.search(&sus).unwrap(), 100932284);
}
#[test]
fn simd() {
    let sus = std::fs::read("libminecraftpe.so").unwrap();
    assert_eq!(pat.simd_search(&sus).unwrap(), 100932284);
}
#[test]
fn mt() {
    let sus = std::fs::read("libminecraftpe.so").unwrap();
    assert_eq!(pat.par_search(&sus).unwrap(), 100932284);
}
