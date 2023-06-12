use std::convert::TryInto;
use std::ops::{Index, IndexMut, Range};
use lazy_static::lazy_static;
use sha3::{Digest, Sha3_256};
use sha3::digest::{FixedOutput};
use log::debug;

/// Note: 2**12 = 4 KiB, the minimum page-size in Unicorn for mmap
pub const PAGE_ADDR_SIZE: usize = 12;
pub const PAGE_KEY_SIZE: usize = 32 - PAGE_ADDR_SIZE;
pub const PAGE_SIZE: usize = 1 << PAGE_ADDR_SIZE;
pub const PAGE_ADDR_MASK: usize = PAGE_SIZE - 1;
const MAX_PAGE_COUNT: usize = 1 << PAGE_KEY_SIZE;
const PAGE_KEY_MASK: usize = MAX_PAGE_COUNT - 1;

pub fn hash_pair(data_l: &[u8; 32], data_r: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::default();
    hasher.update([&data_l[..], data_r].concat());
    return hasher.finalize_fixed().try_into().unwrap();
}

fn zero_hash() -> Box<[[u8; 32]; 29]> {
    let mut out = Box::new(
        [[0; 32]; 29]
    );

    for i in 1..29 {
        out[i] = hash_pair(&out[i-1], &out[i-1]);
    }

    out
}

lazy_static! {
    pub static ref ZERO_HASHS: [[u8; 32]; 29] = *zero_hash();
}

#[derive(Debug, Clone)]
pub struct Page([u8; PAGE_SIZE]);

impl Index<Range<usize>> for Page {
    type Output = [u8];

    fn index(&self, index: Range<usize>) -> &[u8] {
        &self.0[index]
    }
}

impl IndexMut<Range<usize>> for Page {
    fn index_mut(&mut self, index: Range<usize>) -> &mut [u8] {
        &mut self.0[index]
    }
}

impl Page {
    fn new() -> Page {
        Page([0; PAGE_SIZE])
    }
}

#[derive(Debug, Clone)]
pub struct CachedPage {
    pub data: Page,

    // merkle tree intermediate nodes only
    cache: [[u8; 32]; PAGE_SIZE / 32],

    // true if the above intermediate node is valid
    pub ok: [bool; PAGE_SIZE / 32],
}

impl CachedPage {
    pub fn new() -> Self {
        Self {
            data: Page::new(),
            cache: [[0; 32]; PAGE_SIZE / 32],
            ok: [false; PAGE_SIZE / 32],
        }
    }

    pub fn invalidate(&mut self, page_addr: u32) {
        if page_addr as usize >= PAGE_SIZE {
            panic!("CachedPage invalidate page: invalid page addr")
        }

        let mut k = (1 << PAGE_ADDR_SIZE) | page_addr as usize;

        // first cache layer caches nodes that has two 32 byte leaf nodes.
        debug!("invalidate nodes");
        k >>= 5 + 1;
        while k > 0 {
            debug!("k: {}", k);
            self.ok[k] = false;
            k >>= 1;
        }
    }

    pub fn invalidate_full(&mut self) {
        self.ok.fill(false);
    }

    pub fn merkle_root(&mut self) -> [u8; 32] {
        // hash the bottom layer
        debug!("hash the bottom layer");
        for i in (0..PAGE_SIZE).step_by(64) {
            let j = (PAGE_SIZE >> (5+1)) + i / 64;
            if self.ok[j] {
                continue
            }
            debug!("j: {} <- {}, {}", j, i, i+64);
            let mut hasher = Sha3_256::default();
            hasher.update(&self.data[i..i+64]);
            self.cache[j] = hasher.finalize_fixed().try_into().unwrap();
            self.ok[j] = true;
        }

        // hash the cache layers
        debug!("hash the cache layer");
        for i in (0..PAGE_SIZE/32).step_by(2).rev() {
            let j = i >> 1;
            if self.ok[j] {
                continue
            }
            debug!("j: {} <- {}, {}", j, i, i+1);
            self.cache[j] = hash_pair(&self.cache[i], &self.cache[i+1]);
            self.ok[j] = true
        }

        self.cache[1]
    }

    pub fn merklelize_subtree(&mut self, generalized_index: usize) -> [u8; 32] {
        self.merkle_root();
        if generalized_index >= PAGE_SIZE/32 {
            if generalized_index >= PAGE_SIZE/32*2 {
                panic!("generalized_index too deep");
            }
            // it's pointing to a bottom node
            let node_index = generalized_index & (PAGE_ADDR_MASK >> 5);
            [0; 32].clone_from_slice(
                &self.data[(node_index <<5).. ((node_index <<5)+32)]
            )
        }
        self.cache[generalized_index]
    }
}
