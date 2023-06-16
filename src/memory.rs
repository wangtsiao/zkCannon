use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Read;
use std::rc::Rc;
use crate::page::{CachedPage, hash_pair, PAGE_ADDR_MASK, PAGE_ADDR_SIZE, PAGE_KEY_SIZE, PAGE_SIZE, ZERO_HASHS};

#[derive(Debug)]
pub struct Memory {
    /// generalized index -> merkle node or none if invalidate
    nodes: HashMap<u32, Option<Box<[u8; 32]>>>,

    /// page index -> cached page
    pages: HashMap<u32, Rc<RefCell<CachedPage>>>,

    // two caches: we often read instructions from one page, and do memory things with another page.
    // this prevents map lookups each instruction
    last_page_keys: [Option<u32>; 2],
    last_page: [Option<Rc<RefCell<CachedPage>>>; 2],

    // for implement std::io::Read trait
    addr: u32,
    count: u32,
}

impl Memory {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            pages: HashMap::new(),

            last_page_keys: Default::default(), // default to invalid keys, to not match any pages
            last_page: Default::default(),

            addr: 0,
            count: 0,
        }
    }

    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    pub fn for_each_page<T: Fn(u32, &Rc<RefCell<CachedPage>>) -> Result<(), String>>
    (&mut self, handler: T) -> Result<(), String>{

        for (page_index, cached_page) in self.pages.iter() {
            let r = handler(*page_index, cached_page);
            if let Err(e) = r {
                return Err(e)
            }
        }

        Ok(())
    }

    fn page_lookup(&mut self, page_index: u32) -> Option<Rc<RefCell<CachedPage>>> {
        // find cache first
        if Some(page_index) == self.last_page_keys[0] {
            return self.last_page[0].clone();
        }
        if Some(page_index) == self.last_page_keys[1] {
            return self.last_page[1].clone();
        }

        match self.pages.get(&page_index) {
            None => {None}
            Some(cached_page) => {
                self.last_page_keys[1] = self.last_page_keys[0];
                self.last_page[1] = self.last_page[0].clone();

                self.last_page_keys[0] = Some(page_index);
                self.last_page[0] = Some(cached_page.clone());

                return self.last_page[0].clone();
            }
        }
    }

    pub fn invalidate(&mut self, addr: u32) {
        if addr & 0x3 != 0 {
            panic!("unaligned memory access: {:x?}", addr)
        }

        let should_ret = match self.page_lookup(addr >> PAGE_ADDR_SIZE) {
            None => {
                // no page, nothing to invalidate
                true
            }
            Some(cached_page) => {
                let mut cached_page = cached_page.borrow_mut();
                let pre_valid = cached_page.ok[1].clone();
                cached_page.invalidate(addr & (PAGE_ADDR_MASK as u32));
                !pre_valid
            }
        };

        if should_ret {
            return;
        }

        // find the generalized index of the first page covering the address
        let mut generalized_index = (((1<<32 as u64) | (addr as u64)) >> PAGE_ADDR_SIZE) as u32;

        while generalized_index > 0 {
            self.nodes.insert(generalized_index, None);
            generalized_index >>= 1;
        }
    }

    pub fn merklelize_subtree(&mut self, generalized_index: usize) -> [u8; 32] {
        let l = generalized_index.ilog2() as usize;
        if l > 28 {
            panic!("generalized index is too deep");
        }

        let (hash, ok) = match self.nodes.get(&(generalized_index as u32)) {
            None => {
                // the generalized index node is not exist, then zero hash
                (Box::new(ZERO_HASHS[28-l].clone()), true)
            }
            Some(node) => {
                match node {
                    None => {
                        // the generalized index node was invalidated
                        (Box::new([0; 32]), false)
                    }
                    Some(hash) => {
                        // got the generalized index node
                        (hash.clone(), true)
                    }
                }
            }
        };

        if ok {
            return *hash;
        }

        // the generalized index node was invalidated, then re compute
        let left = self.merklelize_subtree(generalized_index<<1);
        let right = self.merklelize_subtree(generalized_index<<1 | 1);
        let hash = hash_pair(&left, &right);
        self.nodes.insert(generalized_index as u32, Some(Box::new(hash)));
        return hash;
    }

    pub fn merkle_root(&mut self) -> [u8; 32] {
        self.merklelize_subtree(1)
    }

    fn traverse_branch(&mut self, parent: u64, addr: u32, depth: u8) -> Vec<[u8; 32]> {
        if depth == 32-5 {
            let mut proof: Vec<[u8; 32]> = Default::default();
            proof.extend([self.merklelize_subtree(parent as usize)]);
            return proof;
        }
        if depth > 32-5 {
            panic!("traversed too deep");
        }
        let mut cur = parent<<1;
        let mut sibling = cur | 1;
        if addr & (1<<(31-depth)) != 0 {
            (cur, sibling) = (sibling, cur);
        }
        let mut proof = self.traverse_branch(cur, addr, depth+1);
        let sibling_node = self.merklelize_subtree(sibling as usize);
        proof.extend([sibling_node]);
        proof
    }

    pub fn merkle_proof(&mut self, addr: u32) -> [u8; 28*32] {
        let proof = self.traverse_branch(1, addr, 0);
        let mut out = [0; 28*32];
        for i in 0..28 {
            out[i*32..(i+1)*32].clone_from_slice(proof[i].as_slice());
        }
        out
    }

    pub fn get_memory(&mut self, addr: u32) -> u32 {
        // addr must be aligned to 4 bytes
        if addr & 0x3 != 0 {
            panic!("unaligned memory access: {:x?}", addr);
        }

        match self.page_lookup(addr >> PAGE_ADDR_SIZE) {
            None => {0u32}
            Some(cached_page) => {
                let cached_page = cached_page.borrow();
                // lookup in page
                let page_addr = (addr as usize) & PAGE_ADDR_MASK;
                u32::from_be_bytes((&cached_page.data[page_addr..page_addr+4]).try_into().unwrap())
            }
        }
    }

    fn alloc_page(&mut self, page_index: u32) -> Rc<RefCell<CachedPage>> {
        let cached_page = Rc::new(
            RefCell::new(
                CachedPage::new()
            )
        );
        self.pages.insert(page_index, cached_page.clone());
        // make nodes to root
        let mut k = (1 << PAGE_KEY_SIZE) | (page_index as u64);
        while k > 0 {
            self.nodes.insert(k as u32, None);
            k >>= 1;
        }
        cached_page
    }

    pub fn set_memory(&mut self, addr: u32, v: u32) {
        // addr must be aligned to 4 bytes
        if addr & 0x3 != 0 {
            panic!("unaligned memory access: {:x?}", addr);
        }

        let page_index = addr >> PAGE_ADDR_SIZE;
        let page_addr = (addr as usize) & PAGE_ADDR_MASK;
        let cached_page = match self.page_lookup(page_index) {
            None => {
                // allocate the page if we have not already
                // Golang may mmap relatively large ranges, but we only allocate just in time.
                self.alloc_page(page_index)
            }
            Some(cached_page) => {
                self.invalidate(addr);
                cached_page
            }
        };
        let mut cached_page = cached_page.borrow_mut();
        cached_page.data[page_addr..page_addr+4].copy_from_slice(&v.to_be_bytes());
    }

    pub fn usage(&self) -> String {
        let total = self.pages.len() * PAGE_SIZE;
        let unit = (1 << 10) as usize;
        if total < unit {
            return format!("{} B", total);
        }

        // KiB, MiB, GiB, TiB, ...
        let (mut div, mut exp) = (unit, 0usize);
        let mut n = total / div;
        while n >= unit {
            div *= unit;
            exp += 1;
            n /= unit;
        }
        let exp_table = b"KMGTPE";
        return format!("{}, {}iB", total/div, exp_table[exp] as char);
    }

    pub fn read_memory_range(&mut self, addr: u32, count: u32) {
        self.addr =  addr;
        self.count = count;
    }

    pub fn set_memory_range<'a>(&mut self, mut addr: u32, mut r: Box<dyn Read+'a>) -> Result<(), std::io::ErrorKind> {
        loop {
            let page_index = addr >> PAGE_ADDR_SIZE;
            let page_addr = addr & (PAGE_ADDR_MASK as u32);
            let cached_page = self.page_lookup(page_index);
            let page = match cached_page {
                None => {
                    self.alloc_page(page_index)
                }
                Some(page) => {
                    page
                }
            };

            let mut page = page.borrow_mut();
            page.invalidate_full();
            let n = r.read(&mut page.data[(page_addr as usize)..]).unwrap();
            if n == 0 {
                return Ok(());
            }
            addr += n as u32;
        }
    }
}

impl Read for Memory {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.count == 0 {
            return Ok(0usize);
        }

        let end_addr = self.addr + self.count;

        let page_index = self.addr >> PAGE_ADDR_SIZE;
        let (start, mut end) = (self.addr & (PAGE_ADDR_MASK as u32), PAGE_SIZE as u32);

        if page_index == (end_addr >> PAGE_ADDR_SIZE) {
            end = end_addr & (PAGE_ADDR_MASK as u32);
        }

        let cached_page = self.page_lookup(page_index);
        let n = match cached_page {
            None => {
                let size = end - start;
                let zero_vec = vec![0; size as usize];
                buf.copy_from_slice(zero_vec.as_slice());
                size
            }
            Some(cached_page) => {
                let page = cached_page.borrow_mut();
                buf.copy_from_slice(&page.data[(start as usize)..(end as usize)]);
                end-start
            }
        };
        self.addr += n;
        self.count -= n;

        Ok(n as usize)
    }
}

