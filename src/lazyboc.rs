//! Lazy, memory-mapped reader for huge single-root BOCs (persistent states).
//!
//! `BocReader::read_inmem` materialises every cell. The masterchain persistent state
//! alone holds >100M cells (mostly `prev_blocks`), which does not fit in RAM.
//! Here one streaming pass computes the hash and depth of every cell (children
//! always have larger indexes, so cells are processed from the end) and stores them
//! with the cell offsets in a sidecar file `<boc>.lazyidx`. After that cells are
//! served straight from the mmapped BOC on demand, so only the touched part of the
//! state is ever read.

use anyhow::{anyhow, bail, ensure, Context, Result};
use ever_block::{Cell, CellImpl, CellType, LevelMask, UInt256};
use memmap2::{Mmap, MmapMut};
use sha2::{Digest, Sha256};
use std::{fs::OpenOptions, path::Path, sync::Arc};

const IDX_MAGIC: &[u8; 8] = b"LZBIDX01";
const IDX_HEADER: usize = 8 + 8 + 8;
const ENTRY: usize = 8 + 32 + 2; // offset, hash, depth

pub struct LazyBoc {
    boc: Mmap,
    idx: Mmap,
    #[allow(dead_code)]
    cells: usize,
    root: usize,
    ref_size: usize,
}

struct Header {
    ref_size: usize,
    cells: usize,
    root: usize,
    data_start: usize,
}

fn read_be(buf: &[u8], pos: &mut usize, size: usize) -> Result<usize> {
    ensure!(*pos + size <= buf.len(), "BOC header is truncated");
    let mut v = 0usize;
    for b in &buf[*pos..*pos + size] {
        v = (v << 8) | *b as usize;
    }
    *pos += size;
    Ok(v)
}

fn parse_header(buf: &[u8]) -> Result<Header> {
    ensure!(buf.len() > 6 && buf[..4] == [0xb5, 0xee, 0x9c, 0x72], "unsupported BOC magic");
    let flags = buf[4];
    let has_idx = flags & 0x80 != 0;
    let ref_size = (flags & 7) as usize;
    let off_size = buf[5] as usize;
    let mut pos = 6;
    let cells = read_be(buf, &mut pos, ref_size)?;
    let roots = read_be(buf, &mut pos, ref_size)?;
    let _absent = read_be(buf, &mut pos, ref_size)?;
    let _total = read_be(buf, &mut pos, off_size)?;
    ensure!(roots == 1, "expected a single-root BOC, got {roots} roots");
    let root = read_be(buf, &mut pos, ref_size)?;
    if has_idx {
        pos += cells * off_size;
    }
    Ok(Header { ref_size, cells, root, data_start: pos })
}

impl LazyBoc {
    /// Open `path`, building the sidecar index on first use.
    pub fn open(path: &Path) -> Result<Arc<Self>> {
        let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        let boc = unsafe { Mmap::map(&file)? };
        let header = parse_header(&boc)?;
        let idx_path = path.with_extension("lazyidx");
        let expected_len = IDX_HEADER + header.cells * ENTRY;
        let fresh = std::fs::metadata(&idx_path).map(|m| m.len() as usize != expected_len).unwrap_or(true);
        if fresh {
            Self::build_index(&boc, &header, &idx_path, expected_len)?;
        }
        let idx = unsafe { Mmap::map(&std::fs::File::open(&idx_path)?)? };
        ensure!(&idx[..8] == IDX_MAGIC, "bad index file {}", idx_path.display());
        Ok(Arc::new(Self { boc, idx, cells: header.cells, root: header.root, ref_size: header.ref_size }))
    }

    fn build_index(boc: &[u8], header: &Header, idx_path: &Path, len: usize) -> Result<()> {
        log::info!("indexing {} cells (one-time, writes {} MiB)", header.cells, len >> 20);
        let tmp = idx_path.with_extension("lazyidx.tmp");
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&tmp)?;
        file.set_len(len as u64)?;
        let mut idx = unsafe { MmapMut::map_mut(&file)? };
        let entry = |i: usize| IDX_HEADER + i * ENTRY;

        // pass 1: offsets
        let mut pos = header.data_start;
        for i in 0..header.cells {
            ensure!(pos + 2 <= boc.len(), "BOC is truncated at cell {i}");
            let (d1, d2) = (boc[pos], boc[pos + 1]);
            ensure!(d1 != 13, "big cells are not supported (cell {i} at {pos})");
            ensure!(d1 & 16 == 0 || d1 >> 5 == 0, "cells with stored hashes of level > 0 are not supported (cell {i} at {pos}, d1 {d1:#x})");
            let data_len = (d2 >> 1) as usize + (d2 & 1) as usize;
            let hashes = if d1 & 16 != 0 { 34 } else { 0 };
            idx[entry(i)..entry(i) + 8].copy_from_slice(&(pos as u64).to_le_bytes());
            pos += 2 + hashes + data_len + (d1 & 7) as usize * header.ref_size;
            if i % 20_000_000 == 0 && i > 0 {
                log::info!("indexing: {i} cells");
            }
        }
        // pass 2: hashes and depths, children first
        for i in (0..header.cells).rev() {
            let off = u64::from_le_bytes(idx[entry(i)..entry(i) + 8].try_into()?) as usize;
            let (d1, d2) = (boc[off], boc[off + 1]);
            ensure!(d1 >> 5 == 0, "cell {i} has a non-zero level (pruned/merkle cells are not expected in a state)");
            let data_len = (d2 >> 1) as usize + (d2 & 1) as usize;
            let skip = if d1 & 16 != 0 { 34 } else { 0 };
            let data = &boc[off + 2 + skip..off + 2 + skip + data_len];
            let refs_pos = off + 2 + skip + data_len;
            let refs = (d1 & 7) as usize;
            let mut hasher = Sha256::new();
            hasher.update([d1 & !16, d2]);
            hasher.update(data);
            let mut children = [0usize; 4];
            let mut depth = 0u16;
            for r in 0..refs {
                let mut p = refs_pos + r * header.ref_size;
                let child = read_be(boc, &mut p, header.ref_size)?;
                ensure!(child > i && child < header.cells, "cell {i} has bad reference {child}");
                children[r] = child;
                let child_depth = u16::from_le_bytes(idx[entry(child) + 40..entry(child) + 42].try_into()?);
                depth = depth.max(child_depth + 1);
                hasher.update(child_depth.to_be_bytes());
            }
            for child in &children[..refs] {
                hasher.update(&idx[entry(*child) + 8..entry(*child) + 40]);
            }
            let hash = hasher.finalize();
            let e = entry(i);
            idx[e + 8..e + 40].copy_from_slice(&hash);
            idx[e + 40..e + 42].copy_from_slice(&depth.to_le_bytes());
            if i % 20_000_000 == 0 && i > 0 {
                log::info!("hashing: {} cells left", i);
            }
        }
        idx[..8].copy_from_slice(IDX_MAGIC);
        idx[8..16].copy_from_slice(&(header.cells as u64).to_le_bytes());
        idx[16..24].copy_from_slice(&(header.root as u64).to_le_bytes());
        idx.flush()?;
        drop(idx);
        std::fs::rename(tmp, idx_path)?;
        Ok(())
    }

    fn entry(&self, i: usize) -> usize {
        IDX_HEADER + i * ENTRY
    }

    fn offset(&self, i: usize) -> usize {
        let e = self.entry(i);
        u64::from_le_bytes(self.idx[e..e + 8].try_into().unwrap()) as usize
    }

    fn hash_of(&self, i: usize) -> UInt256 {
        let e = self.entry(i);
        UInt256::from_slice(&self.idx[e + 8..e + 40])
    }

    fn depth_of(&self, i: usize) -> u16 {
        let e = self.entry(i);
        u16::from_le_bytes(self.idx[e + 40..e + 42].try_into().unwrap())
    }

    pub fn root_hash(&self) -> UInt256 {
        self.hash_of(self.root)
    }

    pub fn root(self: &Arc<Self>) -> Cell {
        LazyCell::make(self.clone(), self.root)
    }
}

struct LazyCell {
    boc: Arc<LazyBoc>,
    index: usize,
    data_start: usize,
    data_len: usize,
    refs: usize,
    cell_type: CellType,
}

impl LazyCell {
    fn make(boc: Arc<LazyBoc>, index: usize) -> Cell {
        let off = boc.offset(index);
        let (d1, d2) = (boc.boc[off], boc.boc[off + 1]);
        let data_len = (d2 >> 1) as usize + (d2 & 1) as usize;
        let data_start = off + 2 + if d1 & 16 != 0 { 34 } else { 0 };
        let cell_type = if d1 & 8 != 0 {
            CellType::try_from(boc.boc[data_start]).unwrap_or(CellType::Unknown)
        } else {
            CellType::Ordinary
        };
        Cell::with_cell_impl(LazyCell { boc, index, data_start, data_len, refs: (d1 & 7) as usize, cell_type })
    }

    fn child_index(&self, i: usize) -> Result<usize> {
        if i >= self.refs {
            bail!("reference {i} out of range")
        }
        let mut p = self.data_start + self.data_len + i * self.boc.ref_size;
        read_be(&self.boc.boc, &mut p, self.boc.ref_size)
    }
}

impl CellImpl for LazyCell {
    fn data(&self) -> &[u8] {
        &self.boc.boc[self.data_start..self.data_start + self.data_len]
    }

    fn raw_data(&self) -> ever_block::Result<&[u8]> {
        ever_block::fail!("lazy cell doesn't support raw_data()")
    }

    fn bit_length(&self) -> usize {
        let off = self.boc.offset(self.index);
        let d2 = self.boc.boc[off + 1];
        if d2 & 1 == 0 {
            self.data_len * 8
        } else {
            ever_block::find_tag(self.data())
        }
    }

    fn references_count(&self) -> usize {
        self.refs
    }

    fn reference(&self, index: usize) -> ever_block::Result<Cell> {
        let child = self.child_index(index).map_err(|e| ever_block::error!("{}", e))?;
        Ok(LazyCell::make(self.boc.clone(), child))
    }

    fn reference_repr_hash(&self, index: usize) -> ever_block::Result<UInt256> {
        let child = self.child_index(index).map_err(|e| ever_block::error!("{}", e))?;
        Ok(self.boc.hash_of(child))
    }

    fn reference_repr_depth(&self, index: usize) -> ever_block::Result<u16> {
        let child = self.child_index(index).map_err(|e| ever_block::error!("{}", e))?;
        Ok(self.boc.depth_of(child))
    }

    fn cell_type(&self) -> CellType {
        self.cell_type
    }

    fn level_mask(&self) -> LevelMask {
        LevelMask::with_mask(0)
    }

    fn hash(&self, _index: usize) -> UInt256 {
        self.boc.hash_of(self.index)
    }

    fn depth(&self, _index: usize) -> u16 {
        self.boc.depth_of(self.index)
    }

    fn store_hashes(&self) -> bool {
        false
    }
}

/// Open a state BOC lazily and check its root hash.
pub fn open_state(path: &Path, expected: Option<&UInt256>) -> Result<Cell> {
    let boc = LazyBoc::open(path)?;
    if let Some(expected) = expected {
        if &boc.root_hash() != expected {
            return Err(anyhow!(
                "state {} hash mismatch: {:x} != {:x}",
                path.display(),
                boc.root_hash(),
                expected
            ));
        }
    }
    Ok(boc.root())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ever_block::{write_boc, BuilderData, IBitstring};

    fn tree(depth: u32, seed: &mut u64) -> Cell {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let mut b = BuilderData::new();
        let bits = (*seed >> 33) as usize % 900 + 1;
        for i in 0..bits {
            b.append_bit_bool((*seed >> (i % 64)) & 1 == 1).unwrap();
        }
        if depth > 0 {
            for _ in 0..(*seed % 5) as usize {
                b.checked_append_reference(tree(depth - 1, seed)).unwrap();
            }
        }
        b.into_cell().unwrap()
    }

    fn same(a: &Cell, b: &Cell) {
        assert_eq!(a.repr_hash(), b.repr_hash());
        assert_eq!(a.data(), b.data());
        assert_eq!(a.bit_length(), b.bit_length());
        assert_eq!(a.references_count(), b.references_count());
        for i in 0..a.references_count() {
            assert_eq!(a.reference(i).unwrap().repr_hash(), b.reference_repr_hash(i).unwrap());
            same(&a.reference(i).unwrap(), &b.reference(i).unwrap());
        }
    }

    #[test]
    fn lazy_boc_matches_in_memory() {
        let dir = std::env::temp_dir().join(format!("lazyboc_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut seed = 7;
        let root = tree(6, &mut seed);
        let path = dir.join("state.boc");
        std::fs::write(&path, write_boc(&root).unwrap()).unwrap();
        let lazy = open_state(&path, Some(&root.repr_hash())).unwrap();
        same(&root, &lazy);
        // reopening uses the cached index
        let lazy = open_state(&path, Some(&root.repr_hash())).unwrap();
        assert_eq!(lazy.repr_hash(), root.repr_hash());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
