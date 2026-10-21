//! Masterchain/shard blocks between the base key block and a timestamp.
//!
//! Blocks come from node archive packages (`tonNode.getArchiveSlice`: 100
//! masterchain blocks with their shard blocks and proofs per package) and, for the
//! tail that is not archived yet, one by one (`tonNode.downloadNextBlockFull`).
//! Everything is cached in `<snapshot>/blocks/*.pack` in the node's package format,
//! so the state at the timestamp can be rebuilt offline any number of times.
//!
//! The state after block N is the base state with the `state_update` Merkle
//! updates of all following blocks applied (no transaction execution). Each
//! update checks the old state hash and produces the new one, and every block is
//! linked to its predecessor through `prev_ref`, so the final state is bound to
//! the signed proof of masterchain block N.

use crate::{
    net::{FullBlock, OverlayClient},
    util::{id_from_json, id_to_json},
};
use anyhow::{anyhow, bail, ensure, Context, Result};
use ever_block::{BlockIdExt, Cell, ShardIdent, UInt256};
use ever_node::block::BlockStuff;
use memmap2::Mmap;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

const PKG_MAGIC: u32 = 0xAE8F_DD01;
const ENTRY_MAGIC: u16 = 0x1E8B;

#[derive(Clone, Copy)]
struct Loc {
    file: usize,
    offset: usize,
    len: usize,
}

/// Index over all cached packages.
pub struct BlockStore {
    dir: PathBuf,
    files: Vec<(PathBuf, Mmap)>,
    blocks: HashMap<BlockIdExt, Loc>,
    proofs: HashMap<BlockIdExt, (Loc, bool)>, // (location, is_link)
    mc: BTreeMap<u32, BlockIdExt>,
}

fn parse_entry_name(name: &str) -> Option<(&'static str, BlockIdExt)> {
    let (kind, rest) = if let Some(r) = name.strip_prefix("prooflink_") {
        ("prooflink", r)
    } else if let Some(r) = name.strip_prefix("proof_") {
        ("proof", r)
    } else if let Some(r) = name.strip_prefix("block_") {
        ("block", r)
    } else {
        return None;
    };
    // (wc,shard,seqno):ROOT:FILE
    let rest = rest.strip_prefix('(')?;
    let (head, hashes) = rest.split_once(')')?;
    let mut parts = head.split(',');
    let wc: i32 = parts.next()?.parse().ok()?;
    let shard = u64::from_str_radix(parts.next()?, 16).ok()?;
    let seqno: u32 = parts.next()?.parse().ok()?;
    let mut hashes = hashes.strip_prefix(':')?.split(':');
    let root = UInt256::from_str(&hashes.next()?.to_lowercase()).ok()?;
    let file = UInt256::from_str(&hashes.next()?.to_lowercase()).ok()?;
    let shard = ShardIdent::with_tagged_prefix(wc, shard).ok()?;
    Some((kind, BlockIdExt::with_params(shard, seqno, root, file)))
}

fn entry_name(kind: &str, id: &BlockIdExt) -> String {
    format!(
        "{kind}_({},{:016x},{}):{:064X}:{:064X}",
        id.shard().workchain_id(),
        id.shard().shard_prefix_with_tag(),
        id.seq_no(),
        id.root_hash(),
        id.file_hash()
    )
}

impl BlockStore {
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let mut store =
            Self { dir: dir.to_path_buf(), files: vec![], blocks: HashMap::new(), proofs: HashMap::new(), mc: BTreeMap::new() };
        let mut paths: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map(|e| e == "pack").unwrap_or(false))
            .collect();
        paths.sort();
        for path in paths {
            store.add_file(&path)?;
        }
        Ok(store)
    }

    /// Index a new package file, or re-index everything if it was indexed before
    /// (`extra.pack` grows in place).
    fn add_file(&mut self, path: &Path) -> Result<()> {
        if self.files.iter().any(|(p, _)| p == path) {
            let paths: Vec<PathBuf> = self.files.drain(..).map(|(p, _)| p).collect();
            self.blocks.clear();
            self.proofs.clear();
            self.mc.clear();
            for p in paths {
                self.map_and_index(&p)?;
            }
            return Ok(());
        }
        self.map_and_index(path)
    }

    fn map_and_index(&mut self, path: &Path) -> Result<()> {
        let map = unsafe { Mmap::map(&std::fs::File::open(path)?)? };
        let file = self.files.len();
        Self::index(&map, file, &mut self.blocks, &mut self.proofs, &mut self.mc)
            .with_context(|| format!("bad package {}", path.display()))?;
        self.files.push((path.to_path_buf(), map));
        Ok(())
    }

    fn index(
        data: &[u8],
        file: usize,
        blocks: &mut HashMap<BlockIdExt, Loc>,
        proofs: &mut HashMap<BlockIdExt, (Loc, bool)>,
        mc: &mut BTreeMap<u32, BlockIdExt>,
    ) -> Result<()> {
        ensure!(data.len() >= 4 && u32::from_le_bytes(data[..4].try_into()?) == PKG_MAGIC, "not a package");
        let mut pos = 4;
        while pos < data.len() {
            ensure!(pos + 8 <= data.len(), "truncated entry header");
            ensure!(u16::from_le_bytes(data[pos..pos + 2].try_into()?) == ENTRY_MAGIC, "bad entry magic");
            let name_len = u16::from_le_bytes(data[pos + 2..pos + 4].try_into()?) as usize;
            let data_len = u32::from_le_bytes(data[pos + 4..pos + 8].try_into()?) as usize;
            let name = std::str::from_utf8(&data[pos + 8..pos + 8 + name_len])?;
            let loc = Loc { file, offset: pos + 8 + name_len, len: data_len };
            ensure!(loc.offset + loc.len <= data.len(), "truncated entry {name}");
            if let Some((kind, id)) = parse_entry_name(name) {
                if id.shard().is_masterchain() {
                    mc.insert(id.seq_no(), id.clone());
                }
                match kind {
                    "block" => {
                        blocks.insert(id, loc);
                    }
                    "proof" => {
                        proofs.entry(id).or_insert((loc, false));
                    }
                    _ => {
                        proofs.entry(id).or_insert((loc, true));
                    }
                }
            }
            pos = loc.offset + loc.len;
        }
        Ok(())
    }

    fn bytes(&self, loc: Loc) -> &[u8] {
        &self.files[loc.file].1[loc.offset..loc.offset + loc.len]
    }

    pub fn mc_id(&self, seqno: u32) -> Option<&BlockIdExt> {
        self.mc.get(&seqno).filter(|id| self.blocks.contains_key(*id))
    }

    pub fn block(&self, id: &BlockIdExt) -> Result<Option<BlockStuff>> {
        match self.blocks.get(id) {
            Some(loc) => Ok(Some(
                BlockStuff::deserialize_block_checked(id.clone(), self.bytes(*loc).to_vec()).map_err(|e| anyhow!("{e}"))?,
            )),
            None => Ok(None),
        }
    }

    pub fn proof(&self, id: &BlockIdExt) -> Option<(Vec<u8>, bool)> {
        self.proofs.get(id).map(|(loc, link)| (self.bytes(*loc).to_vec(), *link))
    }

    fn save_package(&mut self, name: &str, data: &[u8]) -> Result<()> {
        let path = self.dir.join(name);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, data)?;
        std::fs::rename(&tmp, &path)?;
        self.add_file(&path)
    }

    /// Append a separately downloaded block to `extra.pack`.
    fn save_full_block(&mut self, full: &FullBlock) -> Result<()> {
        let path = self.dir.join("extra.pack");
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
        if file.metadata()?.len() == 0 {
            file.write_all(&PKG_MAGIC.to_le_bytes())?;
        }
        let proof_kind = if full.is_link { "prooflink" } else { "proof" };
        for (kind, data) in [("block", &full.block), (proof_kind, &full.proof)] {
            let name = entry_name(kind, &full.id);
            file.write_all(&ENTRY_MAGIC.to_le_bytes())?;
            file.write_all(&(name.len() as u16).to_le_bytes())?;
            file.write_all(&(data.len() as u32).to_le_bytes())?;
            file.write_all(name.as_bytes())?;
            file.write_all(data)?;
        }
        file.sync_all()?;
        drop(file);
        self.add_file(&path)
    }

    fn save_proof(&mut self, id: &BlockIdExt, data: &[u8], is_link: bool) -> Result<()> {
        let path = self.dir.join("extra.pack");
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
        if file.metadata()?.len() == 0 {
            file.write_all(&PKG_MAGIC.to_le_bytes())?;
        }
        let name = entry_name(if is_link { "prooflink" } else { "proof" }, id);
        file.write_all(&ENTRY_MAGIC.to_le_bytes())?;
        file.write_all(&(name.len() as u16).to_le_bytes())?;
        file.write_all(&(data.len() as u32).to_le_bytes())?;
        file.write_all(name.as_bytes())?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        self.add_file(&path)
    }
}

/// What `fetch` found for a timestamp; saved as `<snapshot>/target_<ts>/target.json`.
#[derive(Serialize, Deserialize, Clone)]
pub struct Target {
    pub timestamp: u32,
    pub base_key_block: serde_json::Value,
    /// last masterchain block with gen_utime <= timestamp
    pub block: serde_json::Value,
    pub block_utime: u32,
    /// the next masterchain block (gen_utime > timestamp), evidence that `block` is the last one
    pub next_block: serde_json::Value,
    pub next_block_utime: u32,
    pub prev_key_block: serde_json::Value,
    pub applied_mc_blocks: u32,
    pub shards: Vec<TargetShard>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TargetShard {
    pub base_block: serde_json::Value,
    pub top_block: serde_json::Value,
    pub applied_blocks: u32,
}

pub fn target_dir(snapshot: &Path, timestamp: u32) -> PathBuf {
    snapshot.join(format!("target_{timestamp}"))
}

impl Target {
    pub fn load(snapshot: &Path, timestamp: u32) -> Result<Self> {
        let path = target_dir(snapshot, timestamp).join("target.json");
        Ok(serde_json::from_slice(
            &std::fs::read(&path).with_context(|| format!("{} not found, run download --timestamp first", path.display()))?,
        )?)
    }
}

fn prev_of(block: &BlockStuff) -> Result<BlockIdExt> {
    let (prev, prev2) = block.construct_prev_id().map_err(|e| anyhow!("{e}"))?;
    if prev2.is_some() {
        bail!("block {} is a shard merge; splits/merges between the key block and the timestamp are not supported", block.id())
    }
    Ok(prev)
}

fn utime(block: &BlockStuff) -> Result<u32> {
    block.gen_utime().map_err(|e| anyhow!("{e}"))
}

/// Download (or reuse cached) blocks up to `timestamp` and write the target files.
pub async fn fetch(
    mc_client: &Arc<OverlayClient>,
    wc_clients: &mut crate::net::WcClients,
    snapshot: &Path,
    base: &BlockIdExt,
    base_utime: u32,
    base_shards: &[BlockIdExt],
    key_blocks: &[BlockIdExt],
    timestamp: u32,
) -> Result<Target> {
    ensure!(base_utime <= timestamp, "the base key block ({base_utime}) is newer than the timestamp {timestamp}");
    let mut store = BlockStore::open(&snapshot.join("blocks"))?;

    // masterchain: walk forward from the key block until gen_utime > timestamp
    let mut prev = base.clone();
    let mut prev_utime = base_utime;
    let next = loop {
        let seqno = prev.seq_no() + 1;
        if store.mc_id(seqno).is_none() {
            // estimate how many packages are still needed (~3 s per masterchain block)
            let left = (timestamp.saturating_sub(prev_utime) / 3 / 100 + 1).min(12);
            let mut tasks = Vec::new();
            for i in 0..left.max(1) {
                let (client, s) = (mc_client.clone(), seqno + i * 100);
                tasks.push(tokio::spawn(async move { (s, client.download_archive(s).await) }));
            }
            for task in tasks {
                let (s, result) = task.await?;
                match result {
                    Ok(Some(data)) => store.save_package(&format!("pkg_{s:010}.pack"), &data)?,
                    Ok(None) => log::info!("no archive package for mc block {s} yet"),
                    // fall back to block-by-block download below
                    Err(e) => log::warn!("archive package for mc block {s} failed: {e}"),
                }
            }
            if store.mc_id(seqno).is_none() {
                // not archived yet (recent blocks): one by one
                let full = mc_client.download_next_block_full(&prev).await.map_err(|e| {
                    anyhow!("no masterchain block after {} (gen_utime {prev_utime}) yet, the timestamp {timestamp} is not reached: {e}", prev.seq_no())
                })?;
                ensure!(full.id.seq_no() == seqno && full.id.shard().is_masterchain(), "unexpected next block {}", full.id);
                store.save_full_block(&full)?;
            }
            log::info!("masterchain blocks cached up to {}", store.mc.keys().next_back().copied().unwrap_or(0));
        }
        let id = store.mc_id(seqno).cloned().ok_or_else(|| anyhow!("masterchain block {seqno} is missing"))?;
        let block = store.block(&id)?.unwrap();
        ensure!(prev_of(&block)? == prev, "masterchain block {id} does not follow {prev}");
        let t = utime(&block)?;
        if t > timestamp {
            break (id, t);
        }
        prev = id;
        prev_utime = t;
    };
    let target = prev;
    let applied_mc_blocks = target.seq_no() - base.seq_no();
    log::info!(
        "timestamp {timestamp}: last masterchain block {} (gen_utime {}), next one {} has {}",
        target.seq_no(),
        prev_utime,
        next.0.seq_no(),
        next.1
    );

    let dir = target_dir(snapshot, timestamp);
    std::fs::create_dir_all(&dir)?;

    // signed proof of the target masterchain block
    let target_block = if target == *base { None } else { Some(store.block(&target)?.unwrap()) };
    let prev_key_seqno = match &target_block {
        Some(b) => b.block().map_err(|e| anyhow!("{e}"))?.read_info().map_err(|e| anyhow!("{e}"))?.prev_key_block_seqno(),
        None => 0,
    };
    let mc_proof = match store.proof(&target) {
        Some((data, false)) => data,
        _ => {
            let info_is_key = target_block
                .as_ref()
                .map(|b| b.block().and_then(|b| b.read_info()).map(|i| i.key_block()).unwrap_or(false))
                .unwrap_or(true);
            let (_, data) = if info_is_key {
                mc_client.download_proof(&target, true).await?
            } else {
                mc_client.download_mc_proof(&target).await?
            };
            store.save_proof(&target, &data, false)?;
            data
        }
    };
    std::fs::write(dir.join("mc_block.proof.boc"), &mc_proof)?;

    // shard chains: from the top blocks of the target back to the base top blocks
    let top_blocks = match &target_block {
        Some(b) => b.top_blocks_all().map_err(|e| anyhow!("{e}"))?,
        None => base_shards.to_vec(),
    };
    let mut shards = Vec::new();
    for top in top_blocks {
        let base_top = base_shards
            .iter()
            .find(|b| b.shard() == top.shard())
            .ok_or_else(|| anyhow!("shard {} changed (split/merge) since the key block; not supported", top.shard()))?
            .clone();
        let wc = top.shard().workchain_id();
        let mut cur = top.clone();
        let mut count = 0u32;
        while cur != base_top {
            ensure!(cur.seq_no() > base_top.seq_no(), "shard chain {} does not lead back to {}", top, base_top);
            let block = match store.block(&cur)? {
                Some(b) => b,
                None => {
                    let full = wc_clients.get(wc).await?.download_block_full(&cur).await?;
                    store.save_full_block(&full)?;
                    store.block(&cur)?.unwrap()
                }
            };
            cur = prev_of(&block)?;
            count += 1;
            if count % 5000 == 0 {
                log::info!("shard {}: {count} blocks back, at seqno {}", top.shard(), cur.seq_no());
            }
        }
        let link = match store.proof(&top) {
            Some((data, true)) => data,
            _ => {
                let (_, data) = wc_clients.get(wc).await?.download_proof(&top, false).await?;
                store.save_proof(&top, &data, true)?;
                data
            }
        };
        std::fs::write(dir.join(shard_link_file(&top)), &link)?;
        shards.push(TargetShard { base_block: id_to_json(&base_top), top_block: id_to_json(&top), applied_blocks: count });
    }

    // previous key block proof: its validator set signed the target block
    let prev_key = if target == *base {
        let pos = key_blocks.iter().position(|k| k == base).ok_or_else(|| anyhow!("base not in key blocks"))?;
        key_blocks[pos - 1].clone()
    } else {
        key_blocks
            .iter()
            .find(|k| k.seq_no() == prev_key_seqno)
            .cloned()
            .ok_or_else(|| anyhow!("previous key block {prev_key_seqno} not in key block list"))?
    };
    let prev_key_file = dir.join("prev_key_block.proof.boc");
    if !prev_key_file.exists() {
        let (_, data) = mc_client.download_proof(&prev_key, true).await?;
        std::fs::write(&prev_key_file, data)?;
    }

    let target = Target {
        timestamp,
        base_key_block: id_to_json(base),
        block: id_to_json(&target),
        block_utime: prev_utime,
        next_block: id_to_json(&next.0),
        next_block_utime: next.1,
        prev_key_block: id_to_json(&prev_key),
        applied_mc_blocks,
        shards,
    };
    std::fs::write(dir.join("target.json"), serde_json::to_vec_pretty(&target)?)?;
    Ok(target)
}

pub fn shard_link_file(top: &BlockIdExt) -> String {
    format!("shard_{}_{:016x}_{}.prooflink.boc", top.shard().workchain_id(), top.shard().shard_prefix_with_tag(), top.seq_no())
}

/// Apply all cached blocks of `target` on top of the base states (offline).
pub fn apply(snapshot: &Path, target: &Target, mc_root: Cell, shard_roots: Vec<(BlockIdExt, Cell)>) -> Result<(Cell, Vec<Cell>)> {
    let store = BlockStore::open(&snapshot.join("blocks"))?;
    let e = |e: ever_block::Error| anyhow!("{e}");

    let base = id_from_json(&target.base_key_block)?;
    let block_id = id_from_json(&target.block)?;
    let mut root = mc_root;
    let mut prev = base.clone();
    let started = std::time::Instant::now();
    for seqno in base.seq_no() + 1..=block_id.seq_no() {
        let id = store.mc_id(seqno).ok_or_else(|| anyhow!("masterchain block {seqno} is not cached"))?.clone();
        let block = store.block(&id)?.unwrap();
        ensure!(prev_of(&block)? == prev, "masterchain block {id} does not follow {prev}");
        root = block.block().map_err(e)?.read_state_update().map_err(e)?.apply_for(&root).map_err(e)?;
        prev = id;
        if (seqno - base.seq_no()) % 2000 == 0 {
            log::info!("masterchain: applied {} / {} blocks", seqno - base.seq_no(), target.applied_mc_blocks);
        }
    }
    ensure!(prev == block_id, "masterchain chain ended at {prev}, expected {block_id}");
    log::info!("masterchain state at {} rebuilt in {:?}", block_id.seq_no(), started.elapsed());

    let mut out = Vec::new();
    for shard in &target.shards {
        let base_top = id_from_json(&shard.base_block)?;
        let top = id_from_json(&shard.top_block)?;
        let (_, mut root) = shard_roots
            .iter()
            .find(|(id, _)| id == &base_top)
            .cloned()
            .ok_or_else(|| anyhow!("no base state for {base_top}"))?;
        // collect the chain backwards, then apply forwards
        let mut chain = Vec::new();
        let mut cur = top.clone();
        while cur != base_top {
            let block = store.block(&cur)?.ok_or_else(|| anyhow!("shard block {cur} is not cached"))?;
            let prev = prev_of(&block)?;
            chain.push(cur);
            cur = prev;
        }
        let started = std::time::Instant::now();
        for (n, id) in chain.iter().rev().enumerate() {
            let block = store.block(id)?.unwrap();
            root = block.block().map_err(e)?.read_state_update().map_err(e)?.apply_for(&root).map_err(e)?;
            if (n + 1) % 2000 == 0 {
                log::info!("shard {}: applied {} / {} blocks", top.shard(), n + 1, chain.len());
            }
        }
        log::info!("shard {} state at {} rebuilt in {:?}", top.shard(), top.seq_no(), started.elapsed());
        out.push(root);
    }
    Ok((root, out))
}
