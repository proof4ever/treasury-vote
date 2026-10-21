//! Snapshot download: key block chain walk, persistent state choice,
//! key block proofs, masterchain state, shard block proof links and shard states.

use crate::{
    net::{Network, OverlayClient},
    util::{id_from_json, id_to_json},
};
use anyhow::{anyhow, bail, Context, Result};
use ever_block::{BlockIdExt, Deserializable, ShardStateUnsplit};
use ever_node::block_proof::BlockProofStuff;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Serialize, Deserialize, Clone)]
pub struct ShardEntry {
    pub block_id: serde_json::Value,
    pub proof_file: String,
    pub state_file: String,
    pub state_hash: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Manifest {
    pub key_block: serde_json::Value,
    pub key_block_utime: u32,
    pub prev_key_block: serde_json::Value,
    pub key_block_proof_file: String,
    pub prev_key_block_proof_file: String,
    pub mc_state_file: String,
    pub mc_state_hash: String,
    pub signatures_checked: bool,
    pub shards: Vec<ShardEntry>,
}

impl Manifest {
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join("manifest.json");
        Ok(serde_json::from_slice(&std::fs::read(&path).with_context(|| format!("read {}", path.display()))?)?)
    }
}

/// Walk all key blocks from the zero state (or from the cached tail).
async fn walk_key_blocks(mc: &Arc<OverlayClient>, zero: &BlockIdExt, cache: &Path) -> Result<Vec<BlockIdExt>> {
    let mut list: Vec<BlockIdExt> = if cache.exists() {
        let raw: Vec<serde_json::Value> = serde_json::from_slice(&std::fs::read(cache)?)?;
        raw.iter().map(id_from_json).collect::<Result<_>>()?
    } else {
        vec![zero.clone()]
    };
    if list.first() != Some(zero) {
        bail!("key block cache {} does not start at the zero state", cache.display())
    }
    log::info!("key blocks: starting from seqno {} ({} cached)", list.last().unwrap().seq_no(), list.len() - 1);
    let mut empty_rounds = 0;
    let mut step = 0usize;
    while empty_rounds < 4 {
        let last = list.last().unwrap().clone();
        let peers = mc.random_peers(3);
        if peers.is_empty() {
            mc.find_peers(10).await?;
            continue;
        }
        let answers = futures::future::join_all(peers.iter().map(|p| mc.next_key_block_ids(&last, p))).await;
        let mut best: Vec<BlockIdExt> = Vec::new();
        for answer in answers {
            match answer {
                Ok(ids) => {
                    let mut prev = last.seq_no();
                    let ok = ids.iter().all(|id| {
                        let good = id.shard().is_masterchain() && id.seq_no() > prev;
                        prev = id.seq_no();
                        good
                    });
                    if ok && ids.len() > best.len() {
                        best = ids
                    }
                }
                Err(e) => log::debug!("getNextKeyBlockIds: {e}"),
            }
        }
        if best.is_empty() {
            empty_rounds += 1;
            continue;
        }
        empty_rounds = 0;
        list.extend(best);
        step += 1;
        if step % 25 == 0 {
            log::info!("key blocks: reached seqno {} ({} key blocks)", list.last().unwrap().seq_no(), list.len() - 1);
            save_key_blocks(cache, &list)?;
        }
    }
    save_key_blocks(cache, &list)?;
    log::info!("key blocks: last is {}", list.last().unwrap());
    Ok(list)
}

fn save_key_blocks(cache: &Path, list: &[BlockIdExt]) -> Result<()> {
    let raw: Vec<_> = list.iter().map(id_to_json).collect();
    let tmp = cache.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&raw)?)?;
    std::fs::rename(tmp, cache)?;
    Ok(())
}

fn shard_file_prefix(id: &BlockIdExt) -> String {
    format!("shard_{}_{:016x}_{}", id.shard().workchain_id(), id.shard().shard_prefix_with_tag(), id.seq_no())
}

pub struct DownloadOptions {
    pub global_config: PathBuf,
    pub data_dir: PathBuf,
    pub port: u16,
    /// Own public IPv4 address (detected automatically if not given)
    pub public_ip: Option<std::net::Ipv4Addr>,
    /// Use exactly this key block (seqno) instead of the newest one with a persistent state
    pub key_block_seqno: Option<u32>,
    /// Build the state at this unix time: base key block with gen_utime <= timestamp,
    /// plus all masterchain/shard blocks up to the last masterchain block with gen_utime <= timestamp
    pub timestamp: Option<u32>,
}

/// Returns the snapshot directory.
pub async fn run(opts: DownloadOptions) -> Result<PathBuf> {
    if let Some(ts) = opts.timestamp {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        // the first block after the timestamp must already exist to know the last one before it
        if ts as u64 + 30 > now {
            bail!(
                "timestamp {ts} ({}) is in the future or too recent: now is {} UTC; retry at least 30 s after it",
                chrono::DateTime::from_timestamp(ts as i64, 0).unwrap_or_default().format("%Y-%m-%dT%H:%M:%SZ"),
                chrono::DateTime::from_timestamp(now as i64, 0).unwrap_or_default().format("%Y-%m-%dT%H:%M:%SZ"),
            )
        }
    }
    std::fs::create_dir_all(&opts.data_dir)?;
    if let Some(ts) = opts.timestamp {
        // everything for this timestamp is already on disk: no network needed
        for entry in std::fs::read_dir(&opts.data_dir)?.filter_map(|e| e.ok()) {
            let dir = entry.path();
            let manifest = Manifest::load(&dir);
            let target_ready = crate::blocks::target_dir(&dir, ts).join("target.json").exists();
            let base_ok = manifest.as_ref().map_or(false, |m| {
                opts.key_block_seqno.map_or(true, |s| m.key_block["seqno"].as_u64() == Some(s as u64))
            });
            if base_ok && target_ready {
                log::info!("timestamp {ts}: blocks and proofs are already in {}, skipping the network", dir.display());
                return Ok(dir);
            }
        }
    }
    let net = Network::start(&opts.global_config, opts.port, opts.public_ip).await?;
    let mc = net.overlay_client(-1, 30).await?;

    let key_blocks = walk_key_blocks(&mc, &net.zero_state, &opts.data_dir.join("keyblocks.json")).await?;

    let snapshot_dir = |index: usize| opts.data_dir.join(format!("snapshot_{}", key_blocks[index].seq_no()));

    // With a timestamp every base key block <= timestamp leads to the same state, so a
    // complete local snapshot (newest one <= timestamp) is reused instead of starting a
    // new multi-GB download. Without a timestamp the result is the key block state
    // itself, so the newest available key block is taken.
    let mut chosen = None;
    if let Some(timestamp) = opts.timestamp {
        chosen = (1..key_blocks.len()).rev().find(|&i| {
            opts.key_block_seqno.map_or(true, |s| s == key_blocks[i].seq_no())
                && Manifest::load(&snapshot_dir(i)).map_or(false, |m| m.key_block_utime <= timestamp)
        });
        if let Some(index) = chosen {
            log::info!("reusing local snapshot of key block {}", key_blocks[index].seq_no());
        }
    }

    // otherwise: the newest key block (not newer than the timestamp) whose persistent
    // state is partially downloaded or served by peers
    let proofs_dir = opts.data_dir.join("keyblock_proofs");
    std::fs::create_dir_all(&proofs_dir)?;
    if chosen.is_none() {
        for index in (1..key_blocks.len()).rev().take(60) {
            let id = &key_blocks[index];
            if let Some(seqno) = opts.key_block_seqno {
                if id.seq_no() != seqno {
                    continue;
                }
            }
            if let Some(timestamp) = opts.timestamp {
                let proof = load_or_download_proof(&mc, id, true, &proofs_dir.join(format!("{}.boc", id.seq_no()))).await?;
                let utime = proof.virtualize_block().map_err(|e| anyhow!("{e}"))?.0.read_info().map_err(|e| anyhow!("{e}"))?.gen_utime().as_u32();
                if utime > timestamp {
                    if opts.key_block_seqno.is_some() {
                        bail!("key block {} (gen_utime {utime}) is newer than the timestamp {timestamp}", id.seq_no())
                    }
                    continue;
                }
            }
            let started = snapshot_dir(index).join("key_block_proof.boc").exists();
            if started || !mc.peers_with_state(id, id, 1).await.is_empty() {
                chosen = Some(index);
                break;
            }
            log::info!("key block {} has no persistent state on peers, trying previous", id.seq_no());
            if opts.key_block_seqno.is_some() {
                bail!("key block {} has no persistent state on peers", id.seq_no())
            }
        }
    }
    let index = chosen.ok_or_else(|| anyhow!("no persistent state at or before the timestamp among the latest key blocks"))?;
    let key_block = key_blocks[index].clone();
    let prev_key_block = key_blocks[index - 1].clone();
    log::info!("using key block {key_block}");

    let dir = opts.data_dir.join(format!("snapshot_{}", key_block.seq_no()));
    std::fs::create_dir_all(&dir)?;

    // key block proof, checked against the previous key block proof (validator signatures)
    let kb_proof_file = dir.join("key_block_proof.boc");
    let kb_proof = load_or_download_proof(&mc, &key_block, true, &kb_proof_file).await?;
    let prev_proof_file = dir.join("prev_key_block_proof.boc");
    let mut signatures_checked = false;
    if prev_key_block.seq_no() > 0 {
        let prev_proof = load_or_download_proof(&mc, &prev_key_block, true, &prev_proof_file).await?;
        kb_proof
            .check_with_prev_key_block_proof(&prev_proof)
            .map_err(|e| anyhow!("key block proof signature check failed: {e}"))?;
        signatures_checked = true;
        log::info!("key block proof signatures verified against previous key block {}", prev_key_block.seq_no());
    }
    let (virt_block, _) = kb_proof.virtualize_block().map_err(|e| anyhow!("{e}"))?;
    let utime = virt_block.read_info().map_err(|e| anyhow!("{e}"))?.gen_utime().as_u32();
    let mc_state_hash = virt_block.read_state_update().map_err(|e| anyhow!("{e}"))?.new_hash;

    // masterchain state
    let mc_state_file = dir.join("mc_state.boc");
    if !mc_state_file.exists() {
        mc.download_state(&key_block, &key_block, &dir, &mc_state_file).await?;
    }
    let mc_root = open_checked(&mc_state_file, &mc_state_hash)?;
    let mc_state = ShardStateUnsplit::construct_from_cell(mc_root).map_err(|e| anyhow!("{e}"))?;
    let extra = mc_state.read_custom().map_err(|e| anyhow!("{e}"))?.ok_or_else(|| anyhow!("no McStateExtra"))?;
    let mut top_blocks = Vec::new();
    extra
        .shards()
        .iterate_shards(|ident, descr| {
            top_blocks.push(BlockIdExt::with_params(ident, descr.seq_no, descr.root_hash, descr.file_hash));
            Ok(true)
        })
        .map_err(|e| anyhow!("{e}"))?;
    log::info!("{} shard top blocks: {:?}", top_blocks.len(), top_blocks.iter().map(|b| b.shard().to_string()).collect::<Vec<_>>());

    let mut shard_clients = crate::net::WcClients::new(net.clone());
    let mut shards = Vec::new();
    for block in top_blocks {
        let wc = block.shard().workchain_id();
        let prefix = shard_file_prefix(&block);
        let proof_file = dir.join(format!("{prefix}.proof.boc"));
        let state_file = dir.join(format!("{prefix}.state.boc"));
        let proof = if proof_file.exists() {
            BlockProofStuff::deserialize(&block, std::fs::read(&proof_file)?, true).map_err(|e| anyhow!("{e}"))?
        } else {
            load_or_download_proof(&shard_clients.get(wc).await?, &block, false, &proof_file).await?
        };
        let (shard_block, _) = proof.virtualize_block().map_err(|e| anyhow!("{e}"))?;
        let state_hash = shard_block.read_state_update().map_err(|e| anyhow!("{e}"))?.new_hash;
        if !state_file.exists() {
            shard_clients.get(wc).await?.download_state(&block, &key_block, &dir, &state_file).await?;
        }
        open_checked(&state_file, &state_hash)?;
        shards.push(ShardEntry {
            block_id: id_to_json(&block),
            proof_file: file_name(&proof_file),
            state_file: file_name(&state_file),
            state_hash: state_hash.as_hex_string(),
        });
    }

    let manifest = Manifest {
        key_block: id_to_json(&key_block),
        key_block_utime: utime,
        prev_key_block: id_to_json(&prev_key_block),
        key_block_proof_file: file_name(&kb_proof_file),
        prev_key_block_proof_file: if signatures_checked { file_name(&prev_proof_file) } else { String::new() },
        mc_state_file: file_name(&mc_state_file),
        mc_state_hash: mc_state_hash.as_hex_string(),
        signatures_checked,
        shards,
    };
    std::fs::write(dir.join("manifest.json"), serde_json::to_vec_pretty(&manifest)?)?;
    log::info!("snapshot ready in {}", dir.display());

    if let Some(timestamp) = opts.timestamp {
        let base_shards: Vec<BlockIdExt> = manifest.shards.iter().map(|s| id_from_json(&s.block_id)).collect::<Result<_>>()?;
        let target = crate::blocks::fetch(&mc, &mut shard_clients, &dir, &key_block, utime, &base_shards, &key_blocks, timestamp).await?;
        log::info!(
            "blocks up to masterchain block {} (gen_utime {}) are ready in {}",
            target.block["seqno"],
            target.block_utime,
            crate::blocks::target_dir(&dir, timestamp).display()
        );
    }
    Ok(dir)
}

fn file_name(path: &Path) -> String {
    path.file_name().unwrap().to_string_lossy().into_owned()
}

async fn load_or_download_proof(
    client: &Arc<OverlayClient>,
    block: &BlockIdExt,
    key_block: bool,
    file: &Path,
) -> Result<BlockProofStuff> {
    if file.exists() {
        let proof = BlockProofStuff::deserialize(block, std::fs::read(file)?, !key_block).map_err(|e| anyhow!("{e}"))?;
        return Ok(proof);
    }
    let (proof, data) = client.download_proof(block, key_block).await?;
    std::fs::write(file, data)?;
    Ok(proof)
}

/// Open a downloaded state; a corrupted or mismatching file is removed so the next run downloads it again.
fn open_checked(file: &Path, hash: &ever_block::UInt256) -> Result<ever_block::Cell> {
    match crate::lazyboc::open_state(file, Some(hash)) {
        Ok(root) => Ok(root),
        Err(e) => {
            let _ = std::fs::remove_file(file);
            let _ = std::fs::remove_file(file.with_extension("lazyidx"));
            let _ = std::fs::remove_file(file.with_extension("lazyidx.tmp"));
            bail!("{} is invalid and was removed, rerun to download it again: {e}", file.display())
        }
    }
}
