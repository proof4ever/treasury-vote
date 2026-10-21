//! One-file proof bundle.
//!
//! Layout of the root cell (single-root BOC `proof.boc`):
//!
//! ```text
//! bundle#5e7a7e01 version:uint8
//!   block_proof:^BlockProof              // masterchain block (key block or the last block <= timestamp), with signatures
//!   prev_key_block_proof:^(BlockProof or empty cell)  // previous key block: its validator set signed the block
//!   mc_state_proof:^MerkleProof          // pruned masterchain state of the key block
//!   shards:^ShardList                    // empty cell if there are no shards
//! = Bundle;
//! shard_item$_ block_proof_link:^BlockProof state_proof:^MerkleProof next:(Maybe as optional 3rd ref) = ShardList;
//! ```
//!
//! Hash chain checked by `verify`:
//! masterchain block id (signed) -> state_update.new_hash == mc_state_proof.hash
//! -> mc state shard_hashes contain every shard top block id == block_proof_link.proof_for
//! -> shard block state_update.new_hash == state_proof.hash.

use crate::{
    analyze::{compute, Computed, DePoolRef, StateView},
    util::{load_address_lists, Abis},
};
use anyhow::{anyhow, bail, ensure, Context, Result};
use ever_block::{
    read_single_root_boc, write_boc, BlockIdExt, BlockProof, BuilderData, Cell, Deserializable, IBitstring,
    MerkleProof, Serializable, SliceData,
};
use ever_node::block_proof::BlockProofStuff;
use std::path::Path;

const MAGIC: u32 = 0x5e7a7e01;
const VERSION: u8 = 1;

pub struct ShardPart {
    pub block_proof_link_boc: Vec<u8>,
    pub state_proof: MerkleProof,
}

pub fn build_bundle(
    key_block_proof_boc: &[u8],
    prev_key_block_proof_boc: Option<&[u8]>,
    mc_state_proof: &MerkleProof,
    shards: &[ShardPart],
) -> Result<Cell> {
    let e = |e: ever_block::Error| anyhow!("{e}");
    let mut next: Option<Cell> = None;
    for shard in shards.iter().rev() {
        let mut b = BuilderData::new();
        b.checked_append_reference(read_single_root_boc(&shard.block_proof_link_boc).map_err(e)?).map_err(e)?;
        b.checked_append_reference(shard.state_proof.serialize().map_err(e)?).map_err(e)?;
        if let Some(n) = next.take() {
            b.checked_append_reference(n).map_err(e)?;
        }
        next = Some(b.into_cell().map_err(e)?);
    }
    let mut root = BuilderData::new();
    root.append_u32(MAGIC).map_err(e)?;
    root.append_u8(VERSION).map_err(e)?;
    root.checked_append_reference(read_single_root_boc(key_block_proof_boc).map_err(e)?).map_err(e)?;
    root.checked_append_reference(match prev_key_block_proof_boc {
        Some(boc) => read_single_root_boc(boc).map_err(e)?,
        None => Cell::default(),
    })
    .map_err(e)?;
    root.checked_append_reference(mc_state_proof.serialize().map_err(e)?).map_err(e)?;
    root.checked_append_reference(next.unwrap_or_default()).map_err(e)?;
    root.into_cell().map_err(e)
}

pub struct VerifiedBundle {
    pub key_block: BlockIdExt,
    pub key_block_utime: u32,
    pub signatures_checked: bool,
    pub view: StateView,
}

fn proof_stuff(cell: &Cell, is_link: bool) -> Result<(BlockIdExt, BlockProofStuff)> {
    let proof = BlockProof::construct_from_cell(cell.clone()).map_err(|e| anyhow!("{e}"))?;
    let boc = write_boc(cell).map_err(|e| anyhow!("{e}"))?;
    let stuff = BlockProofStuff::deserialize(&proof.proof_for, boc, is_link).map_err(|e| anyhow!("{e}"))?;
    Ok((proof.proof_for, stuff))
}

/// Check the whole hash chain of the bundle and build a state view on the pruned states.
pub fn open_bundle(path: &Path) -> Result<VerifiedBundle> {
    let e = |e: ever_block::Error| anyhow!("{e}");
    let root = read_single_root_boc(std::fs::read(path).with_context(|| format!("read {}", path.display()))?).map_err(e)?;
    let mut slice = SliceData::load_cell(root.clone()).map_err(e)?;
    ensure!(slice.get_next_u32().map_err(e)? == MAGIC, "not a state proof bundle");
    ensure!(slice.get_next_byte().map_err(e)? == VERSION, "unsupported bundle version");

    // 1. key block proof, signatures checked with the validator set from the previous key block
    let (key_block, kb_proof) = proof_stuff(&root.reference(0).map_err(e)?, false)?;
    ensure!(key_block.shard().is_masterchain(), "root proof is not for a masterchain block");
    let prev_cell = root.reference(1).map_err(e)?;
    let signatures_checked = if prev_cell.references_count() > 0 {
        let (_, prev_proof) = proof_stuff(&prev_cell, false)?;
        kb_proof
            .check_with_prev_key_block_proof(&prev_proof)
            .map_err(|err| anyhow!("key block signatures: {err}"))?;
        true
    } else {
        kb_proof.check_proof_as_link().map_err(|err| anyhow!("key block proof: {err}"))?;
        false
    };
    let (block, _) = kb_proof.virtualize_block().map_err(|err| anyhow!("{err}"))?;
    let info = block.read_info().map_err(e)?;
    let mc_state_hash = block.read_state_update().map_err(e)?.new_hash;

    // 2. masterchain state
    let mc_proof = MerkleProof::construct_from_cell(root.reference(2).map_err(e)?).map_err(e)?;
    ensure!(mc_proof.hash == mc_state_hash, "masterchain state proof does not match the key block");
    let mc_virtual = mc_proof.proof.clone().virtualize(1);

    // 3. shards
    let mut shard_roots = Vec::new();
    let mut shard_ids = Vec::new();
    let mut item = root.reference(3).map_err(e)?;
    while item.references_count() >= 2 {
        let (id, link) = proof_stuff(&item.reference(0).map_err(e)?, true)?;
        link.check_proof_link().map_err(|err| anyhow!("shard block proof link {id}: {err}"))?;
        let (shard_block, _) = link.virtualize_block().map_err(|err| anyhow!("{err}"))?;
        let state_hash = shard_block.read_state_update().map_err(e)?.new_hash;
        let state_proof = MerkleProof::construct_from_cell(item.reference(1).map_err(e)?).map_err(e)?;
        ensure!(state_proof.hash == state_hash, "shard state proof does not match shard block {id}");
        shard_roots.push(state_proof.proof.clone().virtualize(1));
        shard_ids.push(id);
        if item.references_count() < 3 {
            break;
        }
        item = item.reference(2).map_err(e)?;
    }

    let view = StateView::new(mc_virtual, shard_roots, info.gen_utime().as_u32())?;
    let mut top = view.top_shard_blocks()?;
    top.sort_by_key(|b| (b.shard().workchain_id(), b.shard().shard_prefix_with_tag()));
    shard_ids.sort_by_key(|b| (b.shard().workchain_id(), b.shard().shard_prefix_with_tag()));
    if top != shard_ids {
        bail!("shard block proofs do not match the shard top blocks of the masterchain state")
    }
    Ok(VerifiedBundle { key_block, key_block_utime: info.gen_utime().as_u32(), signatures_checked, view })
}

/// Re-run the computation on the pruned proof and compare with `result.json`.
pub fn verify(proof: &Path, result: &Path, addresses_dir: &Path, abi_dir: &Path) -> Result<Computed> {
    let bundle = open_bundle(proof)?;
    log::info!(
        "bundle: masterchain block {} (utime {}), signatures {}",
        bundle.key_block,
        bundle.key_block_utime,
        if bundle.signatures_checked { "verified" } else { "NOT checked (no previous key block proof)" }
    );
    let claimed: serde_json::Value = serde_json::from_slice(&std::fs::read(result)?)?;
    let claimed_block = crate::util::id_from_json(&claimed["block"])?;
    ensure!(claimed_block == bundle.key_block, "result.json is for another block");
    let depools: Vec<DePoolRef> = serde_json::from_value(claimed["depool_refs"].clone())?;
    let lists = load_address_lists(addresses_dir)?;
    let abis = Abis::load(abi_dir)?;
    let computed = compute(&bundle.view, &lists, &depools, &abis)
        .map_err(|err| anyhow!("computation on the pruned proof failed (missing cells?): {err}"))?;
    let claimed_computed: Computed = serde_json::from_value(claimed["computed"].clone())?;
    if computed != claimed_computed {
        let dump = result.with_extension("recomputed.json");
        std::fs::write(&dump, serde_json::to_vec_pretty(&computed)?)?;
        bail!("recomputed result differs from {}; see {}", result.display(), dump.display())
    }
    Ok(computed)
}
