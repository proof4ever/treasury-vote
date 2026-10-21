mod analyze;
mod blocks;
mod download;
mod lazyboc;
mod net;
mod proof;
mod tvm;
mod util;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use ever_block::{write_boc, MerkleProof, UsageTree};
use serde_json::json;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(about = "Everscale key-block state export: balances, DePool stakes and a pruned Merkle proof")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Args, Clone)]
struct DownloadArgs {
    /// Network global config (ever-node-configs/ever-global.config.json)
    #[arg(long, default_value = "config/ever-global.config.json")]
    global_config: PathBuf,
    /// Where key block cache and snapshots are stored
    #[arg(long, default_value = "data")]
    data_dir: PathBuf,
    /// Local UDP port for ADNL
    #[arg(long, default_value_t = 30310)]
    port: u16,
    /// Own public IPv4 address (default: detected via a few HTTP "what is my IP" services)
    #[arg(long)]
    public_ip: Option<std::net::Ipv4Addr>,
    /// Use this key block seqno instead of the newest one that has a persistent state
    #[arg(long)]
    key_block_seqno: Option<u32>,
    /// UTC time (unix seconds or ISO 8601, e.g. 2026-10-19T12:00:00Z): state after the
    /// last masterchain block with gen_utime <= this time
    #[arg(long, value_parser = parse_timestamp)]
    timestamp: Option<u32>,
}

#[derive(clap::Args, Clone)]
struct AnalyzeArgs {
    /// Directory with senders_for*.txt and senders_against*.txt
    #[arg(long, default_value = "addresses")]
    addresses: PathBuf,
    /// Directory with DePool.abi.json, DePoolProxy.abi.json, depool_versions.json
    #[arg(long, default_value = "abi")]
    abi_dir: PathBuf,
    /// Output directory for result.json and proof.boc
    #[arg(long, default_value = "out")]
    out: PathBuf,
}

#[derive(Subcommand)]
enum Command {
    /// Download the latest key block persistent state (masterchain + all shards) and proofs
    Download(DownloadArgs),
    /// Compute balances and DePool stakes from a downloaded snapshot, build the pruned proof
    Analyze {
        /// Snapshot directory (data/snapshot_<seqno>)
        #[arg(long)]
        snapshot: PathBuf,
        /// Same timestamp as given to `download --timestamp` (blocks must be cached)
        #[arg(long, value_parser = parse_timestamp)]
        timestamp: Option<u32>,
        #[command(flatten)]
        args: AnalyzeArgs,
    },
    /// Verify proof.boc against result.json by re-running everything on the pruned state
    Verify {
        #[arg(long, default_value = "out/proof.boc")]
        proof: PathBuf,
        #[arg(long, default_value = "out/result.json")]
        result: PathBuf,
        #[arg(long, default_value = "addresses")]
        addresses: PathBuf,
        #[arg(long, default_value = "abi")]
        abi_dir: PathBuf,
    },
    /// Print the code hash of a .tvc (StateInit BOC) file
    CodeHash { tvc: Vec<PathBuf> },
    /// download + analyze + verify
    Run {
        #[command(flatten)]
        download: DownloadArgs,
        #[command(flatten)]
        args: AnalyzeArgs,
    },
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info,telemetry=off,adnl=error,overlay=warn,dht=warn,rldp=warn"))
        .init();
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    match cli.command {
        Command::Download(d) => {
            runtime.block_on(download::run(to_opts(&d)))?;
        }
        Command::Analyze { snapshot, timestamp, args } => {
            analyze_snapshot(&snapshot, timestamp, &args)?;
            verify_and_print(&args.out.join("proof.boc"), &args.out.join("result.json"), &args.addresses, &args.abi_dir)?;
        }
        Command::Verify { proof, result, addresses, abi_dir } => {
            verify_and_print(&proof, &result, &addresses, &abi_dir)?;
        }
        Command::CodeHash { tvc } => {
            for path in tvc {
                let si = <ever_block::StateInit as ever_block::Deserializable>::construct_from_bytes(&std::fs::read(&path)?)
                    .map_err(|e| anyhow!("{e}"))?;
                let code = si.code.ok_or_else(|| anyhow!("no code in {}", path.display()))?;
                println!("{:x}  {}", code.repr_hash(), path.display());
            }
        }
        Command::Run { download, args } => {
            let snapshot = runtime.block_on(download::run(to_opts(&download)))?;
            analyze_snapshot(&snapshot, download.timestamp, &args)?;
            verify_and_print(&args.out.join("proof.boc"), &args.out.join("result.json"), &args.addresses, &args.abi_dir)?;
        }
    }
    // the ADNL stack keeps background tasks; do not wait for them
    runtime.shutdown_background();
    Ok(())
}

fn to_opts(d: &DownloadArgs) -> download::DownloadOptions {
    download::DownloadOptions {
        global_config: d.global_config.clone(),
        data_dir: d.data_dir.clone(),
        port: d.port,
        public_ip: d.public_ip,
        key_block_seqno: d.key_block_seqno,
        timestamp: d.timestamp,
    }
}

fn parse_timestamp(s: &str) -> std::result::Result<u32, String> {
    if let Ok(t) = s.parse::<u32>() {
        return Ok(t);
    }
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(t.timestamp() as u32);
    }
    for format in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"] {
        if let Ok(t) = chrono::NaiveDateTime::parse_from_str(s, format) {
            return Ok(t.and_utc().timestamp() as u32);
        }
    }
    Err(format!("cannot parse {s:?}: use unix seconds or 2026-10-19T12:00:00Z"))
}

fn utc(t: u32) -> String {
    chrono::DateTime::from_timestamp(t as i64, 0).map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string()).unwrap_or_default()
}

fn analyze_snapshot(snapshot: &Path, timestamp: Option<u32>, args: &AnalyzeArgs) -> Result<()> {
    let e = |e: ever_block::Error| anyhow!("{e}");
    let manifest = download::Manifest::load(snapshot)?;
    let lists = util::load_address_lists(&args.addresses)?;
    let abis = util::Abis::load(&args.abi_dir)?;
    for list in &lists {
        log::info!("{}: {} addresses ({})", list.name, list.addresses.len(), list.file);
    }

    // base state: persistent state of the key block (read lazily from disk)
    let mc_hash = manifest.mc_state_hash.parse().map_err(|e| anyhow!("{e}"))?;
    let base_mc_root = lazyboc::open_state(&snapshot.join(&manifest.mc_state_file), Some(&mc_hash))?;
    let mut base_shards = Vec::new();
    for shard in &manifest.shards {
        let hash = shard.state_hash.parse().map_err(|e| anyhow!("{e}"))?;
        base_shards.push((util::id_from_json(&shard.block_id)?, lazyboc::open_state(&snapshot.join(&shard.state_file), Some(&hash))?));
    }

    // state used for the result: the key block itself, or the key block with all
    // blocks up to the timestamp applied
    let (target, mc_root, shard_roots, block_json, block_utime, mc_proof_boc, prev_key_proof_boc, shard_links, shard_blocks) =
        match timestamp {
            None => (
                None,
                base_mc_root,
                base_shards.iter().map(|(_, r)| r.clone()).collect::<Vec<_>>(),
                manifest.key_block.clone(),
                manifest.key_block_utime,
                std::fs::read(snapshot.join(&manifest.key_block_proof_file))?,
                if manifest.prev_key_block_proof_file.is_empty() {
                    None
                } else {
                    Some(std::fs::read(snapshot.join(&manifest.prev_key_block_proof_file))?)
                },
                manifest.shards.iter().map(|s| std::fs::read(snapshot.join(&s.proof_file))).collect::<std::io::Result<Vec<_>>>()?,
                manifest.shards.iter().map(|s| s.block_id.clone()).collect::<Vec<_>>(),
            ),
            Some(ts) => {
                let target = blocks::Target::load(snapshot, ts)?;
                let dir = blocks::target_dir(snapshot, ts);
                let (mc_root, shard_roots) = blocks::apply(snapshot, &target, base_mc_root, base_shards)?;
                let mut links = Vec::new();
                for shard in &target.shards {
                    links.push(std::fs::read(dir.join(blocks::shard_link_file(&util::id_from_json(&shard.top_block)?)))?);
                }
                (
                    Some(target.clone()),
                    mc_root,
                    shard_roots,
                    target.block.clone(),
                    target.block_utime,
                    std::fs::read(dir.join("mc_block.proof.boc"))?,
                    Some(std::fs::read(dir.join("prev_key_block.proof.boc"))?),
                    links,
                    target.shards.iter().map(|s| s.top_block.clone()).collect(),
                )
            }
        };

    // 1. discovery over the whole state (not tracked, not part of the proof)
    let full_view = analyze::StateView::new(mc_root.clone(), shard_roots.clone(), block_utime)?;
    let (depool_refs, mc_accounts, wc_accounts) = analyze::discover(&full_view, &abis)?;
    drop(full_view);

    // 2. the computation itself, on usage-tracked roots
    let mc_tree = UsageTree::with_params(mc_root.clone(), true);
    let shard_trees: Vec<UsageTree> = shard_roots.iter().map(|r| UsageTree::with_params(r.clone(), true)).collect();
    let view = analyze::StateView::new(mc_tree.root_cell(), shard_trees.iter().map(|t| t.root_cell()).collect(), block_utime)?;
    view.top_shard_blocks()?; // shard descriptions link the shard states to the masterchain block
    let computed = analyze::compute(&view, &lists, &depool_refs, &abis)?;
    drop(view);

    // 3. prune everything that was not touched
    let mc_proof = MerkleProof::create_by_usage_tree(&mc_root, mc_tree).map_err(e)?;
    let mut shard_parts = Vec::new();
    for ((link, root), tree) in shard_links.into_iter().zip(shard_roots.iter()).zip(shard_trees) {
        shard_parts.push(proof::ShardPart {
            block_proof_link_boc: link,
            state_proof: MerkleProof::create_by_usage_tree(root, tree).map_err(e)?,
        });
    }
    let bundle = proof::build_bundle(&mc_proof_boc, prev_key_proof_boc.as_deref(), &mc_proof, &shard_parts)?;
    let bundle_boc = write_boc(&bundle).map_err(e)?;

    std::fs::create_dir_all(&args.out)?;
    std::fs::write(args.out.join("proof.boc"), &bundle_boc)?;
    let last_block = json!({
        "mc_seqno": block_json["seqno"],
        "timestamp": timestamp,
        "timestamp_utc": timestamp.map(utc),
        "block": block_json,
        "block_utime": block_utime,
        "block_utime_utc": utc(block_utime),
        "next_block_seqno": target.as_ref().map(|t| t.next_block["seqno"].clone()),
        "next_block_utime": target.as_ref().map(|t| t.next_block_utime),
        "base_key_block_seqno": manifest.key_block["seqno"],
        "applied_mc_blocks": target.as_ref().map(|t| t.applied_mc_blocks).unwrap_or(0),
        "shard_blocks": shard_blocks,
        "applied_shard_blocks": target.as_ref().map(|t| t.shards.iter().map(|s| s.applied_blocks).collect::<Vec<_>>()),
    });
    std::fs::write(args.out.join("last_block.json"), serde_json::to_vec_pretty(&last_block)?)?;
    let result = json!({
        "block": block_json,
        "block_utime": block_utime,
        "timestamp": timestamp,
        "base_key_block": manifest.key_block,
        "base_key_block_utime": manifest.key_block_utime,
        "mc_state_hash": mc_root.repr_hash().as_hex_string(),
        "shards": shard_blocks.iter().zip(shard_roots.iter()).map(|(b, r)| json!({"block_id": b, "state_hash": r.repr_hash().as_hex_string()})).collect::<Vec<_>>(),
        "scanned_accounts": { "masterchain": mc_accounts, "workchain0": wc_accounts },
        "depool_count": depool_refs.len(),
        "proof": {
            "file": "proof.boc",
            "bundle_root_hash": bundle.repr_hash().as_hex_string(),
            "size_bytes": bundle_boc.len(),
            "mc_state_proof_cells": mc_proof.proof.count_cells(usize::MAX).unwrap_or(0),
            "shard_state_proof_cells": shard_parts.iter().map(|s| s.state_proof.proof.count_cells(usize::MAX).unwrap_or(0)).collect::<Vec<_>>(),
        },
        "depool_refs": depool_refs,
        "computed": computed,
    });
    std::fs::write(args.out.join("result.json"), serde_json::to_vec_pretty(&result)?)?;
    write_table(&args.out.join("table.csv"), &computed)?;
    log::info!("proof: {} bytes, last masterchain block {}, written to {}", bundle_boc.len(), block_json["seqno"], args.out.display());
    Ok(())
}

/// Per-address table: balance, stake, total, and the part of the stake funded by
/// donors (lock/vesting stakes whose `owner` is another address; their principal
/// returns to the donor).
fn write_table(path: &Path, computed: &analyze::Computed) -> Result<()> {
    let mut out = String::from("list,address,balance_ever,stake_ever,total_ever,donor_funded_stake_ever,total_own_ever\n");
    for list in &computed.lists {
        let mut rows: Vec<_> = list.addresses.iter().collect();
        rows.sort_by_key(|a| std::cmp::Reverse(a.balance_plus_stake_nano.parse::<u128>().unwrap_or(0)));
        for a in rows {
            let mut donor = 0u128;
            for s in &a.depool_stakes {
                for (amount, owners) in [(&s.vesting_nano, &s.vesting_owners), (&s.lock_nano, &s.lock_owners)] {
                    let amount: u128 = amount.parse().unwrap_or(0);
                    if amount > 0 && owners.iter().any(|o| o != &a.address) {
                        donor += amount;
                    }
                }
            }
            let total: u128 = a.balance_plus_stake_nano.parse().unwrap_or(0);
            out += &format!(
                "{},{},{},{},{},{},{}\n",
                list.list,
                a.address,
                a.balance_ever,
                a.stake_total_ever,
                a.balance_plus_stake_ever,
                util::nano_to_ever(donor),
                util::nano_to_ever(total - donor)
            );
        }
    }
    std::fs::write(path, out)?;
    Ok(())
}

fn verify_and_print(proof: &Path, result: &Path, addresses: &Path, abi_dir: &Path) -> Result<()> {
    let computed = proof::verify(proof, result, addresses, abi_dir)?;
    println!("proof verified: {} re-computed on the pruned state matches {}", proof.display(), result.display());
    for list in &computed.lists {
        println!(
            "{:<16} {:>3} addresses  balance {:>22} EVER  depool stake {:>22} EVER  total {:>22} EVER",
            list.list,
            list.address_count,
            list.balance_total_ever,
            list.stake_total_ever,
            list.total_ever
        );
    }
    let with_stake: usize = computed.depools.iter().filter(|d| d.matched_participants > 0).count();
    let errors: usize = computed.depools.iter().map(|d| d.errors.len()).sum();
    println!("depools: {} inspected, {} with stakes of listed addresses, {} getter errors", computed.depools.len(), with_stake, errors);
    Ok(())
}
