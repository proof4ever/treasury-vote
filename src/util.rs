use anyhow::{anyhow, bail, Result};
use ever_block::{BlockIdExt, MsgAddressInt, ShardIdent, UInt256};
use serde_json::json;
use std::{collections::HashMap, path::Path, str::FromStr};

pub fn id_to_json(id: &BlockIdExt) -> serde_json::Value {
    json!({
        "workchain": id.shard().workchain_id(),
        "shard": format!("{:016x}", id.shard().shard_prefix_with_tag()),
        "seqno": id.seq_no(),
        "root_hash": id.root_hash().as_hex_string(),
        "file_hash": id.file_hash().as_hex_string(),
    })
}

pub fn id_from_json(v: &serde_json::Value) -> Result<BlockIdExt> {
    let shard = u64::from_str_radix(v["shard"].as_str().ok_or_else(|| anyhow!("shard"))?, 16)?;
    let shard = ShardIdent::with_tagged_prefix(v["workchain"].as_i64().ok_or_else(|| anyhow!("workchain"))? as i32, shard)
        .map_err(|e| anyhow!("{e}"))?;
    Ok(BlockIdExt::with_params(
        shard,
        v["seqno"].as_u64().ok_or_else(|| anyhow!("seqno"))? as u32,
        UInt256::from_str(v["root_hash"].as_str().ok_or_else(|| anyhow!("root_hash"))?).map_err(|e| anyhow!("{e}"))?,
        UInt256::from_str(v["file_hash"].as_str().ok_or_else(|| anyhow!("file_hash"))?).map_err(|e| anyhow!("{e}"))?,
    ))
}

pub fn parse_address(s: &str) -> Result<MsgAddressInt> {
    MsgAddressInt::from_str(s.trim()).map_err(|e| anyhow!("bad address {s:?}: {e}"))
}

pub fn nano_to_ever(nano: u128) -> String {
    let frac = nano % 1_000_000_000;
    let int = nano / 1_000_000_000;
    if frac == 0 {
        int.to_string()
    } else {
        format!("{int}.{frac:09}").trim_end_matches('0').to_string()
    }
}

/// One input list of addresses (`senders_for_*.txt` / `senders_against_*.txt`).
#[derive(Clone)]
pub struct AddressList {
    pub name: String,
    pub file: String,
    pub addresses: Vec<MsgAddressInt>,
}

pub fn load_address_lists(dir: &Path) -> Result<Vec<AddressList>> {
    let mut lists = Vec::new();
    for name in ["senders_for", "senders_against"] {
        let mut files: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                let file = p.file_name().unwrap().to_string_lossy();
                file.ends_with(".txt") && (file == format!("{name}.txt") || file.starts_with(&format!("{name}_")))
            })
            .collect();
        files.sort();
        if files.len() != 1 {
            bail!("expected exactly one {name}*.txt in {}, found {}", dir.display(), files.len())
        }
        let text = std::fs::read_to_string(&files[0])?;
        let mut addresses = Vec::new();
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let address = parse_address(line)?;
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
        lists.push(AddressList {
            name: name.to_string(),
            file: files[0].file_name().unwrap().to_string_lossy().into_owned(),
            addresses,
        });
    }
    Ok(lists)
}

/// DePool ABIs keyed by code hash, plus the fallback (latest) DePool ABI and the proxy ABI.
pub struct Abis {
    pub depool_by_code_hash: HashMap<UInt256, (String, String)>, // code hash -> (version label, abi json)
    pub depool_latest: String,
    pub proxy: String,
}

impl Abis {
    pub fn load(dir: &Path) -> Result<Self> {
        let depool_latest = std::fs::read_to_string(dir.join("DePool.abi.json"))?;
        let proxy = std::fs::read_to_string(dir.join("DePoolProxy.abi.json"))?;
        let registry: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.join("depool_versions.json"))?)?;
        let mut depool_by_code_hash = HashMap::new();
        for version in registry["versions"].as_array().ok_or_else(|| anyhow!("versions"))? {
            let hash = UInt256::from_str(version["code_hash"].as_str().unwrap()).map_err(|e| anyhow!("{e}"))?;
            let label = format!("{} ({})", &version["commit"].as_str().unwrap()[..8], &version["date"].as_str().unwrap()[..10]);
            depool_by_code_hash.insert(hash, (label, version["abi"].to_string()));
        }
        let extra_path = dir.join("depool_extra_versions.json");
        if extra_path.exists() {
            let extra: serde_json::Value = serde_json::from_slice(&std::fs::read(&extra_path)?)?;
            for version in extra["versions"].as_array().ok_or_else(|| anyhow!("versions"))? {
                let hash = UInt256::from_str(version["code_hash"].as_str().unwrap()).map_err(|e| anyhow!("{e}"))?;
                let abi = std::fs::read_to_string(dir.join(version["abi_file"].as_str().unwrap()))?;
                depool_by_code_hash.insert(hash, (version["label"].as_str().unwrap().to_string(), abi));
            }
        }
        Ok(Self { depool_by_code_hash, depool_latest, proxy })
    }

    /// ABI for a DePool with the given code hash, and whether it is a known version.
    pub fn depool_abi(&self, code_hash: &UInt256) -> (&str, String, bool) {
        match self.depool_by_code_hash.get(code_hash) {
            Some((label, abi)) => (abi.as_str(), label.clone(), true),
            None => (self.depool_latest.as_str(), "unknown code, latest ABI".to_string(), false),
        }
    }
}
