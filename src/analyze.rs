//! Balances and DePool stakes on top of a state "view".
//!
//! The same `compute` runs on the full downloaded states (with usage tracking,
//! to know which cells must stay in the proof) and on the pruned Merkle proof
//! (in `verify`), so the proof is exactly what the computation touched.

use crate::{
    tvm::{run_getter, GetterOutcome, TvmContext},
    util::{nano_to_ever, parse_address, AddressList, Abis},
};
use anyhow::{anyhow, Result};
use ever_block::{
    Account, Cell, Deserializable, HashmapAugType, McStateExtra, MsgAddressInt, ShardAccount, ShardAccounts, ShardIdent,
    ShardStateUnsplit, UInt256,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub struct StateView {
    #[allow(dead_code)]
    pub mc_state: ShardStateUnsplit,
    pub mc_extra: McStateExtra,
    pub mc_accounts: ShardAccounts,
    pub shards: Vec<(ShardIdent, ShardAccounts)>,
    pub ctx: TvmContext,
}

impl StateView {
    pub fn new(mc_root: Cell, shard_roots: Vec<Cell>, unix_time: u32) -> Result<Self> {
        let mc_state = ShardStateUnsplit::construct_from_cell(mc_root).map_err(|e| anyhow!("{e}"))?;
        let mc_extra = mc_state.read_custom().map_err(|e| anyhow!("{e}"))?.ok_or_else(|| anyhow!("no McStateExtra"))?;
        let config = mc_extra.config();
        let ctx = TvmContext {
            capabilities: config.capabilities(),
            block_version: config.global_version(),
            unix_time,
            block_lt: mc_state.gen_lt(),
        };
        let mc_accounts = mc_state.read_accounts().map_err(|e| anyhow!("{e}"))?;
        let mut shards = Vec::new();
        for root in shard_roots {
            let state = ShardStateUnsplit::construct_from_cell(root).map_err(|e| anyhow!("{e}"))?;
            shards.push((state.shard().clone(), state.read_accounts().map_err(|e| anyhow!("{e}"))?));
        }
        Ok(Self { mc_state, mc_extra, mc_accounts, shards, ctx })
    }

    pub fn top_shard_blocks(&self) -> Result<Vec<ever_block::BlockIdExt>> {
        let mut out = Vec::new();
        self.mc_extra
            .shards()
            .iterate_shards(|ident, descr| {
                out.push(ever_block::BlockIdExt::with_params(ident, descr.seq_no, descr.root_hash, descr.file_hash));
                Ok(true)
            })
            .map_err(|e| anyhow!("{e}"))?;
        Ok(out)
    }

    fn accounts_for(&self, address: &MsgAddressInt) -> Result<&ShardAccounts> {
        if address.workchain_id() == -1 {
            return Ok(&self.mc_accounts);
        }
        for (shard, accounts) in &self.shards {
            if shard.contains_address(address).map_err(|e| anyhow!("{e}"))? {
                return Ok(accounts);
            }
        }
        Err(anyhow!("no shard state for {address}"))
    }

    pub fn account(&self, address: &MsgAddressInt) -> Result<Option<Account>> {
        let accounts = self.accounts_for(address)?;
        match accounts.account(&address.address()).map_err(|e| anyhow!("{e}"))? {
            Some(shard_account) => {
                let account = shard_account.read_account().map_err(|e| anyhow!("{e}"))?;
                Ok(if account.is_none() { None } else { Some(account) })
            }
            None => Ok(None),
        }
    }
}

/// A DePool to inspect, as found by discovery.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DePoolRef {
    pub address: String,
    pub found_via: Vec<String>,
    pub proxies: Vec<String>,
}

/// Find DePools: (1) all DePoolProxy contracts in the masterchain (-1) answer
/// `getProxyInfo()` with their DePool address; (2) accounts in workchain 0 with a
/// known standard DePool code hash. Runs on the full (untracked) state.
pub fn discover(view: &StateView, abis: &Abis) -> Result<(Vec<DePoolRef>, usize, usize)> {
    let mut depools: BTreeMap<String, DePoolRef> = BTreeMap::new();
    let mut not_proxy_code: BTreeSet<UInt256> = BTreeSet::new();
    let mut mc_count = 0usize;
    let mut errors = 0usize;
    view.mc_accounts
        .iterate_objects(|shard_account: ShardAccount| {
            mc_count += 1;
            let account = shard_account.read_account()?;
            let Some(code_hash) = account.get_code_hash() else { return Ok(true) };
            if not_proxy_code.contains(&code_hash) || account.get_data().is_none() {
                return Ok(true);
            }
            match run_getter(&view.ctx, &account, &abis.proxy, "getProxyInfo", json!({})) {
                Ok(GetterOutcome::Ok(out)) => {
                    let proxy = account.get_addr().unwrap().to_string();
                    if let Some(depool) = out["depool"].as_str() {
                        if let Ok(addr) = parse_address(depool) {
                            if addr.workchain_id() == 0 {
                                let entry = depools.entry(addr.to_string()).or_insert_with(|| DePoolRef {
                                    address: addr.to_string(),
                                    found_via: vec![],
                                    proxies: vec![],
                                });
                                entry.proxies.push(proxy);
                                if !entry.found_via.contains(&"proxy_in_masterchain".to_string()) {
                                    entry.found_via.push("proxy_in_masterchain".into());
                                }
                            }
                        }
                    }
                }
                Ok(GetterOutcome::Exit(_)) | Err(_) => {
                    not_proxy_code.insert(code_hash);
                    errors += 1;
                }
            }
            Ok(true)
        })
        .map_err(|e| anyhow!("{e}"))?;
    log::info!(
        "masterchain: {mc_count} accounts scanned, {} DePools referenced by proxies",
        depools.len()
    );

    let mut wc_count = 0usize;
    for (_, accounts) in &view.shards {
        accounts
            .iterate_objects(|shard_account: ShardAccount| {
                wc_count += 1;
                let account = shard_account.read_account()?;
                if let Some(code_hash) = account.get_code_hash() {
                    if abis.depool_by_code_hash.contains_key(&code_hash) {
                        let addr = account.get_addr().unwrap().to_string();
                        let entry = depools.entry(addr.clone()).or_insert_with(|| DePoolRef {
                            address: addr,
                            found_via: vec![],
                            proxies: vec![],
                        });
                        entry.found_via.push("depool_code_hash".into());
                    }
                }
                Ok(true)
            })
            .map_err(|e| anyhow!("{e}"))?;
    }
    log::info!("workchain 0: {wc_count} accounts scanned, {} DePools in total", depools.len());
    for d in depools.values_mut() {
        d.proxies.sort();
    }
    Ok((depools.into_values().collect(), mc_count, wc_count))
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StakeEntry {
    pub depool: String,
    pub total_nano: String,
    pub ordinary_nano: String,
    pub vesting_nano: String,
    pub lock_nano: String,
    pub withdraw_value_nano: String,
    pub reward_nano: String,
    pub reinvest: bool,
    /// donors (`owner`) of vesting / lock stakes: lock principal and unvested parts go back to them
    pub vesting_owners: Vec<String>,
    pub lock_owners: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AddressResult {
    pub address: String,
    pub account_exists: bool,
    pub account_status: String,
    pub balance_nano: String,
    pub balance_ever: String,
    pub depool_stakes: Vec<StakeEntry>,
    pub stake_total_nano: String,
    pub stake_total_ever: String,
    pub balance_plus_stake_nano: String,
    pub balance_plus_stake_ever: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ListResult {
    pub list: String,
    pub file: String,
    pub address_count: usize,
    pub balance_total_nano: String,
    pub balance_total_ever: String,
    pub stake_total_nano: String,
    pub stake_total_ever: String,
    pub total_nano: String,
    pub total_ever: String,
    pub addresses: Vec<AddressResult>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DePoolResult {
    pub address: String,
    pub exists: bool,
    pub code_hash: String,
    pub abi_version: String,
    pub known_code: bool,
    pub found_via: Vec<String>,
    pub proxies: Vec<String>,
    pub balance_nano: String,
    pub matched_participants: usize,
    pub errors: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Computed {
    pub lists: Vec<ListResult>,
    pub depools: Vec<DePoolResult>,
}

fn u(v: &Value) -> u128 {
    match v {
        Value::String(s) => {
            if let Some(hex) = s.strip_prefix("0x") {
                u128::from_str_radix(hex, 16).unwrap_or(0)
            } else {
                s.parse().unwrap_or(0)
            }
        }
        Value::Number(n) => n.as_u64().unwrap_or(0) as u128,
        _ => 0,
    }
}

fn owners(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = v
        .as_object()
        .map(|m| m.values().filter_map(|i| i["owner"].as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    out.sort();
    out.dedup();
    out
}

fn sum_map(v: &Value, field: Option<&[&str]>) -> u128 {
    let Some(map) = v.as_object() else { return 0 };
    map.values()
        .map(|item| match field {
            None => u(item),
            Some(names) => names.iter().map(|n| u(&item[*n])).find(|x| *x > 0).unwrap_or(0),
        })
        .sum()
}

/// Run all reads needed for the result. Every cell touched here ends up in the proof.
pub fn compute(view: &StateView, lists: &[AddressList], depools: &[DePoolRef], abis: &Abis) -> Result<Computed> {
    // proxies: re-read through the (tracked) view so the link proxy -> DePool is in the proof
    for depool in depools {
        for proxy in &depool.proxies {
            if let Some(account) = view.account(&parse_address(proxy)?)? {
                let _ = run_getter(&view.ctx, &account, &abis.proxy, "getProxyInfo", json!({}));
            }
        }
    }

    let mut stakes: HashMap<String, Vec<StakeEntry>> = HashMap::new();
    let mut depool_results = Vec::new();
    let all_addresses: BTreeSet<String> =
        lists.iter().flat_map(|l| l.addresses.iter().map(|a| a.to_string())).collect();
    for (n, depool) in depools.iter().enumerate() {
        if n % 50 == 0 {
            log::info!("DePools: {n}/{} processed", depools.len());
        }
        let address = parse_address(&depool.address)?;
        let mut result = DePoolResult {
            address: depool.address.clone(),
            exists: false,
            code_hash: String::new(),
            abi_version: String::new(),
            known_code: false,
            found_via: depool.found_via.clone(),
            proxies: depool.proxies.clone(),
            balance_nano: "0".into(),
            matched_participants: 0,
            errors: vec![],
        };
        let account = view.account(&address)?;
        let Some(account) = account.filter(|a| a.get_code().is_some() && a.get_data().is_some()) else {
            depool_results.push(result);
            continue;
        };
        let code_hash = account.get_code_hash().unwrap();
        let (abi, label, known) = abis.depool_abi(&code_hash);
        result.exists = true;
        result.code_hash = code_hash.as_hex_string();
        result.abi_version = label;
        result.known_code = known;
        result.balance_nano = account.balance().map(|b| b.grams.as_u128()).unwrap_or(0).to_string();
        for participant in &all_addresses {
            match run_getter(&view.ctx, &account, abi, "getParticipantInfo", json!({ "addr": participant })) {
                Ok(GetterOutcome::Ok(info)) => {
                    let ordinary = sum_map(&info["stakes"], None);
                    let vesting = sum_map(&info["vestings"], Some(&["remainingAmount", "amount"]));
                    let lock = sum_map(&info["locks"], Some(&["remainingAmount", "amount"]));
                    let withdraw = u(&info["withdrawValue"]).max(u(&info["pauseStake"]));
                    stakes.entry(participant.clone()).or_default().push(StakeEntry {
                        depool: depool.address.clone(),
                        total_nano: u(&info["total"]).to_string(),
                        ordinary_nano: ordinary.to_string(),
                        vesting_nano: vesting.to_string(),
                        lock_nano: lock.to_string(),
                        withdraw_value_nano: withdraw.to_string(),
                        reward_nano: u(&info["reward"]).to_string(),
                        reinvest: info["reinvest"].as_bool().unwrap_or(false),
                        vesting_owners: owners(&info["vestings"]),
                        lock_owners: owners(&info["locks"]),
                    });
                    result.matched_participants += 1;
                }
                Ok(GetterOutcome::Exit(116)) => (), // NO_SUCH_PARTICIPANT
                Ok(GetterOutcome::Exit(code)) => result.errors.push(format!("{participant}: exit code {code}")),
                Err(e) => result.errors.push(format!("{participant}: {e}")),
            }
        }
        depool_results.push(result);
    }

    let mut list_results = Vec::new();
    for list in lists {
        let mut addresses = Vec::new();
        let (mut balance_total, mut stake_total) = (0u128, 0u128);
        for address in &list.addresses {
            let account = view.account(address)?;
            let balance = account.as_ref().and_then(|a| a.balance()).map(|b| b.grams.as_u128()).unwrap_or(0);
            let status = match &account {
                None => "nonexist".to_string(),
                Some(a) => format!("{:?}", a.status()),
            };
            let entries = stakes.get(&address.to_string()).cloned().unwrap_or_default();
            let stake: u128 = entries.iter().map(|e| e.total_nano.parse::<u128>().unwrap()).sum();
            balance_total += balance;
            stake_total += stake;
            addresses.push(AddressResult {
                address: address.to_string(),
                account_exists: account.is_some(),
                account_status: status,
                balance_nano: balance.to_string(),
                balance_ever: nano_to_ever(balance),
                depool_stakes: entries,
                stake_total_nano: stake.to_string(),
                stake_total_ever: nano_to_ever(stake),
                balance_plus_stake_nano: (balance + stake).to_string(),
                balance_plus_stake_ever: nano_to_ever(balance + stake),
            });
        }
        list_results.push(ListResult {
            list: list.name.clone(),
            file: list.file.clone(),
            address_count: list.addresses.len(),
            balance_total_nano: balance_total.to_string(),
            balance_total_ever: nano_to_ever(balance_total),
            stake_total_nano: stake_total.to_string(),
            stake_total_ever: nano_to_ever(stake_total),
            total_nano: (balance_total + stake_total).to_string(),
            total_ever: nano_to_ever(balance_total + stake_total),
            addresses,
        });
    }
    Ok(Computed { lists: list_results, depools: depool_results })
}
