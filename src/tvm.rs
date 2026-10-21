//! Local execution of ABI getters on an account taken from the state.
//!
//! This mirrors how tonos-cli/ever-sdk run "get methods" of Solidity contracts:
//! an unsigned external inbound message with the ABI-encoded call is fed into TVM,
//! and the answer is decoded from the external outbound message in c5.
//! The environment (c7) is fixed to the key block, so runs are deterministic and
//! can be repeated on the pruned Merkle proof.

use anyhow::{anyhow, Result};
use ever_abi::json_abi::{decode_function_response, encode_function_call};
use ever_block::{
    Account, Deserializable, ExternalInboundMessageHeader, Grams, Message, MsgAddressExt, OutAction, OutActions,
    Serializable, SliceData,
};
use ever_vm::{
    executor::{gas::gas_state::Gas, Engine},
    int,
    smart_contract_info::SmartContractInfo,
    stack::{integer::IntegerData, savelist::SaveList, Stack, StackItem},
};

#[derive(Clone, Copy)]
pub struct TvmContext {
    pub capabilities: u64,
    pub block_version: u32,
    pub unix_time: u32,
    pub block_lt: u64,
}

pub enum GetterOutcome {
    Ok(serde_json::Value),
    /// The contract threw (e.g. DePool exit code 116 = no such participant)
    Exit(i32),
}

const GAS_LIMIT: i64 = 10_000_000;

pub fn run_getter(
    ctx: &TvmContext,
    account: &Account,
    abi: &str,
    function: &str,
    params: serde_json::Value,
) -> Result<GetterOutcome> {
    let address = account.get_addr().ok_or_else(|| anyhow!("account has no address"))?.clone();
    let code = account.get_code().ok_or_else(|| anyhow!("account {address} has no code"))?;
    let data = account.get_data().ok_or_else(|| anyhow!("account {address} has no data"))?;
    let balance = account.balance().cloned().unwrap_or_default();

    let abi_json: serde_json::Value = serde_json::from_str(abi)?;
    let mut header = serde_json::Map::new();
    for name in abi_json["header"].as_array().into_iter().flatten() {
        match name.as_str() {
            Some("time") => header.insert("time".into(), (ctx.unix_time as u64 * 1000).into()),
            Some("expire") => header.insert("expire".into(), (ctx.unix_time + 60).into()),
            _ => None,
        };
    }
    let body = encode_function_call(
        abi,
        function,
        Some(&serde_json::Value::Object(header).to_string()),
        &params.to_string(),
        false,
        None,
        Some(&address.to_string()),
    )
    .map_err(|e| anyhow!("encode {function}: {e}"))?;
    let body = SliceData::load_builder(body).map_err(|e| anyhow!("{e}"))?;
    let msg = Message::with_ext_in_header_and_body(
        ExternalInboundMessageHeader { src: MsgAddressExt::AddrNone, dst: address.clone(), import_fee: Grams::zero() },
        body.clone(),
    );
    let msg_cell = msg.serialize().map_err(|e| anyhow!("{e}"))?;

    let mut stack = Stack::new();
    stack
        .push(int!(balance.grams.as_u128()))
        .push(int!(0))
        .push(StackItem::Cell(msg_cell))
        .push(StackItem::Slice(body))
        .push(int!(-1));

    let sci = SmartContractInfo {
        capabilities: ctx.capabilities,
        myself: SliceData::load_cell(address.serialize().map_err(|e| anyhow!("{e}"))?).map_err(|e| anyhow!("{e}"))?,
        block_lt: ctx.block_lt,
        trans_lt: ctx.block_lt,
        unix_time: ctx.unix_time,
        balance,
        config_params: None,
        mycode: code.clone(),
        ..Default::default()
    };
    let mut ctrls = SaveList::new();
    ctrls.put(4, &mut StackItem::Cell(data)).map_err(|e| anyhow!("{e}"))?;
    ctrls.put(7, &mut sci.into_temp_data_item()).map_err(|e| anyhow!("{e}"))?;

    let mut engine = Engine::with_capabilities(ctx.capabilities).setup_with_libraries(
        SliceData::load_cell(code).map_err(|e| anyhow!("{e}"))?,
        Some(ctrls),
        Some(stack),
        Some(Gas::test_with_limit(GAS_LIMIT)),
        vec![],
    );
    engine.set_block_version(ctx.block_version);
    let exit = match engine.execute() {
        Ok(code) => code,
        Err(err) => ever_vm::error::tvm_exception_or_custom_code(&err),
    };
    if exit != 0 && exit != 1 {
        return Ok(GetterOutcome::Exit(exit));
    }
    let actions = engine.get_actions();
    let actions_cell = actions.as_cell().map_err(|e| anyhow!("{e}"))?.clone();
    let actions = OutActions::construct_from_cell(actions_cell).map_err(|e| anyhow!("{e}"))?;
    for action in actions.iter() {
        if let OutAction::SendMsg { out_msg, .. } = action {
            if out_msg.is_outbound_external() {
                let body = out_msg.body().ok_or_else(|| anyhow!("answer without body"))?;
                let decoded = decode_function_response(abi, function, body, false, false)
                    .map_err(|e| anyhow!("decode {function}: {e}"))?;
                return Ok(GetterOutcome::Ok(serde_json::from_str(&decoded)?));
            }
        }
    }
    Err(anyhow!("{function} on {address}: no external answer (exit code {exit})"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::Abis;

    /// Real mainnet DePool accounts recorded by depool_check (2026-10-14).
    #[test]
    fn get_participant_info_on_real_depools() {
        let fixture: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string("tests/fixtures/depool_accounts.json").unwrap()).unwrap();
        let abis = Abis::load(std::path::Path::new("abi")).unwrap();
        let ctx = TvmContext { capabilities: 0x5e, block_version: 0, unix_time: 1_791_939_994, block_lt: 76_750_873_000_010 };
        let wallet = fixture["wallet"].as_str().unwrap();
        let mut found = 0;
        for acc in fixture["accounts"].as_array().unwrap() {
            let account = Account::construct_from_base64(acc["boc"].as_str().unwrap()).unwrap();
            let (abi, _, known) = abis.depool_abi(&account.get_code_hash().unwrap());
            assert!(known);
            match run_getter(&ctx, &account, abi, "getParticipantInfo", serde_json::json!({ "addr": wallet })).unwrap() {
                GetterOutcome::Ok(info) => {
                    assert_eq!(acc["id"], fixture["match"]);
                    assert_eq!(info["total"].as_str().unwrap(), fixture["expected_total_nano"].to_string());
                    found += 1;
                }
                GetterOutcome::Exit(code) => assert_eq!(code, 116, "{}", acc["id"]),
            }
        }
        assert_eq!(found, 1);
    }
}
