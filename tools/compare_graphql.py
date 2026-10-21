"""Compare state_export result.json with depool_check (GraphQL + nekoton), per address and per DePool.

usage: compare_graphql.py <depool_check dir> <result.json> <out.json>
"""
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
import nekoton as nt  # noqa: E402
import personal_stake as ps  # noqa: E402

result = json.load(open(sys.argv[2]))
out_path = Path(sys.argv[3])
endpoint = ps._endpoint()
T = result["block_utime"]
addresses = [a["address"] for l in result["computed"]["lists"] for a in l["addresses"]]
ours = {a["address"]: a for l in result["computed"]["lists"] for a in l["addresses"]}


def gql(q, v=None):
    return ps._graphql(endpoint, q, v)


def changed_after(addr):
    """Transactions of the account after the snapshot block time."""
    d = gql(
        """query($a:String!,$t:Float!){ transactions(filter:{account_addr:{eq:$a}, now:{gt:$t}}, limit:3, orderBy:[{path:"now",direction:ASC}]) { now lt } }""",
        {"a": addr, "t": T},
    )
    return [int(x["now"]) for x in d["transactions"]]


async def main():
    registry = ps._registry()
    abis = {h: nt.ContractAbi(json.dumps(v["abi"])) for h, v in registry.items()}
    transport = nt.GqlTransport([endpoint])
    head = gql('{ blockchain { blocks(workchain:-1, last:1) { edges { node { seq_no gen_utime } } } } }')
    head = head["blockchain"]["blocks"]["edges"][0]["node"]

    # all standard DePools (8 EverX versions) in one pass, then all 79 addresses on each
    stakes = {}  # (address, depool) -> dict
    after, scanned = "", 0
    while True:
        rows = await transport.query_accounts(
            filter=f'code_hash: {{in: {json.dumps(list(registry))}}}, id: {{gt: {json.dumps(after)}}}',
            order_by='{path:"id",direction:ASC}',
            limit=ps.PAGE_SIZE,
        )
        if not rows:
            break
        for address, state in rows:
            address = str(address)
            after = address
            scanned += 1
            code_hash = state.state_init.code_hash.hex()
            fn = abis[code_hash].function("getParticipantInfo")
            for wallet in addresses:
                r = fn.call(state, {"addr": nt.Address(wallet)})
                if r.exit_code == registry[code_hash]["absent_participant_exit_code"]:
                    continue
                if r.exit_code not in (0, 1):
                    raise RuntimeError(f"{address} {wallet}: exit {r.exit_code}")
                o = r.output
                stakes[(wallet, address)] = {
                    "total": o["total"],
                    "ordinary": sum(v for _, v in o["stakes"]),
                    "vesting": sum(v["remainingAmount"] for _, v in o["vestings"]),
                    "lock": sum(v["remainingAmount"] for _, v in o["locks"]),
                }

    rows, mismatches = [], []
    for wallet in addresses:
        d = gql('query($a:String!){ blockchain { account(address:$a) { info { balance acc_type last_trans_lt } } } }', {"a": wallet})
        info = d["blockchain"]["account"]["info"]
        g_balance = int(info["balance"], 16) if info and info.get("balance") else 0
        o = ours[wallet]
        o_balance = int(o["balance_nano"])
        g_st = {dp: v for (w, dp), v in stakes.items() if w == wallet}
        o_st = {s["depool"]: s for s in o["depool_stakes"]}
        problems = []
        if g_balance != o_balance:
            problems.append(("balance", o_balance, g_balance))
        for dp in sorted(set(g_st) | set(o_st)):
            g, s = g_st.get(dp), o_st.get(dp)
            for k, ok in (("total", "total_nano"), ("ordinary", "ordinary_nano"), ("vesting", "vesting_nano"), ("lock", "lock_nano")):
                gv = g[k] if g else 0
                ov = int(s[ok]) if s else 0
                if gv != ov:
                    problems.append((f"{dp[:10]}… {k}", ov, gv))
        explained = None
        if problems:
            touched = {wallet: changed_after(wallet)}
            for dp in set(g_st) | set(o_st):
                touched[dp] = changed_after(dp)
            explained = {k: v for k, v in touched.items() if v}
            mismatches.append({"address": wallet, "problems": problems, "transactions_after_snapshot": explained})
        rows.append({"address": wallet, "balance_ours": o_balance, "balance_graphql": g_balance,
                     "stake_ours": int(o["stake_total_nano"]), "stake_graphql": sum(v["total"] for v in g_st.values()),
                     "depools_ours": len(o_st), "depools_graphql": len(g_st), "ok": not problems})
    report = {"snapshot_block_utime": T, "graphql_head": head, "graphql_depools_scanned": scanned,
              "addresses": len(addresses), "matching": sum(r["ok"] for r in rows), "mismatches": mismatches, "rows": rows}
    out_path.write_text(json.dumps(report, indent=1))
    print(f"graphql head: mc {head['seq_no']} utime {head['gen_utime']}; snapshot utime {T}; depools scanned {scanned}")
    print(f"addresses fully matching (balance + every DePool total/ordinary/vesting/lock): {report['matching']}/{len(addresses)}")
    for m in mismatches:
        print(m["address"], m["problems"], "tx after snapshot:", m["transactions_after_snapshot"])


asyncio.run(main())
