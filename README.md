# state_export

A reproducible tally of the vote on the proposal **"Move the Treasury Under Validator Governance"**.

* **FOR:** addresses that sent EVER to `0:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
* **AGAINST:** addresses that sent EVER to `0:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`
* **Snapshot:** the moment voting closes, `2026-10-21T00:00:00Z`
* **Voting power of an address:** its own EVER balance plus its stake in all DePools at the snapshot

The tool takes the state of the chain at the last masterchain block produced at or before the snapshot time.
It gets that state straight from the Everscale p2p network: no node, indexer or API is involved, and every
step is checked by hashes and validator signatures. It then writes the tally together with a proof file that
anyone can verify offline.

## Run

Requirements:

* Rust (the version is pinned in `rust-toolchain.toml`);
* a C/C++ compiler, clang, OpenSSL headers and pkg-config;
* ~20 GB of free disk (~13 GB of state and blocks in `data/`, ~3 GB of build files in `target/`);
* outbound UDP (VPNs and relays such as iCloud Private Relay or WARP often break it).

```sh
# Debian/Ubuntu: sudo apt install build-essential clang libclang-dev pkg-config libssl-dev
# macOS:         xcode-select --install && brew install openssl@3 pkg-config

git clone https://github.com/proof4ever/treasury-vote.git && cd treasury-vote
cargo build --release
./target/release/state_export run --timestamp 2026-10-21T00:00:00Z
```

The first run downloads ~7 GB (a recent key block state plus the blocks after it) and takes about an hour.
It can be interrupted and restarted, and continues where it stopped. Re-running the same timestamp needs no
network and takes about a minute.

The voter lists are read from `addresses/senders_for*.txt` and `addresses/senders_against*.txt`, one
address `wc:hex` per line.

## Results

Everything is written to `out/`:

| file | content |
| --- | --- |
| `table.csv` | per address: `balance_ever`, `stake_ever`, `total_ever`, plus `donor_funded_stake_ever` and `total_own_ever` (see below) |
| `result.json` | list totals and the full breakdown: every DePool stake of every address |
| `last_block.json` | `mc_seqno`: the masterchain block the tally is taken at, with its hash and time |
| `proof.boc` | validator-signed proof of the voters' and DePools' state at the snapshot; `verify` recomputes the tally from it offline |

Two people running the same command with the same address lists get the same `mc_seqno`, block hash, state
hashes and numbers. `proof.boc` bytes may differ because they include validator signatures obtained from
different peers. Both versions verify.

## Reference result

The published tally is in `vote_result_reference/2026-10-21T00-00-00Z/` (same four files as `out/`). To check it:

```sh
# verify the published proof (no network, no download needed)
./target/release/state_export verify --proof vote_result_reference/2026-10-21T00-00-00Z/proof.boc \
                                     --result vote_result_reference/2026-10-21T00-00-00Z/result.json

# or compare it with your own run
cmp out/table.csv vote_result_reference/2026-10-21T00-00-00Z/table.csv && echo "same tally"
```

## Verify someone else's result

```sh
./target/release/state_export verify --proof proof.boc --result result.json
```

This needs neither the network nor the downloaded state. It checks:

* the validator signatures of the snapshot block;
* that the pruned states in the proof belong to that block;
* that re-running the whole computation on them gives exactly the numbers in `result.json`.

To be sure it is the real chain, compare the block hash in `last_block.json` with any block explorer.

## How the numbers are computed

* **Balance:** the native EVER balance of the address at the snapshot block.
* **Stake:** for every DePool, `getParticipantInfo(address)` runs locally in TVM on the snapshot state, and
  the `total` values are summed. `total` = ordinary + vesting + lock stake, exactly what DePool reports. The
  tool finds DePools in two ways:
  * through their proxies in the masterchain;
  * by the code hashes of all official EverX builds and the Broxus stEVER builds.

  ABIs are in `abi/`.
* **Donor-funded stake:** lock and vesting stakes can be placed on an address by someone else, the donor.
  The principal of a lock goes back to the donor, so that money is not really the address's own.
  `table.csv` shows the donor part separately (`donor_funded_stake_ever`) and the total without it
  (`total_own_ever`), so either interpretation can be applied.

The result was cross-checked against an independent implementation based on the evercloud GraphQL API and
nekoton. All 112 addresses matched to the nanoEVER, and both found the same set of DePools.

## Limitations

* The address lists are taken as given. Make sure they contain exactly the senders up to the end of voting.
* Validator stake held directly by the Elector (not through a DePool) is not counted.
* Blocks and states disappear from nodes over time, so run soon after the snapshot. Once `proof.boc` and
  `result.json` are published, they can be verified forever.

## Troubleshooting

| message | fix |
| --- | --- |
| `timestamp … is in the future or too recent` | wait until at least 30 s after `2026-10-21T00:00:00Z` |
| `no DHT nodes answered`, `no peers found`, many `no reply from …` | UDP is blocked or degraded: turn off VPN/relay or use another network |
| `cannot detect the public IPv4 address` | add `--public-ip <your IPv4>` |
| build fails in `librocksdb-sys` / `openssl-sys` | install the native tools listed above |
