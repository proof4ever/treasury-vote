//! Minimal light client for the Everscale p2p network.
//!
//! It joins the DHT using the static nodes from the global config, looks up the
//! public overlays of the masterchain and of workchain 0, and sends the same
//! `tonNode.*` queries a cold-booting ever-node sends. No database and no
//! validator logic are involved.

use adnl::{
    common::{TaggedByteSlice, TaggedTlObject},
    node::{AdnlNode, AdnlNodeConfig},
    DhtNode, OverlayNode, OverlayShortId, RldpNode,
};
use anyhow::{anyhow, bail, Result};
use ever_block::{BlockIdExt, KeyId};
use ever_node::{block_proof::BlockProofStuff, config::TonNodeGlobalConfigJson};
use rand::seq::SliceRandom;
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use ton_api::{
    serialize_boxed_append,
    ton::{
        rpc::ton_node::{
            DownloadBlockFull, DownloadBlockProof, DownloadBlockProofLink, DownloadKeyBlockProof,
            DownloadNextBlockFull, DownloadPersistentStateSlice, GetArchiveInfo, GetArchiveSlice,
            GetNextKeyBlockIds, PrepareBlock, PrepareBlockProof, PrepareKeyBlockProof, PreparePersistentState,
        },
        ton_node::{ArchiveInfo, DataFull, KeyBlocks, Prepared, PreparedProof, PreparedState},
        TLObject,
    },
    AnyBoxedSerialize, BoxedSerialize, Deserializer,
};

/// A block with its proof (`proof` for masterchain blocks, `proof link` for shard blocks).
pub struct FullBlock {
    pub id: BlockIdExt,
    pub block: Vec<u8>,
    pub proof: Vec<u8>,
    pub is_link: bool,
}

impl FullBlock {
    fn parse(data: &[u8], expected: Option<&BlockIdExt>) -> Result<Self> {
        let full: DataFull = Deserializer::new(&mut std::io::Cursor::new(data))
            .read_boxed()
            .map_err(|e| anyhow!("bad DataFull: {e}"))?;
        let DataFull::TonNode_DataFull(full) = full else { bail!("empty DataFull") };
        if let Some(expected) = expected {
            if &full.id != expected {
                bail!("got block {} instead of {expected}", full.id)
            }
        }
        // checks root hash and file hash against the id
        ever_node::block::BlockStuff::deserialize_block_checked(full.id.clone(), full.block.to_vec())
            .map_err(|e| anyhow!("{e}"))?;
        Ok(Self { id: full.id, block: full.block.to_vec(), proof: full.proof.to_vec(), is_link: full.is_link.into() })
    }
}

const KEY_TAG_DHT: usize = 1;
const KEY_TAG_OVERLAY: usize = 2;
const ADNL_TIMEOUT_MS: u64 = 3000;
const RLDP_MAX_ANSWER: i64 = 10 * 1024 * 1024;
pub const SLICE_SIZE: usize = 1 << 20;

/// Own public IPv4 address, advertised in ADNL packets. ADNL's built-in detection
/// needs a majority of HTTP sources to agree, which fails behind NAT pools/relays
/// that use several egress addresses; here the most frequent answer wins.
fn detect_public_ip() -> Result<std::net::Ipv4Addr> {
    use std::{io::{Read, Write}, net::{TcpStream, ToSocketAddrs}};
    let mut answers: HashMap<std::net::Ipv4Addr, usize> = HashMap::new();
    for host in ["api.ipify.org", "ipv4.icanhazip.com", "checkip.amazonaws.com", "whatismyip.akamai.com"] {
        let result: Result<std::net::Ipv4Addr> = (|| {
            let addr = (host, 80).to_socket_addrs()?.find(|a| a.is_ipv4()).ok_or_else(|| anyhow!("no IPv4 for {host}"))?;
            let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            write!(stream, "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: state_export\r\nConnection: close\r\n\r\n")?;
            let mut response = String::new();
            stream.read_to_string(&mut response)?;
            let body = response.split("\r\n\r\n").nth(1).ok_or_else(|| anyhow!("bad HTTP answer from {host}"))?;
            Ok(body.trim().parse()?)
        })();
        match result {
            Ok(ip) => *answers.entry(ip).or_default() += 1,
            Err(e) => log::debug!("public IP from {host}: {e}"),
        }
    }
    answers
        .into_iter()
        .max_by_key(|(_, n)| *n)
        .map(|(ip, _)| ip)
        .ok_or_else(|| anyhow!("cannot detect the public IPv4 address; pass it with --public-ip"))
}

pub struct Network {
    #[allow(dead_code)] // keeps the ADNL node alive
    adnl: Arc<AdnlNode>,
    dht: Arc<DhtNode>,
    overlay: Arc<OverlayNode>,
    rldp: Arc<RldpNode>,
    pub zero_state: BlockIdExt,
}

impl Network {
    pub async fn start(global_config: &Path, port: u16, public_ip: Option<std::net::Ipv4Addr>) -> Result<Arc<Self>> {
        let config: TonNodeGlobalConfigJson =
            serde_json::from_reader(std::fs::File::open(global_config)?)
                .map_err(|e| anyhow!("cannot parse global config {}: {e}", global_config.display()))?;
        let zero_state = config.zero_state().map_err(|e| anyhow!("{e}"))?;
        let dht_nodes = config.get_dht_nodes_configs().map_err(|e| anyhow!("{e}"))?;

        let public_ip = match public_ip {
            Some(ip) => ip,
            None => tokio::task::spawn_blocking(detect_public_ip).await??,
        };
        log::info!("public IPv4 address: {public_ip}");
        let (_, adnl_config) = AdnlNodeConfig::with_ip_address_and_private_key_tags(
            &format!("{public_ip}:{port}"),
            vec![KEY_TAG_DHT, KEY_TAG_OVERLAY],
        )
        .map_err(|e| anyhow!("{e}"))?;
        let adnl = AdnlNode::with_config(adnl_config).await.map_err(|e| anyhow!("{e}"))?;
        let dht = DhtNode::with_params(adnl.clone(), KEY_TAG_DHT, None).map_err(|e| anyhow!("{e}"))?;
        let overlay = OverlayNode::with_adnl_node_and_zero_state(
            adnl.clone(),
            zero_state.file_hash.as_array(),
            KEY_TAG_OVERLAY,
        )
        .map_err(|e| anyhow!("{e}"))?;
        let rldp = RldpNode::with_adnl_node(adnl.clone(), vec![overlay.clone()]).map_err(|e| anyhow!("{e}"))?;
        AdnlNode::start(&adnl, vec![dht.clone(), overlay.clone(), rldp.clone()])
            .await
            .map_err(|e| anyhow!("{e}"))?;

        let mut static_peers = Vec::new();
        for node in dht_nodes.iter() {
            if let Some(key) = dht.add_peer_to_network(node, None).map_err(|e| anyhow!("{e}"))? {
                static_peers.push(key);
            }
        }
        log::info!("DHT: {} static nodes, searching for more...", static_peers.len());
        for peer in static_peers.iter() {
            match tokio::time::timeout(Duration::from_secs(10), dht.find_dht_nodes_in_network(peer, None)).await {
                Ok(Ok(_)) => (),
                Ok(Err(e)) => log::debug!("DHT node {peer} failed: {e}"),
                Err(_) => log::debug!("DHT node {peer} timed out"),
            }
        }
        let known = dht.get_known_nodes_of_network(10000, None).map_err(|e| anyhow!("{e}"))?.len();
        log::info!("DHT: {known} nodes known");
        if known == 0 {
            bail!("no DHT nodes answered; check UDP connectivity")
        }
        Ok(Arc::new(Self { adnl, dht, overlay, rldp, zero_state }))
    }

    /// Join the public overlay of the given workchain and collect peers from the DHT.
    pub async fn overlay_client(self: &Arc<Self>, workchain: i32, min_peers: usize) -> Result<Arc<OverlayClient>> {
        let shard = ever_block::SHARD_FULL as i64;
        let overlay_id = self.overlay.calc_overlay_short_id(workchain, shard).map_err(|e| anyhow!("{e}"))?;
        if workchain == -1 {
            self.overlay.add_local_workchain_overlay(None, &overlay_id, None)
        } else {
            self.overlay.add_other_workchain_overlay(None, &overlay_id, None)
        }
        .map_err(|e| anyhow!("{e}"))?;
        let client = Arc::new(OverlayClient {
            net: self.clone(),
            workchain,
            overlay_id,
            peers: Mutex::new(Vec::new()),
            failures: Mutex::new(HashMap::new()),
        });
        client.find_peers(min_peers).await?;
        Ok(client)
    }
}

/// Workchain overlay clients, joined only when something has to be downloaded.
pub struct WcClients {
    net: Arc<Network>,
    clients: HashMap<i32, Arc<OverlayClient>>,
}

impl WcClients {
    pub fn new(net: Arc<Network>) -> Self {
        Self { net, clients: HashMap::new() }
    }

    pub async fn get(&mut self, workchain: i32) -> Result<Arc<OverlayClient>> {
        if !self.clients.contains_key(&workchain) {
            let client = self.net.overlay_client(workchain, 30).await?;
            self.clients.insert(workchain, client);
        }
        Ok(self.clients[&workchain].clone())
    }
}

pub struct OverlayClient {
    net: Arc<Network>,
    pub workchain: i32,
    overlay_id: Arc<OverlayShortId>,
    peers: Mutex<Vec<Arc<KeyId>>>,
    failures: Mutex<HashMap<Arc<KeyId>, u32>>,
}

impl OverlayClient {
    const MAX_FAILURES: u32 = 5;

    pub async fn find_peers(&self, min_peers: usize) -> Result<()> {
        let mut iter = None;
        let started = Instant::now();
        loop {
            let nodes = DhtNode::find_overlay_nodes_in_network(&self.net.dht, &self.overlay_id, &mut iter, None)
                .await
                .map_err(|e| anyhow!("{e}"))?;
            for (ip, node) in nodes.iter() {
                if let Some(peer) = self.net.overlay.add_public_peer(ip, node, &self.overlay_id).map_err(|e| anyhow!("{e}"))? {
                    let mut peers = self.peers.lock().unwrap();
                    if !peers.contains(&peer) {
                        peers.push(peer);
                    }
                }
            }
            let count = self.peers.lock().unwrap().len();
            log::debug!("overlay wc{}: {count} peers", self.workchain);
            if count >= min_peers || iter.is_none() || started.elapsed() > Duration::from_secs(120) {
                log::info!("overlay wc{}: {count} peers", self.workchain);
                if count == 0 {
                    bail!("no peers found in overlay of workchain {}", self.workchain)
                }
                return Ok(());
            }
        }
    }

    fn all_peers(&self) -> Vec<Arc<KeyId>> {
        let failures = self.failures.lock().unwrap();
        let mut peers: Vec<_> = self
            .peers
            .lock()
            .unwrap()
            .iter()
            .filter(|p| failures.get(*p).copied().unwrap_or(0) < Self::MAX_FAILURES)
            .cloned()
            .collect();
        peers.shuffle(&mut rand::thread_rng());
        peers
    }

    fn mark(&self, peer: &Arc<KeyId>, ok: bool) {
        let mut failures = self.failures.lock().unwrap();
        let entry = failures.entry(peer.clone()).or_insert(0);
        if ok {
            *entry = 0
        } else {
            *entry += 1
        }
    }

    async fn adnl_query<Q, A>(&self, peer: &Arc<KeyId>, query: Q, timeout_ms: u64) -> Result<A>
    where
        Q: AnyBoxedSerialize,
        A: AnyBoxedSerialize,
    {
        let query = TaggedTlObject { object: TLObject::new(query), tag: 0 };
        let answer = self
            .net
            .overlay
            .query(peer, &query, &self.overlay_id, Some(timeout_ms))
            .await
            .map_err(|e| anyhow!("{e}"))?;
        let answer = answer.ok_or_else(|| anyhow!("no reply from {peer}"))?;
        answer.downcast::<A>().map_err(|obj| anyhow!("unexpected reply {obj:?} from {peer}"))
    }

    async fn rldp_query<Q: BoxedSerialize>(&self, peer: &Arc<KeyId>, query: &Q) -> Result<Vec<u8>> {
        let mut data = self.net.overlay.get_query_prefix(&self.overlay_id).map_err(|e| anyhow!("{e}"))?;
        serialize_boxed_append(&mut data, query).map_err(|e| anyhow!("{e}"))?;
        let (answer, _) = self
            .net
            .overlay
            .query_via_rldp(
                &self.net.rldp,
                peer,
                &TaggedByteSlice { object: &data, tag: 0 },
                Some(RLDP_MAX_ANSWER),
                None,
                &self.overlay_id,
            )
            .await
            .map_err(|e| anyhow!("{e}"))?;
        answer.ok_or_else(|| anyhow!("no RLDP reply from {peer}"))
    }

    /// `tonNode.getNextKeyBlockIds`. The answer is not trusted: every id is later
    /// backed by a downloaded proof.
    pub async fn next_key_block_ids(&self, block: &BlockIdExt, peer: &Arc<KeyId>) -> Result<Vec<BlockIdExt>> {
        let answer: KeyBlocks = self
            .adnl_query(peer, GetNextKeyBlockIds { block: block.clone(), max_size: 8 }, ADNL_TIMEOUT_MS)
            .await?;
        let answer = answer.only();
        if bool::from(answer.error.clone()) {
            bail!("peer {peer} reported an error for {block}")
        }
        Ok(answer.blocks.into_iter().collect())
    }

    pub fn random_peers(&self, count: usize) -> Vec<Arc<KeyId>> {
        let mut peers = self.all_peers();
        peers.truncate(count);
        peers
    }

    /// Download a masterchain key block proof (with signatures) or a proof link
    /// for a shard block.
    pub async fn download_proof(&self, block: &BlockIdExt, key_block: bool) -> Result<(BlockProofStuff, Vec<u8>)> {
        let mut last_err = anyhow!("no peers");
        for attempt in 0..30 {
            let peers = self.all_peers();
            let Some(peer) = peers.get(attempt % peers.len().max(1)).cloned() else {
                self.find_peers(10).await?;
                continue;
            };
            let result: Result<(BlockProofStuff, Vec<u8>)> = async {
                if key_block {
                    let prepared: PreparedProof = self
                        .adnl_query(
                            &peer,
                            PrepareKeyBlockProof { block: block.clone(), allow_partial: false.into() },
                            ADNL_TIMEOUT_MS,
                        )
                        .await?;
                    if !matches!(prepared, PreparedProof::TonNode_PreparedProof) {
                        bail!("peer {peer} has no proof for {block}: {prepared:?}")
                    }
                    let data = self.rldp_query(&peer, &DownloadKeyBlockProof { block: block.clone() }).await?;
                    let proof = BlockProofStuff::deserialize(block, data.clone(), false).map_err(|e| anyhow!("{e}"))?;
                    proof.check_proof_as_link().map_err(|e| anyhow!("{e}"))?;
                    Ok((proof, data))
                } else {
                    let prepared: PreparedProof = self
                        .adnl_query(
                            &peer,
                            PrepareBlockProof { block: block.clone(), allow_partial: true.into() },
                            ADNL_TIMEOUT_MS,
                        )
                        .await?;
                    if matches!(prepared, PreparedProof::TonNode_PreparedProofEmpty) {
                        bail!("peer {peer} has no proof link for {block}")
                    }
                    let data = self.rldp_query(&peer, &DownloadBlockProofLink { block: block.clone() }).await?;
                    let proof = BlockProofStuff::deserialize(block, data.clone(), true).map_err(|e| anyhow!("{e}"))?;
                    proof.check_proof_link().map_err(|e| anyhow!("{e}"))?;
                    Ok((proof, data))
                }
            }
            .await;
            match result {
                Ok(r) => {
                    self.mark(&peer, true);
                    return Ok(r);
                }
                Err(e) => {
                    log::debug!("proof {block} attempt {attempt}: {e}");
                    self.mark(&peer, false);
                    last_err = e;
                }
            }
        }
        bail!("cannot download proof for {block}: {last_err}")
    }

    /// Proof (with signatures) of an ordinary, non-key masterchain block.
    pub async fn download_mc_proof(&self, block: &BlockIdExt) -> Result<(BlockProofStuff, Vec<u8>)> {
        self.retry(&format!("proof {block}"), |peer| async move {
            let prepared: PreparedProof = self
                .adnl_query(&peer, PrepareBlockProof { block: block.clone(), allow_partial: false.into() }, ADNL_TIMEOUT_MS)
                .await?;
            if !matches!(prepared, PreparedProof::TonNode_PreparedProof) {
                bail!("peer {peer} has no proof for {block}: {prepared:?}")
            }
            let data = self.rldp_query(&peer, &DownloadBlockProof { block: block.clone() }).await?;
            let proof = BlockProofStuff::deserialize(block, data.clone(), false).map_err(|e| anyhow!("{e}"))?;
            proof.check_proof_as_link().map_err(|e| anyhow!("{e}"))?;
            Ok((proof, data))
        })
        .await
    }

    /// Run `f` against peers until it succeeds (at most 30 attempts).
    async fn retry<'a, T, F, Fut>(&'a self, what: &str, f: F) -> Result<T>
    where
        F: Fn(Arc<KeyId>) -> Fut,
        Fut: std::future::Future<Output = Result<T>> + 'a,
    {
        let mut last_err = anyhow!("no peers");
        for attempt in 0..30 {
            let peers = self.all_peers();
            let Some(peer) = peers.get(attempt % peers.len().max(1)).cloned() else {
                self.find_peers(10).await?;
                continue;
            };
            match f(peer.clone()).await {
                Ok(r) => {
                    self.mark(&peer, true);
                    return Ok(r);
                }
                Err(e) => {
                    log::debug!("{what} attempt {attempt}: {e}");
                    self.mark(&peer, false);
                    last_err = e;
                }
            }
        }
        bail!("{what}: {last_err}")
    }

    /// `tonNode.getArchiveInfo` + `tonNode.getArchiveSlice`: the archive package
    /// (100 masterchain blocks with their shard blocks and proofs) containing
    /// masterchain block `mc_seqno`. Packages are node-local files, so all slices
    /// come from the same peer. `None` if no peer has it (e.g. not finished yet).
    pub async fn download_archive(&self, mc_seqno: u32) -> Result<Option<Vec<u8>>> {
        const CHUNK: i32 = 1 << 21;
        let mut not_found = 0;
        let mut last_err = anyhow!("no peers");
        for attempt in 0..20 {
            let peers = self.all_peers();
            let Some(peer) = peers.get(attempt % peers.len().max(1)).cloned() else {
                self.find_peers(10).await?;
                continue;
            };
            let result: Result<Option<Vec<u8>>> = async {
                let info: ArchiveInfo = self
                    .adnl_query(&peer, GetArchiveInfo { masterchain_seqno: mc_seqno as i32 }, ADNL_TIMEOUT_MS)
                    .await?;
                let ArchiveInfo::TonNode_ArchiveInfo(info) = info else { return Ok(None) };
                let mut data = Vec::new();
                loop {
                    let query = GetArchiveSlice { archive_id: info.id, offset: data.len() as i64, max_size: CHUNK };
                    let mut part = None;
                    for _ in 0..5 {
                        match self.rldp_query(&peer, &query).await {
                            Ok(p) => {
                                part = Some(p);
                                break;
                            }
                            Err(e) => log::debug!("archive {} slice at {}: {e}", info.id, data.len()),
                        }
                    }
                    let part = part.ok_or_else(|| anyhow!("archive {} from {peer}: slice failed", info.id))?;
                    let len = part.len();
                    data.extend_from_slice(&part);
                    if len < CHUNK as usize {
                        return Ok(Some(data));
                    }
                }
            }
            .await;
            match result {
                Ok(Some(data)) => {
                    self.mark(&peer, true);
                    return Ok(Some(data));
                }
                Ok(None) => {
                    not_found += 1;
                    if not_found >= 4 {
                        return Ok(None);
                    }
                }
                Err(e) => {
                    self.mark(&peer, false);
                    last_err = e;
                }
            }
        }
        bail!("archive for mc block {mc_seqno}: {last_err}")
    }

    /// `tonNode.prepareBlock` + `tonNode.downloadBlockFull`: block and its proof (link).
    pub async fn download_block_full(&self, id: &BlockIdExt) -> Result<FullBlock> {
        self.retry(&format!("block {id}"), |peer| async move {
            let prepared: Prepared = self.adnl_query(&peer, PrepareBlock { block: id.clone() }, ADNL_TIMEOUT_MS).await?;
            if !matches!(prepared, Prepared::TonNode_Prepared) {
                bail!("peer {peer} has no block {id}")
            }
            let data = self.rldp_query(&peer, &DownloadBlockFull { block: id.clone() }).await?;
            FullBlock::parse(&data, Some(id))
        })
        .await
    }

    /// `tonNode.downloadNextBlockFull`: the block following `prev` in its chain.
    pub async fn download_next_block_full(&self, prev: &BlockIdExt) -> Result<FullBlock> {
        self.retry(&format!("next block after {prev}"), |peer| async move {
            let data = self.rldp_query(&peer, &DownloadNextBlockFull { prev_block: prev.clone() }).await?;
            FullBlock::parse(&data, None)
        })
        .await
    }

    /// Ask peers (in parallel) whether they can serve the persistent state of `block`
    /// relative to masterchain block `mc_block`.
    pub async fn peers_with_state(self: &Arc<Self>, block: &BlockIdExt, mc_block: &BlockIdExt, want: usize) -> Vec<Arc<KeyId>> {
        let mut found = Vec::new();
        let mut asked = HashSet::new();
        for _round in 0..3 {
            let candidates: Vec<_> = self.all_peers().into_iter().filter(|p| !asked.contains(p)).collect();
            if candidates.is_empty() {
                let _ = self.find_peers(asked.len() + 20).await;
                continue;
            }
            let mut tasks = Vec::new();
            for peer in candidates.into_iter().take(40) {
                asked.insert(peer.clone());
                let this = self.clone();
                let (block, mc_block) = (block.clone(), mc_block.clone());
                tasks.push(tokio::spawn(async move {
                    let answer: Result<PreparedState> = this
                        .adnl_query(&peer, PreparePersistentState { block, masterchain_block: mc_block }, 5000)
                        .await;
                    (peer, answer)
                }));
            }
            for task in tasks {
                if let Ok((peer, answer)) = task.await {
                    match answer {
                        Ok(PreparedState::TonNode_PreparedState) => found.push(peer),
                        Ok(_) => (),
                        Err(e) => {
                            log::debug!("preparePersistentState {peer}: {e}");
                            self.mark(&peer, false)
                        }
                    }
                }
            }
            if found.len() >= want {
                break;
            }
        }
        found
    }

    /// Every node serializes its persistent state itself and the cell order differs
    /// between node versions, so slices from different peers do not fit together.
    /// Group peers by the hash of slice 0 and keep the largest group (or the group
    /// already used by a previous, interrupted download).
    async fn same_serialization_peers(
        self: &Arc<Self>,
        block: &BlockIdExt,
        mc_block: &BlockIdExt,
        peers: Vec<Arc<KeyId>>,
        slices_dir: &Path,
    ) -> Result<Vec<Arc<KeyId>>> {
        let mut tasks = Vec::new();
        for peer in peers {
            let this = self.clone();
            let query = DownloadPersistentStateSlice {
                block: block.clone(),
                masterchain_block: mc_block.clone(),
                offset: 0,
                max_size: SLICE_SIZE as i64,
            };
            tasks.push(tokio::spawn(async move {
                let data = tokio::time::timeout(Duration::from_secs(60), this.rldp_query(&peer, &query)).await;
                (peer, data)
            }));
        }
        let mut groups: HashMap<String, (Vec<u8>, Vec<Arc<KeyId>>)> = HashMap::new();
        for task in tasks {
            if let Ok((peer, Ok(Ok(data)))) = task.await {
                use sha2::Digest;
                let hash = hex::encode(sha2::Sha256::digest(&data));
                groups.entry(hash).or_insert_with(|| (data, Vec::new())).1.push(peer);
            }
        }
        if groups.is_empty() {
            bail!("no peer returned the first slice of {block}")
        }
        let marker = slices_dir.join("serialization");
        let stored = std::fs::read_to_string(&marker).ok();
        let chosen = match stored.as_ref().filter(|h| groups.contains_key(*h)) {
            Some(hash) => hash.clone(),
            None => {
                if stored.is_some() {
                    log::warn!("no peer has the serialization of the interrupted download any more; starting over");
                    std::fs::remove_dir_all(slices_dir)?;
                    std::fs::create_dir_all(slices_dir)?;
                }
                groups.iter().max_by_key(|(_, (_, p))| p.len()).map(|(h, _)| h.clone()).unwrap()
            }
        };
        let sizes: Vec<_> = groups.values().map(|(_, p)| p.len()).collect();
        let (data, peers) = groups.remove(&chosen).unwrap();
        log::info!("state {}: {} serialization variants among peers {:?}, using {} peers", block.shard(), sizes.len(), sizes, peers.len());
        std::fs::write(&marker, &chosen)?;
        std::fs::write(slices_dir.join("000000.bin"), data)?;
        std::fs::write(slices_dir.join("000000.done"), b"")?;
        Ok(peers)
    }

    /// Download a persistent state BOC with several parallel workers into
    /// `<dir>/slices/*`, resuming already downloaded slices, then concatenate it.
    pub async fn download_state(
        self: &Arc<Self>,
        block: &BlockIdExt,
        mc_block: &BlockIdExt,
        dir: &Path,
        out_file: &Path,
    ) -> Result<()> {
        let slices_dir = dir.join(format!("slices_{}_{:016x}_{}", block.shard().workchain_id(), block.shard().shard_prefix_with_tag(), block.seq_no()));
        std::fs::create_dir_all(&slices_dir)?;
        let peers = self.peers_with_state(block, mc_block, 16).await;
        if peers.is_empty() {
            bail!("no peer serves persistent state {block} (mc {mc_block})")
        }
        log::info!("state {}: {} peers have it", block, peers.len());
        let peers = Arc::new(self.same_serialization_peers(block, mc_block, peers, &slices_dir).await?);
        let next = Arc::new(AtomicUsize::new(0));
        let total: Arc<Mutex<Option<usize>>> = Arc::new(Mutex::new(None));
        let downloaded = Arc::new(AtomicUsize::new(0));
        let workers = (peers.len() * 3).clamp(3, 16);
        let mut tasks = Vec::new();
        for worker in 0..workers {
            let (this, peers, next, total, downloaded) = (self.clone(), peers.clone(), next.clone(), total.clone(), downloaded.clone());
            let (block, mc_block, slices_dir) = (block.clone(), mc_block.clone(), slices_dir.clone());
            tasks.push(tokio::spawn(async move {
                loop {
                    let index = next.fetch_add(1, Ordering::SeqCst);
                    if matches!(*total.lock().unwrap(), Some(t) if index >= t) {
                        return Ok::<(), anyhow::Error>(());
                    }
                    let path = slices_dir.join(format!("{index:06}.bin"));
                    let done = slices_dir.join(format!("{index:06}.done"));
                    let len = if done.exists() {
                        std::fs::metadata(&path)?.len() as usize
                    } else {
                        let mut attempt = worker;
                        let data = loop {
                            let peer = &peers[attempt % peers.len()];
                            let query = DownloadPersistentStateSlice {
                                block: block.clone(),
                                masterchain_block: mc_block.clone(),
                                offset: (index * SLICE_SIZE) as i64,
                                max_size: SLICE_SIZE as i64,
                            };
                            match this.rldp_query(peer, &query).await {
                                Ok(data) => break data,
                                Err(e) => {
                                    if matches!(*total.lock().unwrap(), Some(t) if index >= t) {
                                        // past the end of the state, found by another worker
                                        return Ok(());
                                    }
                                    log::debug!("slice {index} from {peer}: {e}");
                                    attempt += 1;
                                    if attempt > worker + 10 * peers.len() {
                                        bail!("slice {index} of {block}: {e}")
                                    }
                                    tokio::time::sleep(Duration::from_millis(200)).await;
                                }
                            }
                        };
                        std::fs::write(&path, &data)?;
                        std::fs::write(&done, b"")?;
                        data.len()
                    };
                    let mb = downloaded.fetch_add(len, Ordering::SeqCst) + len;
                    if index % 64 == 0 {
                        log::info!("state {}: {} MiB downloaded", block.shard(), mb >> 20);
                    }
                    if len < SLICE_SIZE {
                        let mut total = total.lock().unwrap();
                        let t = total.get_or_insert(index + 1);
                        *t = (*t).min(index + 1);
                    }
                }
            }));
        }
        for task in tasks {
            task.await??;
        }
        let total = total.lock().unwrap().ok_or_else(|| anyhow!("state size is unknown"))?;
        let mut out = std::io::BufWriter::new(std::fs::File::create(out_file.with_extension("tmp"))?);
        for index in 0..total {
            let path = slices_dir.join(format!("{index:06}.bin"));
            std::io::copy(&mut std::fs::File::open(&path)?, &mut out)?;
            // keep the disk footprint at ~1x the state size
            std::fs::remove_file(&path)?;
            let _ = std::fs::remove_file(slices_dir.join(format!("{index:06}.done")));
        }
        drop(out);
        std::fs::rename(out_file.with_extension("tmp"), out_file)?;
        std::fs::remove_dir_all(&slices_dir)?;
        log::info!("state {} saved to {}", block, out_file.display());
        Ok(())
    }
}
