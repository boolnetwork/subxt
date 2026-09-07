#[subxt::subxt(runtime_metadata_path = "examples/metadata-new.scale")]
pub mod polkadot {}

use sp_keyring::AccountKeyring;
use subxt::{rpc_params, tx::PairSigner, Config, OnlineClient};
use subxt::utils::{AccountId32, MultiAddress, MultiSignature};
use subxt::config::substrate::{BlakeTwo256, SubstrateHeader};
use subxt::config::polkadot::PolkadotExtrinsicParams;
use sp_core::Pair;
use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};
use codec::{Compact, Encode};
use jsonrpsee::client_transport::ws::{Uri, WsTransportClientBuilder};
use jsonrpsee::core::client::ClientBuilder;
use subxt::rpc::types;
use sp_core::H256;
use sp_core::hashing;

pub enum PolkadotConfig {}

impl Config for PolkadotConfig {
    type Index = u64;
    type Hash = H256;
    type AccountId = AccountId32;
    type Address = MultiAddress<Self::AccountId, ()>;
    type Signature = MultiSignature;
    type Hasher = BlakeTwo256;
    type Header = SubstrateHeader<u32, BlakeTwo256>;
    type ExtrinsicParams = PolkadotExtrinsicParams<Self>;
}

struct ThreadStats {
    sent: usize,
    ok: usize,
    err: usize,
    send_micros: u128,
    full_micros: u128,
}

async fn ws_online_client(url: &str, max_concurrent: usize, timeout: Duration) -> OnlineClient<PolkadotConfig> {
    let uri: Uri = url.parse().expect("invalid WS url");
    let (sender, receiver) = WsTransportClientBuilder::default()
        .build(uri)
        .await
        .expect("WS connect failed");
    let client = ClientBuilder::default()
        .max_concurrent_requests(max_concurrent)
        .request_timeout(timeout)
        .max_notifs_per_subscription(4096)
        .build_with_tokio(sender, receiver);
    OnlineClient::from_rpc_client(Arc::new(client)).await.expect("OnlineClient init failed")
}

async fn submit_chunk(api: OnlineClient<PolkadotConfig>, bytes: Vec<u8>, thread: usize, chunk_i: usize, txs: usize) -> (usize, usize) {
    let bytes: types::Bytes = bytes.into();
    match api
        .rpc()
        .request::<Vec<Result<H256, String>>>("author_submitExtrinsics", rpc_params![bytes])
        .await
    {
        Ok(results) => {
            let mut ok = 0;
            for (tx_i, result) in results.into_iter().enumerate() {
                match result {
                    Ok(_) => ok += 1,
                    Err(e) => println!("alice{thread} chunk: {chunk_i} tx: {tx_i} Error: {e}"),
                }
            }
            (ok, txs - ok)
        },
        Err(e) => {
            println!("alice{thread} chunk: {chunk_i} Error: {e:?}");
            (0, txs)
        },
    }
}

#[tokio::main]
async fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.len() < 2 {
        panic!("invalid params");
    }
    match args[1].as_str() {
        "storage_prefix" => storage_prefix(args),
        "transfer" => transfer(args).await,
        _ => panic!("invalid mission"),
    }
}

fn storage_prefix(args: Vec<String>) {
    if args.len() < 4 {
        panic!("invalid params");
    }
    let storages = args[3..].to_vec();
    let pallet_hash = hashing::twox_128(args[2].as_bytes());
    for storage in storages {
        let storage_hash = hashing::twox_128(storage.as_bytes());
        let mut final_key = [0u8; 32];
        final_key[..16].copy_from_slice(&pallet_hash);
        final_key[16..].copy_from_slice(&storage_hash);
        println!("{} {storage}\n    {:?}\n    {final_key:?}", args[2], hex::encode(final_key));
    }
}

async fn transfer(args: Vec<String>) {
    if args.len() < 4 {
        panic!("invalid params");
    }
    let threads: usize = args[2].parse().unwrap();
    let thread_transaction: usize = args[3].parse().unwrap();
    let mut submit_batch_size: usize = 1;
    if args.len() >= 5 {
        submit_batch_size = args[4].parse().unwrap();
        submit_batch_size = submit_batch_size.max(1);
    }
    let mut loop_times = 1u8;
    if args.len() >= 6 {
        loop_times = args[5].parse().unwrap();
    }
    let mut wait = false;
    if args.len() >= 7 {
        wait = args[6].eq_ignore_ascii_case("wait");
    }
    let ws_url = env::var("WS_RPC_URL").unwrap_or_else(|_| "ws://127.0.0.1:9944".into());
    let max_concurrent: usize = env::var("WS_MAX_CONCURRENT")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(2048);
    let timeout_secs: u64 = env::var("WS_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(300);
    let max_inflight: usize = env::var("WS_MAX_INFLIGHT")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(1024)
        .min(max_concurrent);
    let inflight_limit = Arc::new(tokio::sync::Semaphore::new(max_inflight));
    let mode_name = if wait { "wait" } else { "nowait" };
    println!(
        "threads {threads} submit_batch_size {submit_batch_size} loop_times {loop_times} mode {mode_name} url {ws_url} max_concurrent {max_concurrent} max_inflight {max_inflight}"
    );
    let mut send_accs: Vec<sp_core::sr25519::Pair> = vec![];
    for i in 0..threads {
        send_accs.push(AccountKeyring::numeric(i));
    }
    let timeout = Duration::from_secs(timeout_secs);
    let api = ws_online_client(&ws_url, max_concurrent, timeout).await;
    let from = PairSigner::new(AccountKeyring::Alice.pair());
    let mut account_nonce = api.tx().account_nonce(&AccountId32::from(AccountKeyring::Alice.pair().public())).await.unwrap();
    let mut progresses = vec![];
    for acc in &send_accs.clone() {
        let dest: AccountId32 = AccountId32::from(acc.public());
        let account_activate_tx = polkadot::tx().quota().activate_account(dest.clone().into());
        api.tx().create_signed_with_nonce(
            &account_activate_tx,
            &from,
            account_nonce,
            Default::default(),
        )
            .unwrap()
            .submit()
            .await
            .unwrap();
        account_nonce += 1;
        let balance_transfer_tx = polkadot::tx().balances().transfer_allow_death(dest.clone().into(), 10_000_000_000_000);
        let progress = api.tx().create_signed_with_nonce(
            &balance_transfer_tx,
            &from,
            account_nonce,
            Default::default(),
        )
            .unwrap()
            .submit()
            .await
            .unwrap();
        account_nonce += 1;
        progresses.push(progress);
    }
    println!("Alice try transfer finished");
    let mut tasks: Vec<tokio::task::JoinHandle<ThreadStats>> = vec![];
    let total_start = Arc::new(tokio::sync::RwLock::new(None::<Instant>));
    let prepare_count = Arc::new(tokio::sync::RwLock::new(0usize));
    for i in 0..threads {
        let total_start_i = total_start.clone();
        let prepare_count_i = prepare_count.clone();
        let inflight_limit = inflight_limit.clone();
        let ws_url = ws_url.clone();
        let from = send_accs[i].clone();
        let task = tokio::spawn(async move {
            let api = ws_online_client(&ws_url, max_concurrent, timeout).await;
            let storage_query = polkadot::storage().system().account(&AccountId32::from(from.public()));
            loop {
                if let Some(account_info) = api
                    .storage()
                    .at_latest()
                    .await
                    .unwrap()
                    .fetch(&storage_query)
                    .await
                    .unwrap()
                {
                    if account_info.data.free > 0 {
                        if account_info.quota == u32::MAX {
                            panic!("Alice{i} address {} is frozen", AccountId32::from(from.public()));
                        } else if account_info.quota >= 1 + thread_transaction as u32 * loop_times as u32 {
                            break;
                        } else {
                            panic!("Alice{i} address {} has quota: {} not enough for {} transaction", AccountId32::from(from.public()), account_info.quota, thread_transaction * loop_times as usize);
                        }
                    }
                } else {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
            let mut account_nonce = api.tx().account_nonce(&AccountId32::from(from.public())).await.unwrap();
            let mut stats = ThreadStats { sent: 0, ok: 0, err: 0, send_micros: 0, full_micros: 0 };
            for round in 1..=loop_times {
                let transactions: Vec<_> = (0..thread_transaction).map(|t| {
                    let dest = AccountId32::from(AccountKeyring::numeric(i * 10000 + 100000 + t).public());
                    let balance_transfer_tx = polkadot::tx().balances().transfer(dest.into(), 10_000);
                    let tx = api
                        .tx()
                        .create_signed_with_nonce(
                            &balance_transfer_tx,
                            &PairSigner::new(from.clone()),
                            account_nonce,
                            Default::default(),
                        )
                        .unwrap();
                    account_nonce += 1;
                    (t, tx, account_nonce - 1)
                })
                    .collect();
                *prepare_count_i.write().await += 1;
                loop {
                    if *prepare_count_i.write().await % threads == 0 {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_micros(10)).await;
                }
                let mut total_start_i = total_start_i.write().await;
                if total_start_i.is_none() {
                    *total_start_i = Some(std::time::Instant::now());
                }
                drop(total_start_i);
                let sent_r: usize = thread_transaction;
                let mut ok_r = 0usize;
                let mut err_r = 0usize;
                let start = std::time::Instant::now();
                let mut inflight: Vec<tokio::task::JoinHandle<(usize, usize)>> = vec![];
                for (chunk_i, chunk) in transactions.chunks(submit_batch_size).enumerate() {
                    let txs = chunk.len();
                    let calls: Vec<_> = chunk
                        .iter()
                        .map(|(_, transaction, _)| transaction.encoded().to_vec())
                        .collect::<Vec<_>>()
                        .concat();
                    let mut encoded_txs = Vec::new();
                    Compact(txs as u32).encode_to(&mut encoded_txs);
                    encoded_txs.extend(calls);
                    if wait {
                        let (ok, err) = submit_chunk(api.clone(), encoded_txs, i, chunk_i, txs).await;
                        ok_r += ok;
                        err_r += err;
                    } else {
                        let api = api.clone();
                        let inflight_limit = inflight_limit.clone();
                        inflight.push(tokio::spawn(async move {
                            let _permit = inflight_limit.acquire_owned().await.expect("inflight semaphore closed");
                            submit_chunk(api, encoded_txs, i, chunk_i, txs).await
                        }));
                    }
                }
                let send_elapsed = start.elapsed().as_micros();
                for handle in inflight {
                    match handle.await {
                        Ok((ok, err)) => {
                            ok_r += ok;
                            err_r += err;
                        },
                        Err(e) => {
                            println!("alice{i} join Error: {e:?}");
                        },
                    }
                }
                let full_elapsed = start.elapsed().as_micros();
                println!(
                    "alice{i} round {round} sent {sent_r} ok {ok_r} err {err_r} send {send_elapsed} micros full {full_elapsed} micros"
                );
                stats.sent += sent_r;
                stats.ok += ok_r;
                stats.err += err_r;
                stats.send_micros += send_elapsed;
                stats.full_micros += full_elapsed;
            }
            stats
        });
        tasks.push(task);
    }
    let mut thread_stats = vec![];
    for task in tasks {
        thread_stats.push(task.await.unwrap());
    }
    let total_end = std::time::Instant::now();
    let sent: usize = thread_stats.iter().map(|s| s.sent).sum();
    let ok: usize = thread_stats.iter().map(|s| s.ok).sum();
    let err: usize = thread_stats.iter().map(|s| s.err).sum();
    let max_send = thread_stats.iter().map(|s| s.send_micros).max().unwrap_or(1).max(1);
    let max_full = thread_stats.iter().map(|s| s.full_micros).max().unwrap_or(1).max(1);
    println!("Total sent: {sent} ok: {ok} err: {err}");
    println!("Send-phase tps: {}", sent as u128 * 1_000_000 / max_send);
    println!("Confirmed tps: {}", ok as u128 * 1_000_000 / max_full);
    let total_start = *total_start.read().await;
    if let Some(start) = total_start {
        let total_time = total_end.duration_since(start).as_micros().max(1);
        println!("Overall tps: {}", ok as u128 * 1_000_000 / total_time);
    }
}
