#[subxt::subxt(runtime_metadata_path = "examples/metadata-new.scale")]
pub mod polkadot {}

use sp_keyring::AccountKeyring;
use subxt::{rpc_params, tx::PairSigner, Config, OnlineClient};
use subxt::utils::{AccountId32, MultiAddress, MultiSignature};
use subxt::config::substrate::{BlakeTwo256, SubstrateHeader};
use subxt::config::polkadot::PolkadotExtrinsicParams;
use sp_core::Pair;
use std::env;
use codec::{Compact, Encode};
use subxt::rpc::types;
use bnk_pallets_api::BoolConfig;
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
    println!("threads {threads} submit_batch_size {submit_batch_size} loop_times {loop_times}");
    let mut send_accs: Vec<sp_core::sr25519::Pair> = vec![];
    for i in 0..threads {
        send_accs.push(AccountKeyring::numeric(i));
    }
    // Create a new API client, configured to talk to Polkadot nodes.
    let api = OnlineClient::<PolkadotConfig>::new().await.unwrap();
    let from = PairSigner::new(AccountKeyring::Alice.pair());
    let mut account_nonce = api.tx().account_nonce(&AccountId32::from(AccountKeyring::Alice.pair().public())).await.unwrap();
    let mut progresses = vec![];
    for acc in &send_accs.clone() {
        let dest: AccountId32 = AccountId32::from(acc.public());
        let account_activate_tx = polkadot::tx().quota().activate_account(dest.clone().into());
        let progress = api.tx().create_signed_with_nonce(
            &account_activate_tx,
            &from,
            account_nonce,
            Default::default(),
        )
            .unwrap()
            .submit()
            .await
            .unwrap();
        println!("Alice try activate address {dest}");
        account_nonce += 1;
        let balance_transfer_tx = polkadot::tx().balances().transfer(dest.clone().into(), 10_000_000_000_000);
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
        println!("Alice try transfer to address {dest}");
        account_nonce += 1;
        progresses.push(progress);
    }
    let mut tasks: Vec<tokio::task::JoinHandle<Vec<(usize, u128)>>> = vec![];
    let total_start = std::sync::Arc::new(tokio::sync::RwLock::new(None));
    let prepare_count = std::sync::Arc::new(tokio::sync::RwLock::new(0usize));
    for i in 0..threads {
        let total_start_i = total_start.clone();
        let prepare_count_i = prepare_count.clone();
        let from = send_accs[i].clone();
        let task = tokio::spawn(async move {
            let api = OnlineClient::<PolkadotConfig>::new().await.unwrap();
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
                            println!("Alice{i} address {} has quota: {} balance: {}", AccountId32::from(from.public()), account_info.quota, account_info.data.free);
                            break;
                        } else {
                            panic!("Alice{i} address {} has quota: {} not enough for {} transaction", AccountId32::from(from.public()), account_info.quota, thread_transaction * loop_times as usize);
                        }
                        // println!("Alice{i} address {} has balance: {}", AccountId32::from(from.public()), account_info.data.free);
                        // break;
                    }
                } else {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
            let mut account_nonce = api.tx().account_nonce(&AccountId32::from(from.public())).await.unwrap();
            let mut round_txs: Vec<_> = Vec::new();
            for round in 1..=loop_times {
                println!("Alice{i} start round {round}");
                let prepare_start = std::time::Instant::now();
                let transactions: Vec<_> = (0..thread_transaction).map(|t| {
                    // Submit the balance transfer extrinsic from Alice, and wait for it to be successful
                    // and in a finalized block. We get back the extrinsic events if all is well.
                    let dest = AccountId32::from(AccountKeyring::numeric(i * 10000  + 100000 + t).public());
                    let balance_transfer_tx = polkadot::tx().balances().transfer(dest.into(), 10_000);
                    let tx = api
                        .tx()
                        .create_signed_with_nonce(
                            &balance_transfer_tx,
                            &PairSigner::new(from.clone()),
                            // sp_timestamp::Timestamp::current().as_millis(),
                            account_nonce,
                            Default::default(),
                        )
                        .unwrap();
                    account_nonce += 1;
                    (t, tx, account_nonce - 1)
                })
                    .collect();
                println!("Alice{i} prepare {thread_transaction} transactions in {} micros", prepare_start.elapsed().as_micros());
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
                let start = std::time::Instant::now();
                let mut txs = thread_transaction;
                if submit_batch_size == 1 {
                    for (tx_i, transactions, nonce) in transactions {
                        let tx_number = tx_i + 1;
                        if let Err(e) = transactions.submit().await {
                            txs = tx_number;
                            println!("alice{i} nonce: {nonce} Error: {e:?}");
                            break;
                        }
                        if tx_number % 100 == 0 {
                            println!("alice{i} tx: {tx_number}, tps: {}", (tx_number) as u128 * 1000 / start.elapsed().as_millis());
                        }
                    }
                } else {
                    for (chunk_i, chunk) in transactions.chunks(submit_batch_size).enumerate() {
                        let mut tx_number = 0;
                        let mut nonce = 0;
                        let calls: Vec<_> = chunk
                            .iter()
                            .map(|(tx_i, transaction, n)| {
                                tx_number = tx_i + 1;
                                nonce = *n;
                                transaction.encoded().to_vec()
                            })
                            .collect::<Vec<_>>()
                            .concat();
                        let mut encoded_txs = Vec::new();
                        Compact(chunk.len() as u32).encode_to(&mut encoded_txs);
                        encoded_txs.extend(calls);
                        let bytes: types::Bytes = encoded_txs.into();
                        let params = rpc_params![bytes];
                        match api.rpc().request::<Vec<Result<<BoolConfig as Config>::Hash, String>>>("author_submitExtrinsics", params).await {
                            Err(e) => {
                                println!("alice{i} nonce: {nonce} chunk: {chunk_i} Error: {e:?}");
                                break;
                            }
                            Ok(results) => for (tx_i, result) in results.into_iter().enumerate() {
                                match result {
                                    Ok(_) => txs += 1,
                                    Err(e) => {
                                        println!("alice{i} nonce: {nonce} chunk: {chunk_i} tx: {tx_i} Error: {e:?}");
                                    }
                                }
                            }
                        }
                        let time = start.elapsed().as_micros();
                        println!("alice{i} chunk: {chunk_i} tx: {tx_number} time: {time} micros, tps: {}", tx_number as u128 * 1000_000 / time);
                    }
                }
                let time = start.elapsed().as_micros();
                println!("alice{i} tx: {} time: {time} micros, tps: {} ", i + 1, txs as u128 * 1000_000 / time);
                round_txs.push((txs, time));
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            round_txs
        });
        tasks.push(task);
    }
    let mut thread_rounds = vec![];
    for task in tasks {
        thread_rounds.push(task.await.unwrap());
    }
    for round in 0..loop_times as usize {
        let total = thread_rounds.iter().map(|r| r[round].0).sum::<usize>();
        let time = thread_rounds.iter().map(|r| r[round].1).max().unwrap();
        println!("Round {} total tx: {total} time: {time} micros, tps: {}", round + 1, total as u128 * 1000_000 / time);
    }
}
