use std::hint::black_box;
use std::sync::Arc;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use fjall::Database;
use futures::stream;
use openraft::{RaftSnapshotBuilder, storage::RaftStateMachine};
use tempfile::TempDir;
use tokio::runtime::Runtime;

use openstack_keystone_distributed_storage::pb::raft::Entry;
use openstack_keystone_distributed_storage::store_command::{
    Mutation, MutationInner, StoreCommand,
};
use openstack_keystone_distributed_storage::{FjallStateMachine, Metadata, Nonce};

fn bench_state_machine(c: &mut Criterion) {
    let db_path = TempDir::new().unwrap();
    let snapshot_dir = db_path.path().join("snapshots");
    let db = Database::builder(db_path).open().unwrap();
    let db = Arc::new(db);
    let sm = Arc::new(FjallStateMachine::new(db, snapshot_dir).unwrap());

    c.bench_function("get_db", |b| {
        b.iter(|| sm.db());
    });
    c.bench_function("get_data_keyspace", |b| {
        b.iter(|| sm.data());
    });

    c.bench_function("get_keyspace", |b| {
        b.iter(|| sm.keyspace("index"));
    });

    let rt = Runtime::new().unwrap();
    c.bench_with_input(
        BenchmarkId::new("build_snapshot", "default"),
        &sm,
        |b, sm| {
            b.to_async(&rt).iter_batched(
                // init
                || sm.clone(),
                // run
                |mut sm| async move {
                    let _ = sm.build_snapshot().await;
                    black_box(sm);
                },
                BatchSize::PerIteration,
            );
        },
    );
    let mut group = c.benchmark_group("Command_Serde");
    let set_transaction = StoreCommand::Transaction(vec![
        MutationInner::convert(
            Mutation::set("foo", "bar", Metadata::new(), Some("data"), None).unwrap(),
            Nonce::default(),
        )
        .unwrap(),
    ])
    .pack()
    .unwrap();
    let remove_transaction = StoreCommand::Transaction(vec![
        MutationInner::convert(
            Mutation::remove("foo", Some("data")).unwrap(),
            Nonce::default(),
        )
        .unwrap(),
    ])
    .pack()
    .unwrap();
    group.bench_with_input(BenchmarkId::new("apply", "set"), &sm, |b, sm| {
        b.to_async(&rt).iter_batched(
            // init
            || {
                let data = vec![Ok((
                    Entry {
                        term: 1,
                        index: 2,
                        app_data: Some(set_transaction.clone()),
                        membership: None,
                    },
                    None,
                ))];
                (sm.clone(), stream::iter(data))
            },
            // run
            |(mut sm, strm)| async move {
                let _ = sm.apply(strm).await;
                black_box(sm);
            },
            BatchSize::PerIteration,
        );
    });
    group.bench_with_input(BenchmarkId::new("apply", "remove"), &sm, |b, sm| {
        b.to_async(&rt).iter_batched(
            // init
            || {
                let data = vec![Ok((
                    Entry {
                        term: 1,
                        index: 2,
                        app_data: Some(remove_transaction.clone()),
                        membership: None,
                    },
                    None,
                ))];
                (sm.clone(), stream::iter(data))
            },
            // run
            |(mut sm, strm)| async move {
                let _ = sm.apply(strm).await;
                black_box(sm);
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

criterion_group!(benches, bench_state_machine);
criterion_main!(benches);
