#![cfg(feature = "bench_internals")]
use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use openstack_keystone_distributed_storage::{Metadata, store_command::*};

fn bench_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("Payload_encryption");

    let remove_cmd = StoreCommand::Transaction(vec![
        MutationInner::convert(Mutation::remove("foo", Some("bar"), None)).unwrap(),
    ]);
    let set_cmd = StoreCommand::Transaction(vec![
        MutationInner::convert(
            Mutation::set("foo", "bar", Metadata::new(), Some("bar"), None).unwrap(),
        )
        .unwrap(),
    ]);
    group.bench_with_input(
        BenchmarkId::new("pack", "remove_cmd"),
        &remove_cmd,
        |b, data| {
            b.iter(|| data.pack().unwrap());
        },
    );
    group.bench_with_input(BenchmarkId::new("pack", "set_cmd"), &set_cmd, |b, data| {
        b.iter(|| data.pack().unwrap());
    });
    let packed = remove_cmd.pack().unwrap();
    group.bench_with_input(
        BenchmarkId::new("unpack", "remove_cmd"),
        &packed,
        |b, data| {
            b.iter(|| StoreCommand::unpack(black_box(data)).unwrap());
        },
    );
    let packed = set_cmd.pack().unwrap();
    group.bench_with_input(BenchmarkId::new("unpack", "set_cmd"), &packed, |b, data| {
        b.iter(|| StoreCommand::unpack(black_box(data)).unwrap());
    });

    group.finish();
}

criterion_group!(benches, bench_encryption);
criterion_main!(benches);
