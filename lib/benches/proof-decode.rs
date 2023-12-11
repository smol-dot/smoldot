// Smoldot
// Copyright (C) 2023  Pierre Krieger
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use rand::Rng as _;

fn benchmark_proof_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof-decode");

    struct Proof<'a> {
        data: &'a [u8],
        trie_root: [u8; 32],
    }

    let proofs: &[Proof] = &[
        Proof {
            data: &include_bytes!("./proof-decode-small")[..],
            trie_root: hex::decode(
                "29d0d972cd27cbc511e9589fcb7a4506d5eb6a9e8df205f00472e5ab354a4e17",
            )
            .unwrap()
            .try_into()
            .unwrap(),
        },
        Proof {
            data: &include_bytes!("./proof-decode-large")[..],
            trie_root: hex::decode(
                "886ca67c0e8d0003e2531bb25b1da0fe2f80d4b9eb6719e819f363265bd670fa",
            )
            .unwrap()
            .try_into()
            .unwrap(),
        },
    ];

    for proof in proofs {
        group.throughput(Throughput::Bytes(proof.data.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("decode", proof.data.len()),
            proof,
            |b, i| {
                b.iter(|| {
                    smoldot::trie::proof_decode::decode_and_verify_proof(
                        smoldot::trie::proof_decode::Config { proof: i.data },
                    )
                    .unwrap()
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("get-storage-value", proof.data.len()),
            &smoldot::trie::proof_decode::decode_and_verify_proof(
                smoldot::trie::proof_decode::Config { proof: proof.data },
            )
            .unwrap(),
            |b, i| {
                b.iter_batched(
                    || {
                        (0..rand::thread_rng().gen_range(12..48))
                            .map(|_| rand::random())
                            .collect::<Vec<_>>()
                    },
                    |key| i.storage_value(&proof.trie_root, &key),
                    BatchSize::SmallInput,
                )
            },
        );

        group.bench_with_input(
            BenchmarkId::new("next-key", proof.data.len()),
            &smoldot::trie::proof_decode::decode_and_verify_proof(
                smoldot::trie::proof_decode::Config { proof: proof.data },
            )
            .unwrap(),
            |b, i| {
                b.iter_batched(
                    || {
                        (0..rand::thread_rng().gen_range(12..48))
                            .map(|_| rand::thread_rng().gen_range(0..16).try_into().unwrap())
                            .collect::<Vec<_>>()
                    },
                    |key| i.next_key(&proof.trie_root, &key, false, &[], true),
                    BatchSize::SmallInput,
                )
            },
        );

        group.bench_with_input(
            BenchmarkId::new("closest-descendant-merkle-value", proof.data.len()),
            &smoldot::trie::proof_decode::decode_and_verify_proof(
                smoldot::trie::proof_decode::Config { proof: proof.data },
            )
            .unwrap(),
            |b, i| {
                b.iter_batched(
                    || {
                        (0..rand::thread_rng().gen_range(12..48))
                            .map(|_| rand::thread_rng().gen_range(0..16).try_into().unwrap())
                            .collect::<Vec<_>>()
                    },
                    |key| i.closest_descendant_merkle_value(&proof.trie_root, &key),
                    BatchSize::SmallInput,
                )
            },
        );

        group.bench_with_input(
            BenchmarkId::new("closest-ancestor", proof.data.len()),
            &smoldot::trie::proof_decode::decode_and_verify_proof(
                smoldot::trie::proof_decode::Config { proof: proof.data },
            )
            .unwrap(),
            |b, i| {
                b.iter_batched(
                    || {
                        (0..rand::thread_rng().gen_range(12..48))
                            .map(|_| rand::thread_rng().gen_range(0..16).try_into().unwrap())
                            .collect::<Vec<_>>()
                    },
                    |key| i.closest_ancestor_in_proof(&proof.trie_root, &key),
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish()
}

criterion_group!(benches, benchmark_proof_decode);
criterion_main!(benches);
