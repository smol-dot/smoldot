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

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn benchmark_proof_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof-decode");

    let proofs: &[&[u8]] = &[
        &include_bytes!("./proof-decode-small")[..],
        &include_bytes!("./proof-decode-large")[..],
    ];

    for proof in proofs {
        group.throughput(Throughput::Bytes(proof.len() as u64));
        group.bench_with_input(BenchmarkId::new("decode", proof.len()), proof, |b, i| {
            b.iter(|| {
                smoldot::trie::proof_decode::decode_and_verify_proof(
                    smoldot::trie::proof_decode::Config { proof: i },
                )
                .unwrap()
            })
        });
    }

    group.finish()
}

criterion_group!(benches, benchmark_proof_decode);
criterion_main!(benches);
