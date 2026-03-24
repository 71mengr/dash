# KAWHeavy: A Hybrid Dash Proof-of-Work Proposal

## Status

- **Type:** Concept proposal (not active on mainnet)
- **Target:** Potential replacement for Dash PoW (X11)
- **Objective:** Combine memory-hard graphics workloads with efficient hash finalization to keep mining GPU-friendly and harder to centralize.

## Motivation

Dash currently uses X11, which was originally designed to discourage specialized mining hardware. Over time, ASICs were developed for X11, increasing mining centralization pressure.

KAWHeavy combines two ideas:

1. **KawPow lineage** (ProgPoW family): dynamic, DAG-backed workloads that better map to commodity GPUs.
2. **KHeavyHash-style finalization:** high-throughput, straightforward hash mixing stage that is efficient on GPUs and CPUs while increasing implementation complexity for fixed-function ASICs.

The intended result is a balanced algorithm with:

- Strong memory-hard pressure (bandwidth + random memory access).
- Frequent GPU ALU and register usage changes.
- A compact and verifiable final hash stage.

## Design Goals

1. **ASIC resistance by cost asymmetry**
   - Avoid fixed pipelines by introducing epoch-dependent program generation.
   - Force high memory bandwidth and random reads from a DAG/cache.
2. **GPU optimization without vendor lock-in**
   - Keep core operations expressible across CUDA, ROCm, OpenCL/Vulkan compute.
3. **Verification efficiency for full nodes**
   - Miners perform expensive dataset generation and random accesses.
   - Validators should verify a block header quickly using lightweight cache + deterministic replay.
4. **Predictable network transitions**
   - Activation via version bits + mandatory fallback period and testnet bake-in.

## High-Level Algorithm

For each candidate block header:

1. Build seed from header fields + nonce.
2. Derive `epoch` from block height.
3. Use `epoch` to select/generate DAG and random math program.
4. Run KawPow-like loop over random DAG accesses and mixed integer ops.
5. Feed loop output into KHeavyHash-inspired finalization rounds.
6. Compare resulting 256-bit digest against target.

### Pseudocode (informative)

```text
input: block_header_without_nonce, nonce, height
seed      = H(header || nonce)
epoch     = floor(height / EPOCH_LENGTH)
cache     = build_light_cache(epoch)
dag_item  = random_walk(seed, cache, ACCESSES)
state     = progpow_mix(seed, dag_item, PROGRAM_ID(epoch, nonce))
final     = kheavy_finalize(state, ROUNDS)
result    = H(final)
valid if result <= target
```

## Proposed Parameters (initial draft)

- `EPOCH_LENGTH`: 7,500 blocks (~10.4 days at 2.0 min block target)
- `DAG_INIT_SIZE`: 3.0 GiB
- `DAG_GROWTH_PER_EPOCH`: 48 MiB
- `LIGHT_CACHE_SIZE`: 32 MiB
- `PROGPOW_ROUNDS`: 64
- `RANDOM_ACCESSES`: 128
- `KHEAVY_ROUNDS`: 16
- `HASH_OUTPUT`: 256 bits

> These values are placeholders for benchmarking and should be finalized only after multi-vendor miner profiling and node validation benchmarking.

## Consensus Integration Plan

### 1) New PoW Versioning

Add a `pow_algo` indicator in block version interpretation (or infer from activation height). During transition windows, nodes must evaluate only the active algorithm at a given height.

### 2) Difficulty Retarget Continuity

- Preserve Dash's existing retarget cadence and damping behavior.
- Do **not** reset cumulative chainwork semantics.
- Introduce a one-time calibration factor at activation height to avoid abrupt hashrate shock.

### 3) Coinbase and Masternode Logic

- No reward split changes are required by the PoW swap itself.
- Existing subsidy and masternode payment logic can remain untouched.

### 4) Header/Stratum Compatibility

- Keep block header structure stable if possible.
- Mining software obtains epoch, cache seed, and program ID deterministically from header/height.

## Security Considerations

1. **ASIC eventuality is inevitable**
   - Goal is delaying and reducing centralization edge, not permanent ASIC prevention.
2. **Memory-hardness tuning risk**
   - Too large DAG can exclude consumer GPUs.
   - Too small DAG can make specialized memory controllers economical.
3. **Implementation diversity risk**
   - Require consensus test vectors and cross-client fuzzing to prevent divergent interpretations.
4. **DoS surface during validation**
   - Validation path must cap per-header compute and cache rebuild frequency.

## Benchmark & Validation Checklist

Before testnet activation:

- Implement reference miner + verifier with deterministic test vectors.
- Benchmark on NVIDIA, AMD, and Intel GPU stacks.
- Benchmark full-node validation throughput (headers/sec).
- Run long-range reorg simulations with mixed old/new software.
- Execute adversarial tests (invalid DAG indices, malformed seeds, overflow behavior).

## Rollout Strategy

1. **Devnet phase**: tune parameters and gather hardware telemetry.
2. **Testnet signaling**: activate via version bits with clear median-time-past windows.
3. **Mainnet lock-in**: require supermajority signaling and long lead time for exchanges/pools.
4. **Post-activation observation**: monitor hashrate distribution, orphan rate, and miner diversity.

## Open Questions

- Should `EPOCH_LENGTH` track fixed block count or wall-clock windows?
- How aggressively should DAG growth target 6–8 GiB GPUs over time?
- Is a periodic program schedule preferable to per-block randomized program IDs?
- Should we include a lightweight anti-optimization tweak every N epochs?

## Next Engineering Steps

1. Add `pow_kawheavy.{h,cpp}` with deterministic primitives and test vectors.
2. Wire `GetHash()`/`CheckProofOfWork()` selection by height.
3. Add functional tests for pre/post-fork validity boundaries.
4. Publish miner specification and stratum update notes.
5. Run public testnet with at least two independent miner implementations.

