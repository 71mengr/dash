# KAWHeavy external backend strategy (KawPow + KHeavyHash)

This repository currently ships an in-tree deterministic KAWHeavy implementation in `src/pow_kawheavy.cpp`.

## Should we use git submodules for KawPow/KHeavyHash?

Short answer: **yes, with strict consensus controls**.

Using upstream implementations can reduce maintenance burden and align behavior with audited code, but PoW is consensus-critical, so integration must be pinned and deterministic.

## Recommended approach

1. Add upstream repositories as pinned submodules:
   - `https://github.com/DNS/kawpow`
   - `https://github.com/bcutil/kheavyhash`
2. Build small adapter wrappers in-tree (`src/pow_kawpow_adapter.*`, `src/pow_kheavy_adapter.*`).
3. Keep a deterministic fallback implementation in-tree for portability and staged rollouts.
4. Gate external backend activation behind compile-time flags and runtime self-tests.
5. Add fixed consensus vectors that must pass before node startup.

## Consensus safety requirements

- Pin submodule commits (never floating branches).
- Include adapters only through stable C ABI/C++ wrappers.
- Normalize endianness and serialization at wrapper boundaries.
- Add per-network test vectors (mainnet/testnet/regtest).
- Disable external backend automatically if self-tests fail.

## Current status

The PoW pipeline now exposes a dedicated integration point (`TryExternalHybridHash`) that can be wired to submodule-based adapters later without changing the public KAWHeavy API.
