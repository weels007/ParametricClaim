# ParametricClaim — Escrowed Contingent Claim with Consensus Measurement

> **A premium is escrowed against a measurable parameter.** Validators independently fetch the canonical source for that parameter and the LLM extracts the *measured value*; when the measurement crosses the policy threshold, a deterministic parametric formula pays out automatically. If the trigger does not fire, the premium is returned when the policy expires.

[![GenLayer](https://img.shields.io/badge/Built%20on-GenLayer-6366f1?style=for-the-badge&logo=genlayer)](https://genlayer.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-32%20passed-16a34a?style=for-the-badge)](https://github.com/)

---

## Table of Contents

- [How it works](#how-it-works)
- [Why this design](#why-this-design)
- [Consensus design](#consensus-design)
- [Reusable patterns](#reusable-patterns)
- [Security & audit](#security--audit)
- [Local lint & test](#local-lint--test)
- [Deployed contract (proof on explorer)](#deployed-contract-proof-on-explorer)
- [Extension ideas](#extension-ideas)

---

## How it works

1. **Open a policy** — `open_policy(instrument, threshold, slope, ttl)` with the premium attached (payable). The instrument comes from a catalogue compiled into the contract (daily rainfall, daily max temperature, daily max wind), each with a canonical source URL and a field path.
2. **Measure** — anyone calls `evaluate_policy(policy_id)`. Validators fetch the instrument's source and the LLM extracts the measured value; the consensus compares the independently extracted numbers.
3. **Settle** — if the measurement is on the trigger side of the threshold, the payout is computed on-chain by a pure formula and paid to the policy holder. Otherwise the policy is marked `no_trigger` and the premium stays escrowed until it is returned at expiry.
4. **Premium always comes back** — cooling-off cancellation (`cancel_policy`, first hour), expiry (`expire_policy`, at the deadline) or a payout. There is no path that leaves a premium locked.

```
open_policy (premium escrowed)
      │
      ├── cancel_policy (cooling-off)  ──► premium back
      │
      ├── evaluate_policy
      │        ├── trigger fired  ────────► payout (deterministic formula) → policy holder
      │        └── no trigger     ────────► premium stays escrowed → expire_policy → premium back
      │
      └── expire_policy (after deadline) ─► premium back
```

---

## Why this design

This contract is deliberately built to answer the questions that are usually asked about AI-driven money:

- **The LLM extracts, it never decides.** It answers exactly one narrow question — "what number does this source report for this field?" — and returns it as an integer in thousandths (the calldata layer cannot encode floats). Every wei that moves is computed on-chain from that number.
- **The source cannot be chosen by the payer.** The instrument catalogue is fixed in the contract code: each instrument names one canonical URL owned by a third party. A payer cannot point the contract at a page they control, so the measured value cannot be gamed by picking a favourable endpoint.
- **The payout formula has no discretionary component.** `payout = excess × slope / 1e6` — a pure function of (measurement, threshold, slope). Leader and validators can verify the same arithmetic, so a disagreement means the *measurement* differs, not the maths.
- **No stranded funds.** The premium is escrowed and is always returned — by payout, by cooling-off cancellation, or at expiry. A dead data source records a failure reason instead of reverting, and the premium is still refundable.
- **Deterministic money, non-deterministic world.** The parts that touch the outside world (fetch, extraction) are consensus-checked; the parts that touch money are pure arithmetic.

---

## Consensus design

`evaluate_policy` uses `run_nondet_unsafe` with the Equivalence Principle:

- **Canonical value**: the leader's extracted measurement is snapped to a fixed **0.1-unit grid** (`grid = MEASURE_SCALE // 10` = 100 milli-units) before consensus, cancelling the ±50-milli-unit noise of independent LLM extractions while still binding one exact value.
- **Validator**: independently fetches and extracts, canonicalizes its own measurement identically, and accepts **iff the two measurements produce the identical on-chain payout** (`_compute_payout(mine, …) == _compute_payout(leader, …)`). Because the payout is a pure, monotone function of the measurement, equal payouts imply the same trigger outcome *and* the same payout amount — no tolerance band can ever straddle two different settlement results. There is no ±% path in the code at all.
- **Error classification**: `[EXPECTED]` (deterministic) and `[EXTERNAL]` (source unreachable/4xx/blocked) must match exactly; `[TRANSIENT]` (5xx/network) agrees if both fail; `[LLM]` always disagrees, forcing rotation.
- **Permanent vs transient**: a permanent source failure is *recorded* on the policy (`failure_reason`) and the evaluation stays retryable later; a transient failure reverts and changes nothing.

---

## Reusable patterns

- **Measurement extraction**: `exec_prompt(response_format="json")` returning integer milli-units, with a whole-unit fallback — designed around the fact that the calldata layer cannot encode floats.
- **Instrument catalogue**: a compile-time map of `name → {url, field, unit, direction}`, so the trusted source is a property of the product, not of the user.
- **Escrow with a guaranteed refund**: premium escrowed on open; refundable by cancellation, expiry, or payout; a permanent data failure is recorded instead of reverting so the escrow can still be recovered.
- **Deterministic parametric payout** with an explicit cap at the escrowed pool (`available = premiums - payouts - refunds`), so the contract can never overpay.
- **Trusted fetch path**: submitter-independent domain allowlist, DoH resolution of every hop before the request, post-fetch re-resolution requiring an unchanged and still-public address set (IP pinning is impossible on-chain — the validator rejects IP literals with `TLD_FORBIDDEN`, measured on studionet).
- **Address coercion** for client-supplied addresses, and `EthSend` payouts (`on="finalized"`).

---

## Security & audit

- **Premium custody**: the premium is held in the contract and tracked in `total_premiums`; payouts and refunds are tracked separately, so `available` is always `premiums - payouts - refunds` and can never go negative.
- **Payout cap**: the computed payout is clamped to `available`, so even a pathological slope cannot drain funds that belong to other policies.
- **Expiry and cancellation**: a premium is returned on cancellation inside the cooling-off window (payer only) and at expiry (anyone, after the deadline) — a policy can be settled exactly once.
- **No unreachable state**: `evaluate_policy` on an expired policy is refused, and expiry refunds the premium of both unevaluated and no-trigger policies.
- **Source integrity**: only catalogue URLs are ever fetched; they are on an allowlist of domains whose DNS the payer cannot control; every hop is resolved over DNS-over-HTTPS and rejected if any address is private/loopback/link-local/reserved/CGNAT, and re-resolved after the fetch.
- **Input validation**: instrument must exist in the catalogue, threshold and slope positive, TTL within 300 s–365 d, premium positive, description lengths bounded.
- **Extraction sanity**: negative, non-numeric, missing or non-integer measurements are rejected as `[LLM]` errors — they never settle a policy with a wrong number.

---

## Local lint & test

```bash
# Run tests
pytest tests/ -v

# Run linter
genvm-lint check contracts/parametric_claim.py
```

32 GenVM direct-mode tests pass. Lint passes. E2E passes on studionet (see below). Deployed to studionet.

---

## Deployed contract (proof on explorer)

[![Explore](https://img.shields.io/badge/Explore-Studionet-6366f1?style=for-the-badge)](https://genlayer-explorer.vercel.app)

**Address:** `0x88617DD8e766Db7622AB211267E313dB6A30670D`
**Chain:** Studionet (Genlayer Studio Network)
**Deployer:** `0x689759bb926E032EAfb1eE986eD7A98C1496ec1c`
**Tx:** `0x75f172dadf37012f16af79e9f477329afeff19c37dc766572114aa1053972fcd`
**Source SHA-256:** `9F712DC5606525C6C845AB51C99FBD9562E5016B8D96259DE227BDBF0F78BC0E`
**Status:** Deployed and tested on studionet.

Live E2E (script `scripts/e2e-test.cjs`):
- **open_policy** — 0.02 GEN premium escrowed → MAJORITY_AGREE.
- **evaluate_policy** — validators fetched the live `api.open-meteo.com` source; canonical 0.1-unit-grid consensus reached **on attempt 1** with measurement **0 mm** (rain genuinely 0 that day) → status `paid`, deterministic payout `5000000000000` wei computed on-chain from the measurement and paid to the policy holder.
- **cancel_policy** — second policy cancelled inside the cooling-off window → status `cancelled`, premium returned to the payer (balance back to its pre-open value).
- Final `pool_totals`: `total_premiums 4e16`, `total_payouts 5e12`, `total_refunds 2e16`, `available 1.9995e16` — `available = premiums − payouts − refunds` exactly; every premium accounted for, nothing stranded.

---

## Extension ideas

- Per-policy source override with a curated second-tier catalogue
- Multi-instrument triggers ("wind above X **and** rainfall below Y")
- Basis-point premiums with partial refunds of unused coverage
- Reinsurance: a policy whose payout is covered by a pool of other policies
- Reporting views: realised vs. theoretical payout per instrument over time
