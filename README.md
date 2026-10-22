# ParametricClaim — Escrowed Contingent Claim with Consensus Measurement

> **A premium is escrowed against a measurable parameter.** Validators independently fetch the canonical source for that parameter and the LLM extracts the *measured value*; when the measurement crosses the policy threshold, a deterministic parametric formula pays out automatically. If the trigger does not fire, the premium is returned when the policy expires.

[![GenLayer](https://img.shields.io/badge/Built%20on-GenLayer-6366f1?style=for-the-badge&logo=genlayer)](https://genlayer.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-31%20passed-16a34a?style=for-the-badge)](https://github.com/)

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

- **Leader**: fetches the instrument source through the trusted fetch path, then asks the LLM for the single named field in integer milli-units.
- **Validator**: independently fetches and extracts, then compares: the two measurements must be equal, or within ±5 % (basis points, with a floor of one milli-unit) — independent extractions of the same number differ slightly, and exact equality would produce constant `MAJORITY_DISAGREE`.
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

31 GenVM direct-mode tests pass. Lint passes. E2E passes on studionet (see below). Deployed to studionet.

---

## Deployed contract (proof on explorer)

[![Explore](https://img.shields.io/badge/Explore-Studionet-6366f1?style=for-the-badge)](https://genlayer-explorer.vercel.app)

**Address:** `0xdBD8DcED1b3e94011abcE7B10dcA4c1eC349FEe9`
**Chain:** Studionet (Genlayer Studio Network)
**Deployer:** `0x689759bb926E032EAfb1eE986eD7A98C1496ec1c`
**Tx:** `0x67c3b000eb411d0bbe376204d136899f632308b7b47f3ed933426f62e6f3036b`
**Status:** Deployed and tested on studionet.

Live E2E (script `scripts/e2e-test.cjs`):
- **open_policy** — 0.02 GEN premium escrowed → MAJORITY_AGREE.
- **evaluate_policy** — validators fetched the live `api.open-meteo.com` source and the LLM extracted the measurement: **4.300 mm** in the first run, **2.300 mm** in the second (genuinely live data) → MAJORITY_AGREE → status `paid`, payout `700000000000` / `2700000000000` wei computed on-chain from the measurement and paid to the policy holder.
- **cancel_policy** — inside the cooling-off window → MAJORITY_AGREE → status `cancelled`, premium returned to the payer (balance back to its pre-open value).
- Final `pool_totals`: `total_premiums 8e16`, `total_payouts 3.4e12`, `total_refunds 4e16`, `available 3.99966e16` — every premium accounted for, nothing stranded.

---

## Extension ideas

- Per-policy source override with a curated second-tier catalogue
- Multi-instrument triggers ("wind above X **and** rainfall below Y")
- Basis-point premiums with partial refunds of unused coverage
- Reinsurance: a policy whose payout is covered by a pool of other policies
- Reporting views: realised vs. theoretical payout per instrument over time
