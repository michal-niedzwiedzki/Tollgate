# PRD - Tollgate

**Spend control and provable receipts for agent API payments, on x402.**

Read alongside architecture-v2.md.

---

## 1. One-liner

An x402-compatible API gateway that gives agent payments what the protocol leaves out: hard spend
caps, sub-agent budget delegation, and signed receipts an agent can prove to whoever funded it.

The payment rail is x402. Tollgate is the control plane on top of it.

## 2. Problem

API access assumes a human is behind the account. Sign up, get a key, attach a card, receive an
invoice. Every step needs a legal person with a bank account.

x402 solved the payment half of this in 2026. An agent can now pay per request in USDC without a
signup. What it did not solve is the control half:

- Nothing stops a runaway loop. x402 settles what it is told to settle. A buggy agent burns the
  wallet and you find out from the block explorer.
- A parent agent cannot hand a sub-agent a scoped budget. It either shares its key, which is the
  shared-master-key problem again with worse blast radius, or it funds a separate wallet per
  sub-agent and manages a wallet fleet by hand.
- There is no artifact proving what an agent spent and on what. The chain shows transfers. It does
  not show which endpoint, which task, which sub-agent, or whether the upstream even returned 200.

Those three gaps are the product.

## 3. Why this is a crypto problem, not a Stripe problem

Card rails have a floor. Interchange and fixed fees make a $0.0004 charge impossible, so providers
batch into subscriptions, which reintroduces the account. Cards also need a merchant of record and a
chargeback window, and an ephemeral agent supplies neither.

Stablecoin transfers on an L2 have near-zero marginal cost. That is the only reason per-request
pricing works at all. Nothing in this PRD needs a chain except settlement.

## 4. Target users

**Primary: API provider.** A small team with an endpoint worth money (a scraper, a specialised
model, a data feed, a geocoder) who wants agent traffic without building billing. Cloudflare and AWS
both ship x402 at the edge now, but they serve their own large customers. The self-hosted small
provider is underserved.

**Secondary: agent developer.** Someone running a LangGraph or custom loop who needs a supervisor to
hand workers scoped budgets and get an expense report back.

**Not a user.** Enterprise procurement. Anyone who wants a monthly invoice. Consumers. Anyone who
needs fiat.

## 5. Non-goals

- Fiat on-ramp or off-ramp
- Key custody as a service. The agent brings its own signer
- A marketplace or discovery directory of paid APIs
- Subscription or committed-spend pricing tiers
- KYC of any kind
- Mainnet with real money
- A new payment protocol. If a behaviour exists in x402, use x402's version of it

## 6. Core user stories

### Provider

1. I wrap my existing endpoint and set a price per request, and agents can pay me in under three
   minutes, with no billing code on my side.
2. I see a live log of paid requests with payer address, endpoint, upstream status, and settlement
   transaction hash.
3. I charge a fixed price per call, or a maximum with the actual amount settled after execution,
   so a variable-cost endpoint is priceable.
4. My earnings land in my own wallet. Tollgate never holds them.

### Agent developer

5. I fund an agent once, set a total cap and a per-request cap, and a runaway loop cannot exceed
   them.
6. My supervisor agent hands each worker a scoped budget with its own cap, expiry, and endpoint
   allowlist, signed once, with no server round-trip per worker.
7. My agent calls a paid endpoint, gets a 402 with machine-readable payment requirements, signs,
   retries, and gets the data in the same round trip.
8. At the end of a run I get a signed expense report: what each agent and sub-agent spent, on which
   endpoint, with the transaction hash for every settled charge.

### Anyone trying it out

9. I watch a supervisor hand three workers different budgets, watch one worker hit its cap and stop
   while the others keep going, and verify every payment on a block explorer.

## 7. Functional requirements

### P0, the core path

| ID | Requirement |
|----|-------------|
| F1 | Gateway returns a spec-compliant x402 402 response with payment requirements. Any existing x402 client can pay it |
| F2 | Gateway accepts an x402 payment header, verifies the EIP-3009 payload with `alloy`, and proxies to the upstream |
| F3 | Per-request cap, total cap, and endpoint allowlist enforced atomically before the upstream call |
| F4 | Sub-agent budget delegation: an EIP-712 capability chain, attenuation-only, verified at the gateway with no round-trip to the parent |
| F5 | Batched settlement worker, one chain, settling off the request path |
| F6 | Signed spend receipt per charge, and a per-run expense report endpoint |
| F7 | Provider registration: upstream URL, price, receiving address. SSRF-safe |
| F8 | Dashboard: provider view, agent view with the delegation tree, public settled-charge feed |
| F9 | Python client library handling 402, sign, retry, plus a `delegate()` call |

### P1, natural next iteration

| ID | Requirement |
|----|-------------|
| F10 | `upto` scheme: authorise a maximum, settle the actual amount after execution |
| F11 | Payment channel mode (x402 `batch-settlement`) for session-scoped prepaid budgets |
| F12 | Refund path: upstream 5xx or timeout is never settled |
| F13 | Time-window budgets on top of total caps |
| F14 | `tollgate wrap ./openapi.yaml --price 0.001` CLI |

### P2, worth noting, do not build

| ID | Requirement |
|----|-------------|
| F15 | Second chain |
| F16 | MCP server wrapper so a paid tool call pays for itself |
| F17 | Provider SLA with automatic refunds on violation |
| F18 | Streaming settlement for long-running responses |
| F19 | Dispute window and arbitration |

F12 (refunds) and F10 (`upto`) are correct behaviours but not P0: the core flow works without them and
neither is the most memorable part of what it does.

## 8. Success metrics

Numbers worth tracking and showing live, on a panel, as evidence the design holds up.

| Metric | Target |
|--------|--------|
| Added gateway latency, p50 | Under 15 ms, excluding upstream |
| Added gateway latency, p99 | Under 50 ms, excluding upstream |
| End-to-end p50 including upstream | Under 150 ms |
| Settlement cost per request after batching | Under $0.001, verified with `forge` gas snapshots, not estimated |
| Requests handled live | 100+ in under 60 seconds |
| Delegation depth demonstrated | 2 levels, 3 workers |
| Provider integration measured live | Under 3 minutes from zero |

Most of the end-to-end budget is the upstream network hop, which the caller was paying anyway.
Separate your added latency from the upstream's and show both live. Anyone reading the numbers will
conflate them if you do not.

## 9. What using it looks like

The core flow, end to end:

1. Supervisor agent gets a task needing three workers. It signs three delegations with different
   caps and allowlists. One signature each, no server call.
2. Workers run. They hit paid endpoints, get 402, pay, get data. Public feed scrolls.
3. Worker 2 hits its cap mid-task and stops. Workers 1 and 3 keep going. This is the moment.
4. Block explorer: settlement transaction appears, one transaction covering all of it.
5. Expense report: signed, per-worker, per-endpoint, with transaction hashes.
6. Wrap a brand-new public endpoint live and have a worker pay it.

Step 3 is the part worth showing off. Everyone worries about autonomous agents with money. Showing
scoped budgets hold under load answers it physically.

## 10. Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Someone asks why this is not just x402 | High | Answer directly: it is x402, plus the three things x402 does not do. Say it up front, not as an afterthought |
| Delegation is the headline feature and it slips | High | Ship receipts alone if it does. Lower risk, still differentiating. Decide early, don't let it drag |
| Someone finds an SSRF live | High | Resolve once, validate the IP, pin the connection. Deny-by-default egress. Test with a rebinding payload before relying on it |
| Free-shopping bug: response released before the authorisation is replay-checked | High | Never proxy before the atomic Redis claim succeeds. This class of bug is documented in production x402 facilitators |
| Latency claim does not hold | Medium | Instrument per stage from the start, not as an afterthought. If the proxy hop is the problem, return a pass-through token instead |
| Contract bug drains testnet funds during testing | Medium | Channel mode is P1 specifically so the only contract you must ship is none. Direct-pull uses Circle's USDC contract, which you did not write |
| Reads as invisible infrastructure | Medium | The delegation tree view and the expense report are the visible product. Build them, do not treat them as optional |
| Settler EOA throughput ceiling | Low at this scale | One in-flight transaction per chain covers 100 requests in 60 seconds comfortably. State the ceiling out loud rather than hiding it |

## 11. How this makes money

Include this honestly in any write-up. A fake hockey-stick projection is easy to see through, and the
real numbers are checkable.

**The market today is small.** The whole x402 rail moved roughly $24M in the 30 days to mid-July
2026, across about 75 million transactions, ~94,000 buyers, ~22,000 sellers, average payment near 32
cents. That is roughly a $290M annualised run-rate for the entire rail. An independent scan of one
facilitator found only about 5% of settled volume came from wallets that returned and paid again, so
a large share is one-shot or test traffic.

**Therefore a take rate cannot fund this yet.** 30bps on the entire rail is about $870k a year. 1%
is about $2.9M. A realistic single-digit-percent slice of that funds nobody. Pure facilitation is
already priced near zero: Coinbase's CDP facilitator charges $0.001 per settlement after 1,000 free
per month, and several competitors charge nothing.

**The models that could work, in order of realism:**

| Model | Comparable | Notes |
|-------|-----------|-------|
| Open core: free self-hosted gateway, paid cloud | OpenRouter (~5% take, ~$50M annualised by March 2026), Kong (from $25/mo) | The only model that fits the non-goals and lets adoption compound before monetisation. Recommended |
| SaaS for the control plane | Kong, Tyk | Sell the policy engine, dashboard, and managed settlers. Not the settlement |
| Take rate on settled volume | Nevermined charges 1% | 30bps to 1% is the plausible band. Stay under Nevermined |
| Gas abstraction margin | n/a | Real but tiny. Hundredths of a cent per request |
| Marketplace take | RapidAPI takes 25% plus processing | Requires being a marketplace, which is an explicit non-goal |
| Float or yield on held funds | n/a | Do not. It is the biggest regulatory trap, conflicts with non-custodial positioning, and is a rounding error at this volume |

**Unit economics.** Settlement gas on Base for a batch is on the order of a few cents, so per-request
cost stays well under $0.001 across a full batch. To cover one engineer at roughly $25k fully loaded
purely on take rate, you need about $8M of annual settled volume at 30bps, or $2.5M at 1%. Nobody is
close.

**Sell to providers, not agent platforms.** Providers have the pain and adopt gateways. Agent
platforms will standardise on x402 clients and will not pay you.

**Regulatory shape, which is why direct-pull is the default.** Holding customer funds in escrow and
deciding who gets paid is the pattern that triggers money-transmitter obligations. Direct-pull, where
funds move by the user's own signature and you never hold them, keeps the non-custodial argument
strong. In India specifically, stablecoins are Virtual Digital Assets: 30% flat tax under 115BBH, 1%
TDS under 194S, and since 2023 entities that exchange, transfer, or safekeep VDAs are PMLA reporting
entities that must register with FIU-IND. If Tollgate ever custodies real funds for Indian users, it
is in that perimeter. Testnet-only for now, but the architecture should not box you in later.
None of this is legal advice.

## 12. Naming

"Tollgate" is the working name. Meter.io (token MTRG) is a live EVM L1 in the same broad category
since 2020, and Payline is an existing payments company, so both are ruled out. Before writing code,
check npm, PyPI, crates.io, and domain availability for Tollgate, and confirm there is no existing
crypto or toll-adjacent project using it.

## 13. Decisions locked before starting

| # | Decision | Chosen |
|---|----------|--------|
| 1 | Own protocol or x402 | x402-compatible. Speak the 402 payment-requirements schema, accept x402 payment headers |
| 2 | Escrow or direct-pull | Direct-pull via EIP-3009 as the default. Channel mode only for delegated and session spend, and only as P1 |
| 3 | Chain and token | Native USDC on Base Sepolia (84532). Not bridged USDC.e anywhere |
| 4 | Headline feature | Sub-agent budget delegation |
| 5 | Own contract or none | None on the critical path. Circle's USDC contract does the verification |

## 14. Still open, resolve early

- Does any external integration require a specific chain? If it forces a chain without EIP-3009
  native USDC, fall back to channel mode and budget the extra time.
- `transferWithAuthorization` or `receiveWithAuthorization`? The latter checks the caller is the
  payee and closes a known front-running path. Confirm what the x402 SDK you interoperate with
  expects before you pick.
- Read the x402 `batch-settlement` SDK contract interface before designing anything channel-shaped.
  Borrow the cumulative-voucher semantics rather than inventing your own.
- Delegation and direct-pull have a real tension: the sub-agent signs, but the parent holds the
  funds. See architecture.md section 5. Decide which of the two resolutions you are building.
