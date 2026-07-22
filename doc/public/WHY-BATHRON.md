# Why BATHRON

> The product hypothesis is conditional settlement. The chain, M0, M1 and the burn are the
> machinery behind it—not assets offered to the public.

## 1. The unmet need

Simple Bitcoin payments already have strong solutions. BATHRON starts where a payment must be
coordinated with another leg or condition: delivery-versus-payment, escrow, an OTC exchange or a
Bitcoin event that must be verified before funds move.

Today that coordination commonly relies on a custodian, federation, oracle or arbitrator.
BATHRON tests another design: represent the conditional leg as a covenant and let every node
verify the relevant Bitcoin fact against a header chain carried in consensus.

## 2. The service being tested

A **Clearing Provider (CP)** presents a quote in the assets familiar to the client. It orchestrates
the commitments, execution paths and timeouts. One or more **Liquidity Providers (LPs)** provide
inventory and pair-specific prices. **Settlement Operators** provide consensus and finality but
do not control quotes or select providers for users.

The CP is paid through explicit fees and spreads. Those revenues must cover liquidity, inventory,
capital and operating risk. Whether that equation works is unproven and is the central commercial
test—not an assumption hidden behind token appreciation.

The intended client flow is:

1. receive a quote specifying amount, deadline, fees and refund path;
2. commit BTC to the quoted execution or timeout conditions;
3. let the CP and LPs use BATHRON's internal state to coordinate the settlement;
4. receive BTC or the other quoted external asset, or recover the committed principal after the
   applicable timeout.

The final protection in step 4 remains a **design target**. The complete cross-chain state
machine, reorganisation rules and timelock ordering are not yet formally specified or externally
reviewed, so BATHRON does not currently claim a general atomic-settlement guarantee.

## 3. Why the chain needs internal state

BATHRON can verify Bitcoin facts but cannot spend native BTC. Programmable conditions therefore
need an internal asset that the BATHRON consensus can lock and release.

- M0 can arise only from an irreversible, SPV-verified destruction of BTC.
- Locking M0 creates M1 at a protocol accounting ratio of 1:1.
- M1 carries the programmable settlement state used by CPs and LPs.

Destroyed BTC is not held for redemption. M0 and M1 are neither claims on a reserve nor assets
whose external value BATHRON guarantees. Their realizable value depends on professional demand
and available liquidity and can fall to zero. In the target service, that inventory risk belongs
to CPs and LPs, not to retail clients.

This explains the order of the design: the settlement problem requires programmable internal
state; M1 provides that state; M0 accounts for its origin; verified BTC destruction is the
one-way acquisition mechanism. The burn is a consequence of the architecture, not its product.

## 4. Evidence available today

The live testnet has demonstrated the components separately and in scripted flows:

- `TX_CONFIRMED` verification of a Bitcoin payment against headers in consensus;
- CTV-enforced covenant payouts;
- Sapling transfers for confidential internal state;
- paired BATHRON/Bitcoin-signet HTLCs sharing a preimage;
- M0 and M1 conservation invariants enforced during block validation.

Still missing are a productised two-party workflow, formal end-to-end safety specification,
external review, sustained multi-provider liquidity and evidence of paying demand.

## 5. Where the approach may be useful

The strongest candidate is a BTC transaction whose release depends on a verifiable condition and
where neither party wants a custodian to hold and adjudicate the funds. Delivery-versus-payment,
escrow and certain OTC workflows fit that description.

BATHRON is a poor fit for:

- ordinary instant payments, where Lightning is simpler;
- stable unit-of-account needs, where stablecoins already serve the market;
- users seeking a liquid or appreciating network asset;
- transactions where a trusted provider is acceptable and operational simplicity dominates.

## 6. Falsifiable next milestone

The next milestone is not “more burns.” It is one independent CP candidate willing to examine a
real conditional-settlement flow and provide its own numbers for expected volume, fees, spread,
inventory, liquidity and operational costs.

If no such operator sees an economic advantage after reviewing the complete risk model, the
commercial thesis fails even if the protocol continues to work technically.

*BATHRON is an experiment in conditional settlement, not a promise that an internal asset will
acquire value.*
