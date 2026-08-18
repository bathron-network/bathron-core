# BATHRON P&A swap frontend

> **Status: experimental prototype — not currently deployed.** This demonstrator was built for
> the previous public testnet, whose Bitcoin leg used **Bitcoin signet**. The current measurement
> network reads **Bitcoin testnet4**; the BTC leg of this prototype has not been migrated. It is
> kept as a reference implementation of the quote / HTLC-orchestration split described in the
> canonical documentation, not as a supported product. What the network can and cannot do today:
> <https://bathron.org/docs/consensus/status-and-claims.html>. How markets and providers fit
> together: <https://bathron.org/docs/markets/how-a-market-appears.html> ·
> <https://bathron.org/docs/markets/roles.html>.

Web frontend for the P&A swap flow on the BATHRON testnet
(`:3002`): quote aggregation across LPs and swap progress tracking.

Maintained as a **demonstrator**: it exercises the settlement primitives end to
end. It is not a supported product.
