# BATHRON LP dashboard + swap SDK

> **Historical DMM testnet documentation.** Network status: <https://bathron.org/docs/status.html>.

> **Status: experimental prototype — not currently deployed.** This demonstrator was built for
> the previous public testnet, whose Bitcoin leg used **Bitcoin signet**. The former DMM
> measurement network read **Bitcoin testnet4**; the BTC leg of this prototype was not migrated. It is
> kept as a historical reference implementation of the quote / HTLC-orchestration split,
> not as a supported product. Network status:
> <https://bathron.org/docs/status.html>. How markets and providers fit
> together: <https://bathron.org/docs/between-providers.html> ·
> <https://bathron.org/docs/roles.html>.

Liquidity-Provider dashboard and Python swap SDK for the BATHRON testnet:
quoting, HTLC orchestration (BATHRON M1 leg; Bitcoin-signet and EVM legs, historical) and inventory views.

- `sdk/` — Python swap SDK (HTLC builders, watchers, wallets)
- `bin/`, `web/` — LP dashboard service (`:8080`)

Maintained as a **demonstrator**: it exercises the settlement primitives end to
end. It is not a supported product.
