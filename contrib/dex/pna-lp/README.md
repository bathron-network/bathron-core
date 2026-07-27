# BATHRON LP dashboard + swap SDK

> **Status: experimental prototype.** This component is a working demonstrator for
> the BATHRON public testnet. It is suitable for testing and exploration, not for
> production use, and its interfaces may change without notice.

Liquidity-Provider dashboard and Python swap SDK for the BATHRON testnet:
quoting, HTLC orchestration (BATHRON/BTC-signet/EVM legs) and inventory views.

- `sdk/` — Python swap SDK (HTLC builders, watchers, wallets)
- `bin/`, `web/` — LP dashboard service (`:8080`)

Maintained as a **demonstrator**: it exercises the settlement primitives end to
end. It is not a supported product.
