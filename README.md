# OTC Trust - Secure Fund Management

A smart contract system that **guarantees client funds can only be sent to pre-approved addresses**.

---

## Why This Exists

Your clients need assurance that when they deposit funds:

1. **Their money is protected** — funds can ONLY go to whitelisted addresses
2. **No one can steal** — not even the person executing daily transactions
3. **Recovery is possible** — if something goes wrong, authorized signers can help

---

## How It Works

```
┌──────────────────────────────────────────────────────────────────────┐
│                          CLIENT FUNDS SAFE                           │
│                                                                      │
│   ┌────────────────────────────────────────────────────────────┐     │
│   │                    WHITELIST GUARD                         │     │
│   │                                                            │     │
│   │   ✅ Send to Bank Account A        (whitelisted)           │     │
│   │   ✅ Send to Bank Account B        (whitelisted)           │     │
│   │   ✅ Send to Settlement Wallet     (whitelisted)           │     │
│   │                                                            │     │
│   │   ❌ Send anywhere else            BLOCKED                 │     │
│   │   ❌ Remove this guard             BLOCKED                 │     │
│   │   ❌ Change Safe settings          BLOCKED                 │     │
│   └────────────────────────────────────────────────────────────┘     │
│                                                                      │
│   Executor: Day-to-day operator (uses Safe UI)                       │
│   Recovery: Authorized signers (can update whitelist if needed)      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Security Guarantees

| Threat                                 | Protected? | How                                                  |
| -------------------------------------- | ---------- | ---------------------------------------------------- |
| Executor sends to unauthorized address | ✅ Yes     | Guard blocks all non-whitelisted destinations        |
| Executor removes the guard             | ✅ Yes     | Guard blocks `setGuard()` function                   |
| Executor adds a backdoor module        | ✅ Yes     | Guard blocks `enableModule()` function               |
| Executor adds an accomplice as owner   | ✅ Yes     | Guard blocks `addOwner()` function                   |
| Executor changes security settings     | ✅ Yes     | Guard blocks all admin functions                     |
| Executor uses delegatecall exploit     | ✅ Yes     | Guard blocks ALL delegatecalls                       |
| Executor loses their key               | ✅ Yes     | Recovery signers can enable bypass and recover funds |

**The executor can ONLY send funds to whitelisted addresses. Nothing else.**

---

## Roles

| Role         | Who                | What They Can Do                                        | What They Cannot Do                 |
| ------------ | ------------------ | ------------------------------------------------------- | ----------------------------------- |
| **Executor** | Trust operator     | Send to whitelisted addresses via Safe UI               | Send anywhere else, change settings |
| **Recovery** | Authorized signers | Add/remove whitelist addresses, enable emergency bypass | Day-to-day transactions             |

---

## Daily Operations (Executor)

The executor uses the standard **Gnosis Safe interface** at [app.safe.global](https://app.safe.global):

1. Log in with executor wallet
2. Click "New Transaction"
3. Enter recipient (must be whitelisted)
4. Enter amount
5. Sign and execute

**If the address is not whitelisted, the transaction will fail.**

---

## Emergency Recovery

If the executor loses their key or becomes unavailable:

1. Recovery signers call `setBypass(true)` on the guard
2. Recovery signers transfer funds to a safe address
3. Recovery signers call `setBypass(false)` to restore protection
4. New executor key can be set up

---

## What Gets Blocked

The guard prevents these Safe functions from being called directly:

```
setGuard()              — Cannot remove the guard
enableModule()          — Cannot add modules
disableModule()         — Cannot remove modules
addOwnerWithThreshold() — Cannot add owners
removeOwner()           — Cannot remove owners
swapOwner()             — Cannot swap owners
changeThreshold()       — Cannot change threshold
setFallbackHandler()    — Cannot change handler
delegatecall            — Always blocked
```

**There is no way for the executor to bypass the whitelist.**

---

## Setup Summary

1. **Create Safe** — 1 owner (executor), threshold 1
2. **Deploy Guard** — with Safe address, admin address, and initial whitelist
3. **Set Guard on Safe** — via Settings → Setup → Transaction Guard
4. **Configure Recovery** — set admin to recovery multisig or Zodiac Roles

---

## Contract

**`WhitelistGuard.sol`** — 230 lines of Solidity

### Key Functions

```solidity
// View - check if address is whitelisted
isWhitelisted(address) → bool

// Admin only - manage whitelist
addToWhitelist(address)
removeFromWhitelist(address)
addBatch(address[])

// Admin only - emergency
setBypass(bool)

// Admin only - admin management
setAdmin(address)
lockAdmin()  // permanent!
```

### Immutable Properties

- `safe` — the Safe this guard protects (set at deployment)
- Blocked function selectors (hardcoded, cannot be changed)

---

## Testing

36 tests covering all security scenarios:

```bash
cd contracts
forge test
```

```
✅ Blocks setGuard
✅ Blocks enableModule
✅ Blocks disableModule
✅ Blocks addOwner
✅ Blocks removeOwner
✅ Blocks swapOwner
✅ Blocks changeThreshold
✅ Blocks setFallbackHandler
✅ Blocks delegatecall (always)
✅ Blocks non-whitelisted addresses
✅ Allows whitelisted addresses
✅ Bypass still blocks admin functions
✅ Only admin can manage whitelist
✅ Only admin can enable bypass
... and more
```

---

## Files

```
contracts/
├── src/WhitelistGuard.sol    # The guard contract
├── test/WhitelistGuard.t.sol # Security tests
└── script/Deploy.s.sol       # Deployment script
```

---

## FAQ

**Q: Can the executor send funds to their personal wallet?**  
A: Only if that wallet is whitelisted. If not, the transaction fails.

**Q: Can the executor remove the guard and then send anywhere?**  
A: No. The guard blocks the `setGuard()` function.

**Q: Can the executor add a module to bypass the guard?**  
A: No. The guard blocks the `enableModule()` function.

**Q: What if we need to add a new recipient address?**  
A: Recovery signers call `addToWhitelist(newAddress)` on the guard.

**Q: What if the executor loses their key?**  
A: Recovery signers enable bypass, transfer funds, then set up new executor.

**Q: Is the whitelist on-chain and verifiable?**  
A: Yes. Anyone can call `isWhitelisted(address)` to verify.

---

## For Clients

You can verify the protection yourself:

1. Go to the Safe on [app.safe.global](https://app.safe.global)
2. Check Settings → Setup → Transaction Guard (shows guard address)
3. On the guard contract, call `isWhitelisted(address)` to see approved destinations
4. Verify the guard code matches this repository

**Your funds can only go to addresses you can verify on-chain.**

---

## License

MIT
