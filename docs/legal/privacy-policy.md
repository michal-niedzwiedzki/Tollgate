# Privacy Policy

**Last updated: [DATE]**

## The short version

**This website collects nothing about you.** No cookies, no analytics, no tracking pixels, no
contact forms, no accounts, no newsletter. Nothing you do here is recorded by me.

The rest of this page explains the two places data *does* exist — my hosting provider's server
logs, and the Tollgate software itself when **you** run it — because saying "we value your privacy"
and stopping there would be worth nothing.

## Who this is about

Tollgate is an open-source software project published by [YOUR NAME], an individual based in
India. There is no company. This policy covers the website at **[DOMAIN]** only.

Contact: **[CONTACT EMAIL]**

## What this website collects

Nothing.

| | |
|---|---|
| Cookies | None set |
| Analytics | None |
| Forms, signup, waitlist | None |
| Accounts | None |
| Advertising / third-party trackers | None |
| Wallet connection | None — this site never asks you to connect a wallet |

There is nothing to opt out of, nothing to delete, and no profile of you anywhere.

## What my hosting provider sees

The site is served by **[HOSTING PROVIDER]**. Like every web host, it processes basic technical
information to deliver the page — your IP address, browser user-agent, the page requested, and the
time. This is standard server logging, it happens before anything reaches me, and I do not use it
to identify anyone or build any profile.

That data is governed by [HOSTING PROVIDER]'s own privacy policy: **[HOSTING PROVIDER PRIVACY
URL]**.

## What the Tollgate *software* does — when you run it

This is the part people actually want to know, and it is separate from this website.

Tollgate is a self-hosted API payment gateway. If you download and run it, **you** operate it and
**you** are responsible for the data it handles. I never see any of it — I run no hosted service,
no gateway, no server that your traffic passes through, and I receive no copy of anything.

When you run Tollgate, the software handles:

- **Wallet addresses.** Payer addresses, provider payout addresses, and the issuer/subject
  addresses inside capability chains are stored in your database. A public blockchain address is
  pseudonymous, not anonymous — it can often be linked to a person through other information.
- **Payment authorisations.** Signed EIP-3009 payloads, amounts, nonces, and which endpoint was
  called, in your ledger.
- **Client IP addresses.** The proxy adds an `X-Forwarded-For` header when it forwards a request,
  so **the upstream provider you proxy to receives the calling agent's IP address.**
- **A public feed.** The bundled dashboard exposes a `/v1/feed` endpoint that shows **full payer
  wallet addresses, untruncated**, along with amounts, endpoints and transaction hashes. If you
  expose that endpoint or dashboard publicly, you are publishing your users' payment activity.
  This is deliberate for a testnet demo and is a decision you should revisit before running it
  anywhere real.

If you run Tollgate in a way that processes other people's personal data, you are the data
fiduciary/controller for it under laws such as India's **Digital Personal Data Protection Act,
2023**, or the GDPR if you serve users in the EU/UK. Those obligations are yours, not mine.

## Blockchain data cannot be deleted

Settled payments are recorded on a public blockchain. Once a transaction is confirmed, **it is
permanent, public, and outside anyone's control — including mine and yours.** No one can edit,
hide, or erase it on request.

This is a genuine and unavoidable limit on the right to erasure. Anyone building on Tollgate should
understand it before putting real user data anywhere near a chain. Note also that the current
release is **testnet-only** (Base Sepolia), so no real funds and no mainnet records are involved.

## Links to other places

This site links to third parties such as GitHub, block explorers, and documentation. Once you
follow a link, that site's own privacy policy applies. I have no control over what they collect.

## Your rights

Because this website collects no personal data, there is nothing for me to access, correct,
export, or delete. If you believe I hold personal data about you anyway, write to **[CONTACT
EMAIL]** and I will respond within 30 days.

Under India's Digital Personal Data Protection Act, 2023, you have rights of access, correction and
erasure against whoever holds your data. If your data was processed by someone *running* Tollgate,
those requests go to that operator, not to me.

## Children

This site is not directed at children and collects no data from anyone, including children.

## Changes

If this policy changes, the "last updated" date above changes with it. Because I collect nothing,
any change is likely to be about the software or the hosting provider rather than about you.

---

*Tollgate is open-source software published under the Apache License 2.0. This policy describes the
project's website. It is not legal advice — if you deploy Tollgate in a way that handles real funds
or other people's personal data, get advice that accounts for your jurisdiction and use case.*
