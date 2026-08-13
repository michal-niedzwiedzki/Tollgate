# Terms of Service

**Last updated: [DATE]**

## 1. What this is, and what it is not

**[DOMAIN]** is an informational website about **Tollgate**, an open-source software project
published by [YOUR NAME], an individual based in India.

Read this part carefully, because it is the whole shape of the agreement:

- **I do not operate a payment service.** There is no hosted Tollgate gateway. Nothing you do
  passes through infrastructure I run.
- **I never hold, receive, control, or transmit your funds.** Tollgate is designed so that payments
  move directly from payer to payee by the payer's own cryptographic signature. I am not a
  custodian, escrow agent, exchange, broker, payment processor, or money transmitter, and I do not
  act as an intermediary in any transaction.
- **I provide software, not a financial service.** What you get is source code under a licence.
  What you do with it is yours.

By using this website you agree to these terms. If you do not agree, please do not use the site.

## 2. The software is licensed separately

Tollgate's source code is released under the **Apache License 2.0**. That licence — not this page —
governs your rights to use, modify and distribute the software, including its patent grant and its
disclaimer of warranty.

These terms govern only your use of **this website**. Where the two overlap, the Apache License 2.0
controls the software.

## 3. Testnet only — no real value

The current release runs on **Base Sepolia (chain 84532) with testnet USDC**. Testnet tokens have
no monetary value and are not exchangeable for anything.

Tollgate has **not** been audited, and its settlement path has never been exercised on a live public
network. Anyone deploying it against mainnet or real funds does so entirely at their own risk and
should commission a security audit first. The project's README lists its known limitations plainly;
please read them.

## 4. No advice of any kind

Nothing on this website or in the repository is financial, investment, legal, tax, or accounting
advice. No fiduciary or advisory relationship is created by your reading it.

**You are responsible for your own regulatory position.** In India, stablecoins and similar assets
are treated as Virtual Digital Assets, attracting tax under section 115BBH and TDS under section
194S, and entities that exchange, transfer, or safekeep them may be reporting entities under the
PMLA required to register with FIU-IND. Other countries impose their own rules. If you run
Tollgate in a way that touches real value — particularly if you hold funds for anyone else — those
obligations attach to **you**, and you should take professional advice before you start.

## 5. Your responsibilities if you run Tollgate

Tollgate is infrastructure that handles money and secrets. If you deploy it:

- **You operate it.** Your keys, your servers, your database, your users' data.
- **Keys are your problem.** The settler key is a hot key in an environment variable by design, and
  the project says so. Production deployments want a KMS or a threshold signer.
- **Read the stated boundaries.** Documented limitations — including the deny-by-default egress
  network policy the application expects but does not itself enforce — are your responsibility to
  address in deployment.
- **Do not enable the loopback escape hatch in production.** `TOLLGATE_ALLOW_LOOPBACK_UPSTREAM`
  exists for local testing and disables an SSRF defence.
- **Comply with the law** wherever you and your users are.

## 6. Acceptable use of this website

Please do not attempt to gain unauthorised access to the site or its hosting, disrupt or overload
it, use it for anything unlawful, or misrepresent the project as an offering of financial services.

## 7. No warranty

**This website and the Tollgate software are provided "as is" and "as available", without warranties
of any kind**, express or implied, including any implied warranty of merchantability, fitness for a
particular purpose, title, or non-infringement.

I do not warrant that the site or the software will be uninterrupted, error-free, secure, or free of
defects, or that the software is fit for any particular deployment. This mirrors the disclaimer in
the Apache License 2.0.

## 8. Limitation of liability

To the maximum extent permitted by law, [YOUR NAME] shall not be liable for any indirect,
incidental, special, consequential, exemplary or punitive damages, nor for any loss of funds,
digital assets, private keys, profits, data, or business, arising out of or relating to this
website or the Tollgate software — whether in contract, tort, or otherwise, and even if advised of
the possibility.

**In particular, I am not liable for losses arising from your use, deployment, or modification of
the software**, including smart-contract behaviour, key compromise, misconfiguration, third-party
network or blockchain failure, or any bug in the code.

Nothing here excludes liability that cannot lawfully be excluded.

## 9. Third-party links and services

This site links to third parties such as GitHub, block explorers and public RPC endpoints. I do not
control them, do not endorse them, and am not responsible for their content, availability, or
terms. Blockchain networks themselves are independent, permissionless systems that no one operates
on your behalf.

## 10. Changes

These terms may change; the "last updated" date will reflect it. Material changes to the project's
status — for example, if a hosted service is ever offered — will require terms that address that
service specifically, and those will be published before any such service launches.

## 11. Governing law

These terms are governed by the laws of **India**, and the courts at **[YOUR CITY], India** shall
have exclusive jurisdiction, subject to any mandatory consumer-protection rights available to you
where you live.

## 12. Contact

**[CONTACT EMAIL]**

---

*Tollgate is open-source software published under the Apache License 2.0. These terms are a
good-faith starting point written for a non-commercial, non-custodial, testnet-only open-source
project — they are not legal advice. Before offering any hosted service, handling real funds, or
taking payment from anyone, have a qualified lawyer in your jurisdiction review them.*
