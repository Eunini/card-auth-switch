# Application workspace

[Open card-auth-switch](https://leads.realalma.com/fintech/card-auth-switch/)

Issue and fund cards; manage card status; authorize purchases; inspect persistent holds; reverse or settle authorizations; attach dispute evidence; process chargeback clearing and representment; and record resolutions.

Terminal requests use the Rust switch, EMV verification, simulated HSM, and Java issuer. A purchase remains held until reversed or settled. Settlement and dispute transitions produce actual double-entry postings.

## Accounts and team access

Create an account with a name, email, and password. Alternatively, open a workspace immediately and save that account from Workspace later. Upgrading a guest keeps its records. Sign out and sign in to resume saved work. A single account works across the four applications.

Workspace owners can issue one-use, seven-day invitations for analysts or supervisors. Invitees create their own accounts, accept the code from Workspace, and switch between workspaces they belong to. STR filing requests require review by a different supervisor; requesters cannot approve their own filings.

Sessions use secure, HTTP-only cookies. Passwords are salted and hashed with scrypt. Writes require a session-bound CSRF token. Every record mutation checks workspace ownership, and operation keys are scoped to the workspace. Persistent application data uses SQLite outside the source tree; clearing, cases, and the card issuer also use dedicated PostgreSQL databases. Ledger data is persisted by the three Rust replicas.

## Hosting and verification

The UI source is in `web/`. The shared authenticated application gateway, SQLite store, deployment scripts, and public browser test are in [quorum-ledger/ops/portfolio-demo](https://github.com/Eunini/quorum-ledger/tree/main/ops/portfolio-demo). Java and Rust services bind only to loopback. Nginx serves the applications over HTTPS. Systemd supervises the services and starts them at boot. Runtime credentials, private synthetic card material, and databases remain outside Git.

[Recorded public workflow checks](public-deployment-verification.json) and the screenshots in this directory describe the deployed application. Earlier command-line recordings and benchmark measurements remain separately documented.

This is a development environment with synthetic financial data, public test cryptographic keys, and fictional participants. It is not connected to a bank or card scheme. Reports are not submitted to regulators.
