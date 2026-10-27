# NIS2 requirements

This page derives what the EU NIS2 Directive (Directive (EU) 2022/2555) means
for Keystone and for the operators who run it. It is an engineering gap
analysis, not legal advice, and it is not a compliance claim. It complements the
[Cyber Resilience Act analysis](cra-requirements.md): the CRA binds whoever
makes the product, NIS2 binds whoever runs it.

Article numbers and the list of measures are quoted from general knowledge of
the Directive. Check them against the Official Journal text and the national
transposition before they are used in any compliance document.

Related pages: [CRA requirements](cra-requirements.md),
[Technical file index](cra-technical-file.md),
[Cybersecurity policy](cybersecurity-policy.md),
[Support policy](support-policy.md), [VEX statements](vex.md),
[Crypto inventory](crypto-inventory.md), [Security model](security-model.md).

## 1. Applicability

NIS2 regulates **entities**, not products. An essential or important entity in a
sector listed in Annex I or II must take appropriate and proportionate
cybersecurity risk-management measures (Art. 21) and report significant
incidents (Art. 23). Keystone is an identity and access management service. It
reaches NIS2 through the entities that operate it:

| Actor | NIS2 role | Consequence for Keystone |
| ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Cloud computing service providers, data centre and managed service providers running it | Essential or important entity (Annex I digital infrastructure and ICT service management), depending on size and national transposition | Art. 21 applies to the deployment: Keystone is a core security control of their cloud. |
| Any other in-scope entity (energy, health, public administration, ...) running it | Essential or important entity | Same measures; Keystone is one more network and information system to cover. |
| Distribution vendors that ship or sell a Keystone build | Suppliers of the entities above; may themselves be entities (managed service provider) | Their customers must assess them under Art. 21(3). They answer with the evidence in section 3. |
| The upstream project (steward) | Not an NIS2 entity. A supplier of software to operators and vendors. | No direct duty. The project's job is to make the operator's Art. 21 evidence cheap to produce and honest. |

Consequences for this analysis:

- Every measure in section 2 is the **operator's** duty. The tables therefore
  separate what Keystone provides from what the operator must still do. A
  Keystone feature never discharges a measure on its own.
- The CRA and NIS2 meet at the supply chain. NIS2 Art. 21(3) tells an entity to
  weigh the quality of its suppliers' products and their secure development
  practices. The CRA evidence (SBOM, VEX, advisories, support period) is what a
  careful operator will ask for.

## 2. Art. 21(2) risk-management measures

Art. 21(2) lists the minimum content of the measures, as an all-hazards
approach. The table maps each item to what Keystone gives an operator. Evidence
for the Rust implementation is verified against this repository and cites a
file. The Python implementation is not analysed here.

| Ref | Measure | Keystone provides | Operator must add | Gap / action |
| --- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| (a) | Policies on risk analysis and information system security | Threat analysis in the [security review](security-review.md) (vectors V1–V10) and the [security model](security-model.md) invariants. [Security reference](../admin/security-reference.md) lists secure defaults, interfaces, failure semantics and data inventory. | Its own risk register, naming Keystone, the identity data it holds and the blast radius of a compromise. | No single packaged risk assessment (also a CRA gap, see the technical file index). |
| (b) | Incident handling | Signed, tamper-evident CADF audit of every authentication attempt and state change (ADR 0023, `admin/features/audit.md`). Rate-limit, lockout and policy-deny outcomes. OpenTelemetry traces and Prometheus metrics (`admin/operations.md`). | Detection rules, on-call, escalation, the incident process itself. | N2: no operator guide that says which audit events and metrics to alert on. |
| (c) | Business continuity: backup management, disaster recovery, crisis management | Encrypted Raft snapshot (`backup` command, AES-256-GCM under a backup DEK), Raft replication, health and readiness endpoints. [Operations](../admin/operations.md) has an upgrade checklist and a recovery paragraph. | Backup schedule, off-site copies, restore tests, recovery objectives, crisis plan. | N1: recovery guide is one paragraph; no restore-test procedure, no key-escrow guidance beyond "preserve the KEK". |
| (d) | Supply chain security, including relationships with direct suppliers | Dependency policy (`cargo deny`, `cargo vet`, Dependabot), digest-pinned base images, SBOM per binary, build attestations, cosign-signed policy bundle, OpenVEX statements ([section 3](#3-supplier-assurance-summary-arts-213-and-22)). | Supplier due diligence on the vendor or build it deploys; verifying the artefacts before rollout. | None open. Evidence exists; see section 3. |
| (e) | Security in acquisition, development and maintenance, including vulnerability handling and disclosure | Secure development gates (policy CI gates A–J, fuzzing, mutation tests, `unsafe_code = "forbid"`), [cybersecurity policy](cybersecurity-policy.md), [SECURITY.md](https://github.com/openstack-experimental/keystone/blob/main/SECURITY.md) disclosure process, VEX, advisories via GHSA. | Patch management with a service-level target, change control, a test environment. | Upstream patches the latest release only ([support policy](support-policy.md)); an operator on a vendor build needs the vendor's window. |
| (f) | Policies and procedures to assess the effectiveness of the measures | Weekly audit and fuzz workflows, scheduled mutation testing, a dated security review. CI is the test record. | Its own audits, penetration tests and review cadence. | No per-release test report and no third-party penetration test is recorded (technical file index, known gaps). |
| (g) | Basic cyber hygiene and cybersecurity training | Secure defaults ([security reference](../admin/security-reference.md)), reviewer checklist in the security model for contributors. | Operator staff training, patch hygiene, admin practices. | Out of scope for the software. |
| (h) | Policies and procedures on the use of cryptography and encryption | [Crypto inventory](crypto-inventory.md): algorithm, provider and FIPS status per primitive, kept current by a repository rule. Encryption at rest for the Raft store and backups, Fernet for tokens, rustls for TLS. Not-validated primitives are listed. | Key management policy: KEK custody, Fernet and credential key rotation schedule, TLS termination and ciphers. | None open for documentation. SQL identity data is stored as-is in the database (security reference, encryption coverage). |
| (i) | Human resources security, access control policies and asset management | OPA/Rego policy on every handler, delegation invariants, failed-auth lockout, inactive-account and password expiry, passkeys, mTLS/SPIFFE on the admin socket. SBOM and VEX give a component inventory. | Joiner-mover-leaver process, privileged-access review, the asset register entry for Keystone. | HR security is the operator's. No Keystone-specific access-review report is shipped. |
| (j) | Multi-factor or continuous authentication, secured communications | TOTP and passkey (WebAuthn) methods; a v3 request can combine methods; the OAuth2 browser and device login requires a second factor from any user who holds a TOTP credential or passkey (`crates/keystone/src/api/v4/oauth2/mfa.rs`). SPIFFE/mTLS for services. Public TLS is expected at a proxy. | Enforce MFA for human administrators, protect the proxy and the admin listener. | **Gap.** N3: `multi_factor_auth_rules` is stored and returned but not enforced on `POST /v3/auth/tokens`, so a password alone still issues a token. |

### Notes on single measures

- **(b) and (c) are thin on guidance.** Keystone has strong audit and a working
  backup command, but the operator guidance that turns them into incident
  handling and continuity is short. N1 and N2 close that.
- **(j) is the one code gap.** The rules a user sets for required factor
  combinations are not applied to token issuance (N3). The OAuth2 login does
  require the second factor, so the gap is the v3 password path.
- **(e) depends on the support period.** NIS2 expects patching without delay. A
  steward that patches only the latest release (see the
  [support policy](support-policy.md)) gives an operator one window: upgrade to
  the latest release or buy a vendor's backports.
- **(h) is a documentation strength.** The crypto inventory is the artefact a
  regulator asks for under (h). Keep it enforced.

## 3. Supplier assurance summary (Arts. 21(3) and 22)

Art. 21(3) tells an entity to consider vulnerabilities specific to each direct
supplier, the overall quality of the supplier's products and its secure
development procedures. Art. 22 covers Union-level coordinated risk assessments
of critical supply chains and does not bind the upstream project. This table is
the answer an operator can quote when it assesses a Keystone build.

| Operator question | Answer and evidence |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| What is in the build? | CycloneDX 1.5 SBOM per binary attached to each GitHub release (`release-sbom.yml`); SPDX SBOM attestation on container images; dependency graph embedded in binaries. |
| Can I verify the artefact is from you? | GitHub build attestations on binaries and images; cosign signature on the OPA policy bundle. Steps in [Verifying release artifacts](../admin/verify-artifacts.md). |
| Which known vulnerabilities affect it? | OpenVEX file shipped with each release and explained in [VEX statements](vex.md). Two advisories are assessed `affected` with accepted residual risk. |
| How are vulnerabilities handled and disclosed? | [SECURITY.md](https://github.com/openstack-experimental/keystone/blob/main/SECURITY.md): private reporting, 3-day acknowledgement, 7-day triage, GHSA with CVE request. |
| How long is it supported? | Latest release only, no fixed period ([support policy](support-policy.md)). A vendor build carries the vendor's declared period (CRA Art. 13(8)). |
| How is the software developed securely? | CI gates, fuzzing, mutation testing, a dated security review, no `unsafe`, digest-pinned and non-root container images ([CRA requirements](cra-requirements.md)). |
| Where is the cryptography documented? | [Crypto inventory](crypto-inventory.md). |
| Is there independent assurance? | No third-party penetration test is recorded in this repository. Conformity route is the manufacturer's decision ([technical file index](cra-technical-file.md)). |

### Coordinated vulnerability disclosure (Art. 12)

Art. 12 makes each Member State designate a CSIRT as coordinator for
coordinated vulnerability disclosure, and ENISA runs the European vulnerability
database. Neither places a duty on the project. Keystone's own channel is GitHub
private vulnerability reporting. GitHub advisories carry CVE identifiers, which
European databases ingest. A reporter who goes to a national CSIRT coordinator
instead has no direct route to the maintainers, because the project publishes no
role mailbox. That is an accepted risk in the
[cybersecurity policy](cybersecurity-policy.md#accepted-risks).

## 4. Not covered here

- **Art. 23 incident reporting** (early warning in 24 h, notification in 72 h,
  final report in one month). It is the operator's duty to its CSIRT. The audit
  trail and N2 give it the evidence. The reporting timeline itself is not
  analysed on this page.
- **Art. 20 governance** (management approval, oversight and training).
- **Implementing Regulation (EU) 2024/2690**, which sets detailed technical and
  methodological requirements for cloud computing service providers and other
  digital infrastructure. A cloud operator running Keystone will need it. It
  deserves its own pass.
- **National transposition.** Member States add sector rules, supervision and
  penalties.

## 5. Open work items

| ID | Item | Priority | Effort |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ------ |
| N1 | Expand the recovery guide: backup schedule, restore-test procedure, key-escrow for the KEK and Fernet keys, what a restore does not bring back | P1 | Low |
| N2 | Add an incident-detection guide: which audit events, rate-limit and lockout signals and metrics to alert on, and how audit records support Art. 23 evidence | P1 | Low |
| N3 | Enforce `multi_factor_auth_rules` when issuing tokens on `/v3/auth/tokens` (Python parity), or document the gap and the OAuth2-only second factor | P1 | Medium |
