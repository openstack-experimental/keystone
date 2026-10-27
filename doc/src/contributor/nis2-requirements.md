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
| --------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
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
| --- | ----------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| (a) | Policies on risk analysis and information system security | Threat analysis in the [security review](security-review.md) (vectors V1–V10) and the [security model](security-model.md) invariants. [Security reference](../admin/security-reference.md) lists secure defaults, interfaces, failure semantics and data inventory. | Its own risk register, naming Keystone, the identity data it holds and the blast radius of a compromise. | No single packaged risk assessment (also a CRA gap, see the technical file index). |
| (b) | Incident handling | Signed, tamper-evident CADF audit of every authentication attempt and state change (ADR 0023, `admin/features/audit.md`). Rate-limit, lockout and policy-deny outcomes. OpenTelemetry traces and Prometheus metrics. [Operations](../admin/operations.md#detecting-security-incidents) lists the audit records, metrics and alerts to use as detection signals. | Detection thresholds, on-call, escalation, the incident process itself. | None open. Alert rules for authentication failures are left to the operator. |
| (c) | Business continuity: backup management, disaster recovery, crisis management | Encrypted Raft snapshot (`backup` command, AES-256-GCM under a backup DEK), Raft replication, health and readiness endpoints. [Operations](../admin/operations.md#backup-and-recovery) lists what to back up, a restore test, what a restore does not bring back, and key custody. | Backup schedule, off-site copies, running the restore tests, recovery objectives, crisis plan. | None open. |
| (d) | Supply chain security, including relationships with direct suppliers | Dependency policy (`cargo deny`, `cargo vet`, Dependabot), digest-pinned base images, SBOM per binary, build attestations, cosign-signed policy bundle, OpenVEX statements ([section 3](#3-supplier-assurance-summary-arts-213-and-22)). | Supplier due diligence on the vendor or build it deploys; verifying the artefacts before rollout. | None open. Evidence exists; see section 3. |
| (e) | Security in acquisition, development and maintenance, including vulnerability handling and disclosure | Secure development gates (policy CI gates A–J, fuzzing, mutation tests, `unsafe_code = "forbid"`), [cybersecurity policy](cybersecurity-policy.md), [SECURITY.md](https://github.com/openstack-experimental/keystone/blob/main/SECURITY.md) disclosure process, VEX, advisories via GHSA. | Patch management with a service-level target, change control, a test environment. | Upstream patches the latest release only ([support policy](support-policy.md)); an operator on a vendor build needs the vendor's window. |
| (f) | Policies and procedures to assess the effectiveness of the measures | Weekly audit and fuzz workflows, scheduled mutation testing, a dated security review. CI is the test record. | Its own audits, penetration tests and review cadence. | No per-release test report and no third-party penetration test is recorded (technical file index, known gaps). |
| (g) | Basic cyber hygiene and cybersecurity training | Secure defaults ([security reference](../admin/security-reference.md)), reviewer checklist in the security model for contributors. | Operator staff training, patch hygiene, admin practices. | Out of scope for the software. |
| (h) | Policies and procedures on the use of cryptography and encryption | [Crypto inventory](crypto-inventory.md): algorithm, provider and FIPS status per primitive, kept current by a repository rule. Encryption at rest for the Raft store and backups, Fernet for tokens, rustls for TLS. Not-validated primitives are listed. | Key management policy: KEK custody, Fernet and credential key rotation schedule, TLS termination and ciphers. | None open for documentation. SQL identity data is stored as-is in the database (security reference, encryption coverage). |
| (i) | Human resources security, access control policies and asset management | OPA/Rego policy on every handler, delegation invariants, failed-auth lockout, inactive-account and password expiry, passkeys, mTLS/SPIFFE on the admin socket. SBOM and VEX give a component inventory. | Joiner-mover-leaver process, privileged-access review, the asset register entry for Keystone. | HR security is the operator's. No Keystone-specific access-review report is shipped. |
| (j) | Multi-factor or continuous authentication, secured communications | TOTP and passkey (WebAuthn) methods. `multi_factor_auth_rules` is enforced on `POST /v3/auth/tokens` ([guide](../admin/features/mfa.md)). The OAuth2 browser and device login requires a second factor from any user who holds a TOTP credential or passkey (`crates/keystone/src/api/v4/oauth2/mfa.rs`). SPIFFE/mTLS for services. Public TLS is expected at a proxy. | Enforce MFA for human administrators, protect the proxy and the admin listener. | **Partial.** N4: the rules are not evaluated by the federation and OAuth2 login paths. K8s, EC2 and passkey are exempt by design. |

### Notes on single measures

- **(j) is the one open code gap.** The multi-factor rules of a user are
  enforced on `POST /v3/auth/tokens` and not on the other token-issuing paths
  (N4). K8s and EC2 are machine and delegated access, and a passkey is
  multi-factor on its own, so those are exempt by design. Federation and the
  OAuth2 login remain to be decided.
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
| ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| What is in the build? | CycloneDX 1.5 SBOM per binary attached to each GitHub release (`release-sbom.yml`); SPDX SBOM attestation on container images; dependency graph embedded in binaries. |
| Can I verify the artefact is from you? | GitHub build attestations on binaries and images; cosign signature on the OPA policy bundle. Steps in [Verifying release artifacts](../admin/verify-artifacts.md). |
| Which known vulnerabilities affect it? | OpenVEX file shipped with each release and explained in [VEX statements](vex.md). Two advisories are assessed `affected` with accepted residual risk. |
| How are vulnerabilities handled and disclosed? | [SECURITY.md](https://github.com/openstack-experimental/keystone/blob/main/SECURITY.md): private reporting, 3-day acknowledgement, 7-day triage, GHSA with CVE request. |
| How long is it supported? | Latest release only, no fixed period ([support policy](support-policy.md)). A vendor build carries the vendor's declared period (CRA Art. 13(8)). |
| How is the software developed securely? | CI gates, fuzzing, mutation testing, a dated security review, no `unsafe`, digest-pinned and non-root container images ([CRA requirements](cra-requirements.md)). |
| Where is the cryptography documented? | [Crypto inventory](crypto-inventory.md). |
| Is there independent assurance? | No third-party penetration test is recorded in this repository. Conformity route is the manufacturer's decision ([technical file index](cra-technical-file.md)). |

### Coordinated vulnerability disclosure (Art. 12)

Art. 12 makes each Member State designate a CSIRT as coordinator for coordinated
vulnerability disclosure, and ENISA runs the European vulnerability database.
Neither places a duty on the project. Keystone's own channel is GitHub private
vulnerability reporting. GitHub advisories carry CVE identifiers, which European
databases ingest. A reporter who goes to a national CSIRT coordinator instead
has no direct route to the maintainers, because the project publishes no role
mailbox. That is an accepted risk in the
[cybersecurity policy](cybersecurity-policy.md#accepted-risks).

## 4. Implementing Regulation (EU) 2024/2690

Implementing Regulation (EU) 2024/2690 sets the technical and methodological
requirements of Art. 21(5) NIS2 for DNS service providers, TLD registries, cloud
computing service providers, data centre service providers, content delivery
networks, managed service providers, managed security service providers, online
marketplaces, search engines, social networks and trust service providers. It
also defines when an incident is significant for these entities. Other NIS2
entities remain under Art. 21(2) only. The most likely class for a Keystone
deployment is the **cloud computing service provider**, the operator of an
OpenStack cloud.

Section headings in the Annex (security policy, risk management, incident
handling, continuity, supply chain, acquisition and development, effectiveness,
hygiene, cryptography, human resources, access control, asset management,
physical security) are quoted from general knowledge and cited at section level
only. Check them, and the sub-requirements, against the Official Journal text
before use.

The measures overlap with section 2. The table adds only what the Regulation
asks for in more detail, with the Keystone evidence.

| Annex area | What it adds over Art. 21(2) | Keystone provides | Operator must add | Gap / action |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Incident handling, monitoring and logging | Logging of security-relevant events, protected and retained, with monitoring and detection | Signed CADF audit of every authentication attempt and state change, spool and sink, [detection guide](../admin/operations.md#detecting-security-incidents) | Centralised log store, retention period, time synchronisation, access control on logs, detection rules | None open. Retention is the operator's decision; the [audit guide](../admin/features/audit.md#retention-and-protection) says what Keystone does and does not keep |
| Business continuity and disaster recovery | Backup management, recovery plans, tested | Encrypted snapshots, [recovery guide](../admin/operations.md#backup-and-recovery) | Recovery objectives, tests, crisis plan | None open |
| Supply chain security | Policy on suppliers, security requirements in contracts, register of suppliers | [Supplier assurance summary](#3-supplier-assurance-summary-arts-213-and-22), SBOM, VEX, attestations | Supplier register entry, contract terms, review of the vendor build | None open |
| Acquisition, development and maintenance | Secure development, change management, security testing, security patch management | CI gates, fuzzing, mutation tests, dated security review, VEX, [support policy](support-policy.md) | Change control, patch windows, a test environment | Latest release only is patched upstream |
| Effectiveness assessment | Regular review of measures, audits, testing | Weekly audit and fuzz workflows, security review | Its own audits and penetration test | No third-party penetration test is recorded |
| Cryptography | Cryptography policy, key management over the full key lifecycle | [Crypto inventory](crypto-inventory.md); key rotation for Fernet, credential keys and the Raft DEK ([Fernet](../admin/tokens/fernet.md), [distributed storage](../admin/storage/distributed.md)) | KEK custody, TLS policy, rotation schedule | None open |
| Access control and authentication | Access policy, privileged account management, strong authentication including MFA | OPA policy on every handler, lockout and expiry, TOTP and passkeys, `multi_factor_auth_rules` ([guide](../admin/features/mfa.md)), mTLS and SPIFFE for the admin socket | Joiner-mover-leaver, privileged-access review, MFA for administrators | N4: rules not evaluated on federation and OAuth2 login |
| Asset management | Inventory of assets and their classification | SBOM per binary, [data inventory](../admin/security-reference.md#data-inventory) | The asset register | None open |
| Human resources, hygiene and training, physical security | Staff screening, training, physical and environmental controls | Not applicable to the software | All of it | Out of scope for the software |
| Significant incident criteria | When an incident is significant for these entities | Audit evidence only | Classification and reporting | Out of scope, see below |

Keystone is one component of a cloud. Whether the cloud as a whole meets the
Regulation depends on the operator's controls around it. This page does not make
that assessment.

## 5. Not covered here

- **Art. 23 incident reporting** (early warning in 24 h, notification in 72 h,
  final report in one month). It is the operator's duty to its CSIRT. The audit
  trail and the detection guide give it the evidence. The reporting timeline
  itself is not analysed on this page. The same applies to the significant
  incident thresholds of Regulation 2024/2690.
- **Art. 20 governance** (management approval, oversight and training).
- **National transposition.** Member States add sector rules, supervision and
  penalties.

## 6. Open work items

| ID | Item | Priority | Effort |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ------ |
| N4 | Decide whether the federation and OAuth2 login paths must honour `multi_factor_auth_rules`, and enforce or document each | P2 | Medium |
