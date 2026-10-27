# CRA technical file index

Annex VII of the Cyber Resilience Act lists what a manufacturer's technical
documentation contains. The upstream project is an open-source steward and does
not compile this file (see [CRA requirements](cra-requirements.md) §1). A vendor
that ships or sells a Keystone build does, and this page points it to the
upstream material for each Annex VII item and says what the vendor must add.
The item list below is a working summary; check it against the Official
Journal text before use.

## Classification

Keystone is an identity management system and is treated as a **class I
important product** (Annex III). That classification is confirmed for this
project. It decides how a manufacturer signs off:

- Internal control (module A) is available only when the manufacturer applies a
  harmonised standard or an EU cybersecurity certification scheme in full.
- Otherwise the manufacturer needs third-party assessment (modules B+C or H).
- Harmonised standards were still in preparation when this page was written.
  The conformity route is the manufacturer's decision. The project does not
  choose one and plans for the third-party path.

## Annex VII mapping

| Annex VII item                                                                  | Upstream material                                                                                                                                                                                                                                 | Vendor must add                                                                                                       |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| 1. General description: intended purpose, software versions that affect compliance | Intended purpose: OpenStack identity and access management service, compatible with the Python Keystone API subset in [Python compatibility](python-compatibility.md). Release versions come from the release notes and the [verified release artifacts](../admin/verify-artifacts.md). | The product name and version it ships, its own build configuration, and its Annex II user information.                |
| 1. User information and instructions (Annex II)                                 | [Security hardening](../admin/security.md), [Security reference](../admin/security-reference.md), [Operations](../admin/operations.md), [Configuration](../admin/configuration.md); [SECURITY.md](https://github.com/openstack-experimental/keystone/blob/main/SECURITY.md) for the contact point. | The support end date for its own product, and where its customers find the SBOM and advisories.                       |
| 2. Design and development: architecture, how components interact               | [Architecture decision records](../adr/index.md), [Security model](security-model.md), [Crypto inventory](crypto-inventory.md).                                                                                                                     | Changes to the architecture or defaults in its own build.                                                              |
| 2. Vulnerability handling: policy, contact, SBOM                                | [Cybersecurity policy](cybersecurity-policy.md), [Art. 14 runbook](cra-art14-runbook.md), [VEX statements](vex.md), the CycloneDX SBOM attached to each release by `release-sbom.yml`.                                                              | Its own coordinated disclosure policy and contact for its product, and its reporting to the CSIRT and ENISA.            |
| 2. Secure distribution of updates                                               | Release binaries and container images carry GitHub build attestations; verification steps in [Verify release artifacts](../admin/verify-artifacts.md). The release gate (`release-gate.yml`) blocks a release on advisories and missing VEX statements.     | The update channel and automatic-update behaviour of its own product (Annex I Part I(2)(c)).                            |
| 2. Production and monitoring processes, validation                              | CI in `.github/workflows` (`ci.yml`, `audit.yml`, `fuzz.yml`, `mutants.yml`, `container-build.yml`, `release.yml`), `cargo deny` and `cargo vet` supply-chain checks.                                                                                | Its own build and release process if it rebuilds from source.                                                          |
| 3. Cybersecurity risk assessment                                                | [Security architecture review](security-review.md) (vectors V1–V10), [Security model](security-model.md) (invariants I1–I10), [CRA requirements](cra-requirements.md) (Annex I gap analysis).                                                       | A single risk assessment that covers its product's deployment, the shared Fernet and credential keys, and its scope.    |
| 4. Information used to determine the support period                             | [Support policy](support-policy.md). Upstream sets no support period.                                                                                                                                                                              | The declared support period (at least five years unless the expected use time is shorter) and its justification.        |
| 5. Standards, common specifications, certification schemes applied              | None applied in full. Cryptography and FIPS status are in the [Crypto inventory](crypto-inventory.md).                                                                                                                                            | The standards or scheme it applies, or the solutions it adopts where it applies none.                                  |
| 6. Test reports against Annex I Parts I and II                                  | Unit, integration and API tests, OPA policy tests, fuzz targets, mutation testing and the policy-handler coverage checks, all in CI. See [Testing](testing.md). CI logs expire; they are not an archive.                                          | Retained test reports for the exact build it ships, including penetration tests if its assessor requires them.          |
| 7. EU declaration of conformity                                                 | None. Only a manufacturer can issue it.                                                                                                                                                                                                           | The declaration, the conformity assessment (see Classification) and the CE marking.                                    |
| 8. SBOM, when a market surveillance authority asks                              | CycloneDX SBOM per release, attested; `Cargo.lock` is committed.                                                                                                                                                                                   | The SBOM for its build if it adds or changes components.                                                               |

## Known gaps in the upstream evidence

- No single document packages the risk assessment. The sources in item 3 are
  spread over four pages.
- Test reports are CI logs. Nothing retains a report per release.
- No third-party penetration test is recorded in this repository.
- The `crypto-bigint` advisory is assessed `affected` with accepted residual
  risk ([VEX statements](vex.md)). A manufacturer's assessor will ask about it.
