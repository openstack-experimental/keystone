# Cybersecurity policy

This page is the project's cybersecurity policy in the sense of Art. 24 of the
Cyber Resilience Act (Regulation (EU) 2024/2847). It is an engineering and
governance statement, not legal advice.

## Role of the project

The project is an open-source software steward (Art. 3(14), Art. 24). It
develops Keystone in the open and does not place a product on the market in the
course of a commercial activity.

The project does **not** claim the duties of a manufacturer: no CE marking, no
conformity assessment, no EU declaration of conformity, and no ENISA reporting
on behalf of others. A vendor that ships or sells a Keystone build is the
manufacturer and carries those duties. The project provides the evidence
vendors need. See [CRA requirements](cra-requirements.md) for the gap analysis.

## Vulnerability handling

- Reporters use GitHub private vulnerability reporting, described in
  [SECURITY.md](https://github.com/openstack-experimental/keystone/blob/main/SECURITY.md).
- Maintainers acknowledge within 3 days and triage within 7 days.
- Fixes are prepared privately. Once a fix is released, the project publishes a
  GitHub Security Advisory with a CVE request and announces it in the
  `Security announcements` GitHub Discussions category.
- Only the latest release receives security fixes. See the
  [support policy](support-policy.md).
- Downstream manufacturers follow the [Art. 14 runbook](cra-art14-runbook.md).

## Cooperation with authorities

On a reasoned request from a market surveillance authority, the project
provides this policy and cooperates with the authority on mitigating
cybersecurity risks the project identifies.

## Accepted risks

- **Single reporting channel.** Reports depend on GitHub private vulnerability
  reporting and the availability of repository administrators. There is no
  role mailbox.
- **No PGP key.** Reporters needing encrypted mail have no option beyond the
  private GitHub channel.
- **Maintainer continuity.** The security response maintainer role is held by
  whoever the repository administrators designate. Continuity relies on more
  than one administrator holding that access.
- **Steward reporting scope.** The extent of Art. 14 duties for a steward is to
  be confirmed by legal review.

## Caveats

The CRA dates and article references in this project's documents are stated
not yet verified against the Official Journal text. Verify them before citing them externally.
