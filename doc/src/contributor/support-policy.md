# Support policy

This page states what the upstream project does and does not commit to for
security support. It supports the [cybersecurity policy](cybersecurity-policy.md)
and the [CRA requirements](cra-requirements.md).

## Position

The upstream project is an open-source software steward under the Cyber
Resilience Act (Art. 3(14), Art. 24). It does not place a product on the market
and gives **no support period** (Art. 13(8)). The five-year minimum applies to
the manufacturer that ships or sells a Keystone build.

What the project does commit to:

- **Latest release only.** Security fixes go into the latest release. Older
  releases are not patched. This holds before and after a 1.0 release until
  maintainers change this page.
- **Vulnerability handling for that release.** Reporting, triage times,
  advisories and disclosure follow [SECURITY.md](https://github.com/openstack-experimental/keystone/blob/main/SECURITY.md)
  and the [cybersecurity policy](cybersecurity-policy.md).
- **No retroactive support.** Publishing an advisory for a release does not
  create a patch for it.
- **Changes announced.** A change to this policy is published in the
  `Security announcements` category of GitHub Discussions and in the release
  notes of the release that carries it.

## What a downstream manufacturer must do

A vendor that ships Keystone as part of a product with digital elements owns
the support period for that product:

1. Declare a support period of at least five years, or a shorter one with a
   justification based on the expected use time (Art. 13(8)), and publish the
   end date in the user information (Annex II).
2. Backport upstream security fixes to the release it supports. Upstream does
   not provide patch-only branches, so the vendor maintains its own.
3. Keep consuming the upstream evidence: security advisories, the SBOM and
   the [VEX statements](vex.md) that ship with each release, and the
   [Art. 14 runbook](cra-art14-runbook.md) for reporting to authorities.
4. Report vulnerabilities found in a backport upstream, so all users benefit
   (Art. 13(6)).

Operators who run Keystone for their own cloud and depend on a longer window
than the latest release provides should agree it with their vendor, or track
upstream releases.

## Accepted risk

A deployment that cannot follow the latest release has no upstream security
fixes. The upstream project accepts this because it has no commercial
relationship with users and no capacity to maintain release branches. This is
not a gap in the steward's own duties; it is the main reason vendors carry the
manufacturer role.

## Review

Revisit this page when the project defines a 1.0 line, when a maintainer or
sponsor offers capacity for long-term branches, or when harmonised standards
under the CRA change what a steward must state.
