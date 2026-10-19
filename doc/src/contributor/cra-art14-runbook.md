# CRA Art. 14 reporting runbook

Art. 14 of the Cyber Resilience Act obliges **manufacturers** to report actively
exploited vulnerabilities and severe incidents. The project is an
[open-source steward](cybersecurity-policy.md). It does not file reports on
behalf of downstream manufacturers. Any reporting duty that applies to the
project itself as a steward (Art. 24(3), to the extent it is involved in
development) is handled by the security response maintainer. This page says
what the project gives downstream manufacturers so they can meet their own
deadlines, and how maintainers produce it.

## For downstream manufacturers

Subscribe to:

- The `Security announcements` category in GitHub Discussions.
- The repository's Releases.
- The GitHub Advisory Database, for this repository's advisories.

The project does not keep a private pre-notification list. Information reaches
manufacturers when the advisory is published.

### Art. 14 windows

Severe-incident reporting (one-month final report) is out of scope of this
runbook.

| Report (actively exploited vulnerability) | Deadline |
| --- | --- |
| Early warning | 24 hours from becoming aware |
| Notification | 72 hours from becoming aware |
| Final report | 14 days after a corrective measure is available |

### What the project aims to publish

For a vulnerability the project learns is **actively exploited**:

| Step | Project target |
| --- | --- |
| Confirm exploitation and severity | within 24 hours of the report |
| Publish GHSA and Discussions post, with at least a mitigation | within 72 hours |
| Publish the fix release and complete the advisory | as soon as the fix is available |

These are targets of a volunteer project, not commitments. A manufacturer
remains responsible for its own deadlines.

Each advisory states: affected versions, severity (CVSS), a description, the
fixed version, mitigations, and whether exploitation is known.

## For maintainers

The **security response maintainer** role owns this procedure. It is a role, not
a person; repository administrators designate who holds it.

1. A report arrives through GitHub private vulnerability reporting. Acknowledge
   within 3 days and triage within 7 days (see
   [SECURITY.md](https://github.com/openstack-experimental/keystone/blob/main/SECURITY.md)).
2. If there is evidence of active exploitation, move to the accelerated track:
   confirm within 24 hours.
3. Draft the GitHub Security Advisory in the private report. Fill in affected
   versions, severity, description and mitigation.
4. Request a CVE through the advisory.
5. For active exploitation, publish the advisory with the mitigation within 72
   hours even if the fix is not released. Otherwise publish with the fix.
6. Post a short note in the `Security announcements` Discussions category that
   links to the advisory.
7. After the fix release, update the advisory with the fixed version and mark
   the record complete.
8. Record the timeline (reported, confirmed, published, fixed) in the advisory
   so downstream manufacturers can reuse it in their final report.
