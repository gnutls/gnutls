# GnuTLS -- Information about our security issue handling process

 Security issues are reported either to [issue tracker](https://gitlab.com/gnutls/gnutls/issues)
as private bugs, or on the bug report mail address.

The following steps describe the steps we recommend to use to address the
issue.

# Which issues are security issues

A metric we consult to assessing security vulnerabilities is
the [CVSS](https://www.first.org/cvss) metric. Only vulnerabilities
at the high or critical level are handled with this process.
Issues of lower severity are managed separately, often with different
estimated times of arrival (ETAs) and backport targets.

Some of the bundled programs, including gnutls-cli and gnutls-serv,
are for testing and diagnostic purposes. Issues reported against those
programs and not library proper are not treated as a vulnerability.

# Committing a fix

The fix when is made available, preferably within 1 month of the report,
is pushed to the repository using a detailed message on all supported
branches which are affected. The commit message must refer to the bug
report addressed (e.g., our issue tracker or some external issue tracker).

For issues reported by third parties which request an embargo time, the
general aim to have embargo dates which do not exceed the upcoming stable
release date, or the following one, if the report was received late for
a fix to be included. In exceptional circumstances longer initial embargoes
may be negotiated by mutual agreement between members of the security team
and other relevant parties to the problem.

# Releasing

Currently our releases are time-based, thus there are no special releases
targeting security fixes. At release time the NEWS entries must reflect
the issues addressed (also referring to the relevant issue trackers), and
security-related entries get assigned a GNUTLS-SA (gnutls security advisory
number). The assignment is done at release time at the web repository, in
the 'security-entries' path. The number assigned is the year separated
with a dash with the first unassigned number for the year.

