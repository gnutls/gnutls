# GnuTLS -- Information about our security issue handling process

 Security issues are reported either to [issue tracker](https://gitlab.com/gnutls/gnutls/issues)
as private bugs, or on the bug report mail address.

The following steps describe the steps we recommend to use to address the
issue.

# Which issues are security issues

A metric we consult to assessing security vulnerabilities is
the [CVSS](https://www.first.org/cvss) metric. Only vulnerabilities
at the high or critical level are handled with this process. Other
issues are handled with the normal release process.

# Committing a fix

The fix when is made available, preferrably within 1 month of the report,
is pushed to the repository using a detailed message on all supported
branches which are affected. The commit message must refer to the bug
report addressed (e.g., our issue tracker or some external issue tracker).

For issues reported by third parties which request an embargo time, the
general aim to have embargo dates which are two weeks or less in duration.
In exceptional circumstances longer initial embargoes may be negotiated by
mutual agreement between members of the security team and other relevant
parties to the problem. Any such extended embargoes will aim to be at most
one month in duration.

# Releasing

Currently our releases are time-based, thus there are no special releases
targetting security fixes. At release time the NEWS entries must reflect
the issues addressed (also referring to the relevant issue trackers), and
security-related entries get assigned a GNUTLS-SA (gnutls security advisory
number). The assignment is done at release time at the web repository, in
the 'security-entries' path. The number assigned is the year separated
with a dash with the first unassigned number for the year.

