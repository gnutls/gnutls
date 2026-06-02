# Information about our security issue handling process

## Reporting procedure

Report any security sensitive issues as a **confidential** issue on
our [issue tracker]. In case you are unable to use the GitLab web
interface, you can still submit issues by sending an email to us, but
use the method only as a last resort; such reports require special
handling from our side.

The report should be self-contained and actionable without requiring
us to follow any links or perform any extra actions. It is also
desirable that the report contains a standalone reproducer.

## Threat model

Given GnuTLS is a library, its use-cases vary and we can't cover
everything. As such, we only target practical applications.

We assume applications are following the current best practices. For
example:

* They should be compiled with [hardening options], such as
  `-D_FORTIFY_SOURCE=3`
* The server applications should be designed to isolate resources per
  user, meaning that a compromised authenticated user cannot read or
  modify another user's data
* The applications should be designed to run without unnecessary
  privileges. libcap, libseccomp, or similar technologies would be
  useful to accomplish this

Our threat model doesn't consider attacks only possible by modifying
anything within the trust boundary (private keys, trusted
certificate authorities and their issued certificates including
intermediate CAs, etc.).

Our threat model doesn't consider attacks only possible by mis-using
API, such as supplying an out-of-range enum value, or deinitializing
an object after a missing error check of the initialization.

Denial of Service (DoS) attacks only relevant to the client are still in
scope. However, due to the nature of TLS handshake, which is always
initiated by the client, such attacks are classified as Medium or Low
severity (see below for the severity ratings).

Bugs entirely in the dependencies (nettle, libtasn1, leancrypto, gmp,
p11-kit, etc.) are out of scope. If you are unsure where the cause is,
you can still report an issue to GnuTLS, though we may later reassign
it to the other components.

The following bundled programs are for testing and diagnostic
purposes: `gnutls-cli`, `gnutls-serv`, and `gnutls-cli-debug`. Issues
reported against those programs and not library proper are out of
scope.

Subsystems and features explicitly marked as obsolete (listed below)
are out of scope:

- OpenSSL compatibility layer (`extra/openssl/*`)
- cryptodev support (`lib/accelerated/cryptodev*`)
- Linux AF\_ALG support (`lib/accelerated/afalg*`)
- SRP support (`lib/srp.[ch]` and the `srptool` program)
- TPM v1.2 support (`lib/tpm.[ch]` and the `tpmtool` program)
- Older TLS protocols: DTLS 0.9 and SSL 3.0

Subsystems and features explicitly marked as a technology preview
(listed below) are out of scope:

- PKCS\#11 cryptographic provider (`lib/pkcs11/*`)
- HPKE (`lib/hpke/*`)

The default selection of algorithms and protocols are, even if they
are considered insecure at certain point of time, out of scope. We do
our best to tighten it from time to time, though backwards
compatibility constraints limit how aggressively we can do that.

## Severity ratings

Our severity ratings differ from [CVSS], as CVSS scores are often
inadequate to accommodate our threat model. The following are the
current definitions of severity levels:

* **Critical**
  * This vulnerability is easy for remote, unauthenticated attackers
    to exploit
  * Exploitation can lead to system compromise, often resulting in
    arbitrary code execution
  * The risk is associated with popular platforms and requires no user
    interaction
  * Flaws that require authentication, local or physical access to a
    system, or an unlikely configuration are not classified as
    Critical impact
  * Issues that only affect system availability (such as DoS) are not
    classified as Critical impact.
  * Past example: N/A
* **High**
  * Exploiting or triggering the problem is not difficult
  * This is a serious problem with real-world impact
  * Flaws at this level can easily compromise the confidentiality,
    integrity, or availability of resources
  * Past example: [#1011](https://gitlab.com/gnutls/gnutls/-/work_items/1011)
* **Medium**
  * This security issue is more difficult to exploit or trigger than a
    High severity one, based on a technical evaluation of the flaw
    and/or affect unlikely configurations
  * This type of problem often requires a secondary factor or
    condition to become a serious threat
  * It may involve less strict timing requirements, wider platform
    availability, or more widely used options or protocols
  * Past example: [#1383](https://gitlab.com/gnutls/gnutls/-/work_items/1383)
* **Low**
  * This security problem is genuinely hard or unlikely to be
    exploited or triggered
  * The difficulty is typically due to factors such as demanding
    timing constraints, memory pressure error paths, specific platform
    prerequisites, or thew involvement of rare options or protocols
  * Flaws that invalidate promised security level, but the provided
    security is still good enough, fall into this category, such as
    protocol downgrade attacks
  * Past example: [#1277](https://gitlab.com/gnutls/gnutls/-/work_items/1277)

## Disclosure

We do not maintain our own disclosure window. When to release a fix is
up to the maintainers, depending on the current release cadence
(approx. 2 months), the severity of the issue, and their capacity to
handle it. In circumstances where longer embargoes may be negotiated
by mutual agreement between members of the security team and other
relevant parties to the problem.

## Releasing fixes

Currently our releases are time-based, thus there are no special
releases targeting security fixes. Only the current development branch
is the target for fixing security issues. We may help backport
important issues to previous versions up to version 3.6, if
applicable.

At release time the NEWS entries must reflect the issues addressed
(also referring to the relevant issue trackers), and security-related
entries get assigned a GNUTLS-SA (gnutls security advisory number), in
the form of `GNUTLS-SA-%Y-%m-%d` using the `strftime` format
[specifiers][strftime]. If there are multiple entries disclosed on the
same day, they are distinguished with an optional numeric suffix after
a hyphen.

All the security advisories are published on the web under the
[security-entries] page.

[CVSS]: https://nvd.nist.gov/vuln-metrics/cvss
[issue tracker]: https://gitlab.com/gnutls/gnutls/issues
[hardening options]: https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++
[strftime]: https://pubs.opengroup.org/onlinepubs/9699919799/
[security-entries]: https://gnutls.org/security-new.html
