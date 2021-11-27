# Release process

1. Create a new 'milestone' for the next release and move all issues
   present in the current release milestone.
1. Verification of release notes: ensure that release notes
   ([NEWS](NEWS)) exist for this release, and include all significant
   changes since last release.
1. Update of release date in [NEWS](NEWS), and bump of version number
   in [configure.ac](configure.ac) as well as soname numbers in
   [m4/hooks.m4](m4/hooks.m4).
1. Remove the last section of [devel/libgnutls.abignore], update the
   *.abi files under [devel/abi-dump] submodule, run `make
   abi-dump-latest`, and push any changes to the [abi-dump
   repository]; then do `make abi-check`
1. Create a tarball and detached GPG signature:
```console
make distcheck
git tag -s $VERSION
git push && git push $VERSION
gpg --detach-sign gnutls-$VERSION.tar.xz
```
1. Upload the tarball and the signature to ftp.gnupg.org:
```console
scp gnutls-$VERSION.tar.xz* ftp.gnupg.org:/home/ftp/gcrypt/gnutls/v$(expr $VERSION : '\([0-9]*\.[0-9]*\)')/
```
1. Create and send announcement email based on previously sent email
   to the list and [NEWS](NEWS) file.
1. Create a [NEWS entry] and/or a [security advisory entry] at
   [web-pages repository] if necessary. The NEWS entry is usually
   pointing to the announcement email. A commit auto-generates the
   [gnutls web site].
1. Optionally announce the release on the @GnuTLS twitter account.
1. Close the current release milestone.

[abi-dump repository]: https://gitlab.com/gnutls/abi-dump
[NEWS entry]: https://gitlab.com/gnutls/web-pages/-/tree/master/news-entries
[security advisory entry]: https://gitlab.com/gnutls/web-pages/-/tree/master/security-entries
[web-pages repository]: https://gitlab.com/gnutls/web-pages/
[gnutls web site]: https://gnutls.gitlab.io/web-pages/
