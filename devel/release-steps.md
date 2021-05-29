# Release process

 0. Create a new 'milestone' for the next release and move all issues present in the
    current release milestone.
 1. Verification of release notes: ensure that release notes ([NEWS](NEWS)) exist
    for this release, and include all significant changes since last release.
 2. Update of release date in [NEWS](NEWS), and bump of version number in
    [configure.ac](configure.ac) as well as soname numbers in [m4/hooks.m4](m4/hooks.m4).
 3. make distcheck
 4. git tag -s $VERSION
 5. git push && git push $VERSION
 6. gpg --detach-sign gnutls-$VERSION.tar.xz
 7. scp gnutls-$VERSION.tar.xz* ftp.gnupg.org:/home/ftp/gcrypt/gnutls/v$(expr $VERSION : '\([0-9]*\.[0-9]*\)')/
 8. Create and send announcement email based on previously sent email to the list and
    [NEWS](NEWS) file.
 9. Create a NEWS entry at [web-pages repository](https://gitlab.com/gnutls/web-pages/-/tree/master/news-entries),
    and/or [a security advisory entry](https://gitlab.com/gnutls/web-pages/-/tree/master/security-entries)
    if necessary. The NEWS entry is usually pointing to the announcement email.
    A commit auto-generates the [gnutls web site](https://gnutls.gitlab.io/web-pages/)
    which is mirrored twice a day by www.gnutls.org.
10. Use the @GnuTLS twitter account to announce the release.
11. Close the current release milestone.
