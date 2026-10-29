# Release process

## General steps

1. Prepare and test the security fixes in private.
1. Consider updating every submodule.
1. Create a new 'milestone' for the next release and move all issues
   present in the current release milestone.
1. Verification of release notes: ensure that release notes
   ([NEWS](NEWS)) exist for this release, and include all significant
   changes since last release.
1. Update of release date in [NEWS](NEWS), and bump of version number
   in [configure.ac](configure.ac) as well as soname numbers in
   [m4/hooks.m4](m4/hooks.m4).
1. Remove the last section of
   [devel/libgnutls.abignore](devel/libgnutls.abignore), update the
   *.abi files under [devel/abi-dump](devel/abi-dump) submodule, run
   `make abi-dump-latest`, and push any changes to the [abi-dump
   repository]; then do `make abi-check`
1. Sync [gnutls translations] from [Translation Project]:
   ```console
   rm po/*.po
   wget -np -r -l1 -nd -nv -A.po -P po \
     https://translationproject.org/latest/gnutls/
   ls po/*.po | sed 's|.*/||; s|\.po$||' | LC_ALL=C sort > po/LINGUAS
   git add -A po/ && git commit -sm 'po: sync from translationproject.org' po/
   ```
1. Create a distribution tarball: note that this requires
   the documentation to be generated. See the `fedora-docdist/build` job in
   [.gitlab-ci.yml](.gitlab-ci.yml), which does the same thing in the CI:
   ```console
   # Install necessary packages for documentation, and then:
   make distcheck
   ```
1. Create a detached GPG signature:
   ```console
   gpg --detach-sign --user your-key-id gnutls-$VERSION.tar.xz
   ```
   Repeat this step for everyone who's available to sign the release,
   and concatenate the signatures together.
1. *Point of no return: update the release merge request with security fixes.*
1. Merge the changes.
1. Create a git tag on the merge commit and push it:
   use [git-evtag] if possible; at least use GPG-signed tag:
   ```console
   git tag -s $VERSION -m "released $VERSION"
   git push --atomic origin $VERSION
   ```
1. Upload the tarball and the signature to ftp.gnupg.org:
   ```console
   scp -oHostKeyAlgorithms=+ssh-rsa gnutls-$VERSION.tar.xz* ftp.gnupg.org:/home/ftp/gcrypt/gnutls/v$(expr $VERSION : '\([0-9]*\.[0-9]*\)')/
   ```
1. Download `mingw32/archive` artifact for new release from [CI/CD jobs].
   Rename downloaded zip file to `gnutls-$VERSION-w32.zip`.
   Create a detached GPG signature.
   Upload zip and signature files to ftp.gnupg.org.
   Do the same analogically for `mingw64/archive`.
1. Reveal and close the security issues addressed in the release.
1. Close the security fixes merge requests addressed in the release.
1. Create and send announcement email based on previously sent email
   to the [gnutls-help@lists.gnutls.org list] and [NEWS](NEWS) file.
   Optionally CC [info-gnu@gnu.org list] for extra visibility.
1. Create a [NEWS entry] and/or a [security advisory entry] at
   [web-pages repository] if necessary. The NEWS entry is usually
   pointing to the announcement email in gnutls-help archives.
   A commit auto-generates the [gnutls web site].
1. Optionally announce the release on the @GnuTLS twitter account.
1. Close the current release milestone.
1. Notify the [Translation Project] of the new release, according to
   the guidance from the [Translation Project maintainers page].

## Distribution specific steps

- To update Fedora, you can use the [packit](http://packit.dev/) tool
  to submit pull-requests to the package repository. Install the tool
  and run `packit propose-downstream . $VERSION` in the checkout
  directory.

[abi-dump repository]: https://gitlab.com/gnutls/abi-dump
[NEWS entry]: https://gitlab.com/gnutls/web-pages/-/tree/master/news-entries
[security advisory entry]: https://gitlab.com/gnutls/web-pages/-/tree/master/security-entries
[web-pages repository]: https://gitlab.com/gnutls/web-pages/
[gnutls web site]: https://gnutls.gitlab.io/web-pages/
[git-evtag]: https://github.com/cgwalters/git-evtag
[gnutls translations]: https://translationproject.org/latest/gnutls
[Translation Project]: https://translationproject.org
[Translation Project maintainers page]: https://translationproject.org/html/maintainers.html
[CI/CD jobs]: https://gitlab.com/gnutls/gnutls/-/jobs
[gnutls-help@lists.gnutls.org list]: https://lists.gnutls.org/pipermail/gnutls-help
[info-gnu@gnu.org list]: https://lists.gnu.org/archive/html/info-gnu
