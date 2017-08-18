#!/bin/bash

# This wrapper is a work around for the following issue in gitlab CI:
#   https://gitlab.com/gitlab-com/support-forum/issues/1311

dir=$1

test -z ${dir} && exit 1

pushd ${dir}

fedpkg local
rc=$?

popd

if test $rc = 0;then
	exit 0
fi

exit 1
