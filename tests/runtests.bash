#!/usr/bin/env bash

set -e

TGPG="./tgpgtest"
GPG2="gpg2 --homedir gpghome --quiet --decrypt"

tests=0
failed=0

function ok()
{
    let tests=$tests+1
}

function fail()
{
    let tests=$tests+1
    let failed=$failed+1
}

while [ "$1" ]
do
    chksum="$(sha1sum < $1)"
    test "$chksum" = "$(${TGPG} $1.gpg | sha1sum)" && ok || fail
    test "$chksum" = "$(${TGPG} --mandatory-mdc $1.gpg | sha1sum)" && fail || ok
    test "$chksum" = "$(${TGPG} --mandatory-mdc $1.gpg.mdc | sha1sum)" && ok || fail
    test "$chksum" = "$(${TGPG} $1.tgpg | sha1sum)" && ok || fail
    test "$chksum" = "$(${TGPG} --mandatory-mdc $1.tgpg.mdc | sha1sum)" && ok || fail
    test "$chksum" = "$(${GPG2} $1.tgpg | sha1sum)" && ok || fail
    test "$chksum" = "$(${GPG2} $1.tgpg.mdc | sha1sum)" && ok || fail
    shift
done

echo "$tests executed, $failed failed."

exit $failed
