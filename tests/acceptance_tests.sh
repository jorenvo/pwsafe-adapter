#!/usr/bin/env bash
# Copyright (C) 2017 Joren Van Onder

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA

set -euo pipefail

EXECUTABLE='./pwsafe_adapter.py -f tests/test.db'
FAILED_TESTS="0"
TEST_OUTPUT_FILE=$(mktemp)

function cleanup {
    rm "${TEST_OUTPUT_FILE}"
}

function assert_equal {
    local TEST_INPUT="${1}"
    local EXPECTED_OUTPUT="${2}"

    # null bytes in subshells get eaten:
    # odoo@jov:~$ a=$(echo -en '\x00\x00')
    # odoo@jov:~$ echo -n $a | hexdump -C
    # odoo@jov:~$
    # so use a tempfile file
    echo -ne "${TEST_INPUT}" | ${EXECUTABLE} > "${TEST_OUTPUT_FILE}"

    diff <(hexdump -C "${TEST_OUTPUT_FILE}") <(echo -ne "${EXPECTED_OUTPUT}" | hexdump -C)
    FAILED_TESTS="${FAILED_TESTS}" || "${?}"
}

function run_tests {
    # note that the order of keys in the JSON object will always be the
    # same because of sort_keys=True when dumping JSON
    assert_equal '\x2d\x00\x00\x00{"password": "pwd", "website": "mozilla.org"}' '\x40\x00\x00\x00{"password": "mozilla_password", "username": "mozilla_username"}'
    assert_equal '\x2f\x00\x00\x00{"password": "wrong", "website": "mozilla.org"}' '\x10\x00\x00\x00"wrong_password"'
    assert_equal '\x32\x00\x00\x00{"password": "pwd", "website": "doesnt_exist.org"}' '\x0b\x00\x00\x00"not_found"'
}

run_tests
cleanup

exit "${FAILED_TESTS}"
