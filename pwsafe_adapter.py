#!/usr/bin/env python3
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

import json
import select
import struct
import subprocess
import sys


class WebExtensionDecodingError(Exception):
    pass


class WebExtensionDecoder:
    """Deserializes WebExtension encoded messages to Python objects."""
    def __init__(self, input_fd):
        self.MSG_SIZE_LENGTH_B = 4
        self.input = input_fd

    def set_fd(self, fd):
        if self.get_fd():
            self.get_fd().close()
        self.input = fd

    def get_fd(self):
        return self.input

    def read(self):
        msg_size = self._read_msg_size(self.get_fd().buffer.read(self.MSG_SIZE_LENGTH_B))
        read = self.get_fd().read(msg_size)

        if len(read) != msg_size:
            raise WebExtensionDecodingError("Only {} bytes could be read but {} bytes were specified.".format(len(read), msg_size))

        return json.loads(read)

    def _read_msg_size(self, msg):
        """Converts the length in a WebExtension message to an integer. msg
        has to be a bytes because it represents an unsigned integer, not
        text."""
        if not isinstance(msg, bytes):
            raise WebExtensionDecodingError("msg must be bytes.")

        if len(msg) != self.MSG_SIZE_LENGTH_B:
            raise WebExtensionDecodingError("The length of a message has to be specified with {} bytes not {} bytes.".format(self.MSG_SIZE_LENGTH_B, len(msg)))

        # The msg size is specified with 4 bytes which represent the
        # length in bytes of the message that will follow. The 4 bytes are
        # encoded as a 4 byte unsigned integer in native byte order.
        return struct.unpack("@I", msg)[0]


class Adapter:
    def __init__(self, pwsafe_args=None):
        self.pwsafe_args = pwsafe_args
        self.web_extension_decoder = WebExtensionDecoder(sys.stdin)

    def encode(self, obj):
        # sort_keys for acceptance testing
        msg = json.dumps(obj, sort_keys=True)

        msg_length = struct.pack("@I", len(msg))
        return msg_length + msg.encode("utf-8")

    def output(self, msg):
        sys.stdout.buffer.write(self.encode(msg))

    def native_pwsafe(self, password, website, additional_pwsafe_args):
        if additional_pwsafe_args is None:
            additional_pwsafe_args = []

        self.pwsafe_process = subprocess.Popen(["pwsafe", "-Equp", website] + additional_pwsafe_args,  # todo jov website
                                               stdout=subprocess.PIPE,
                                               stderr=subprocess.DEVNULL,
                                               stdin=subprocess.PIPE)

        return self.pwsafe_process.communicate(input=(password + '\n').encode('utf-8'))[0]

    def run(self):
        # wait until input is available
        select.select([self.web_extension_decoder.get_fd()], [], [])
        web_extension_msg = self.web_extension_decoder.read()

        pwsafe_stdout = self.native_pwsafe(web_extension_msg["password"],
                                           web_extension_msg["website"],
                                           additional_pwsafe_args=self.pwsafe_args)

        if b"No matching entries" in pwsafe_stdout:
            self.output("not_found")
        elif b"Passphrase is incorrect" in pwsafe_stdout:
            self.output("wrong_password")
        else:
            lines = pwsafe_stdout.decode("utf-8").splitlines()

            # line 0 is "Enter passphrase for"
            username = lines[1]
            password = lines[2]

            self.output({"username": username, "password": password})


if __name__ == "__main__":
    additional_arguments = sys.argv[1:]

    # Firefox calls native applications with two arguments e.g.:
    # ['/home/odoo/.mozilla/native-messaging-hosts/pwsafe.json', 'pwsafe-ff@jorenvo.org']
    if not additional_arguments or 'pwsafe.json' in additional_arguments[0]:
        additional_arguments = None

    Adapter(additional_arguments).run()
