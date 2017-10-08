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

import io
import pwsafe_adapter
import struct
import unittest


class FakeStdin(io.StringIO):
    """This makes an attempt at mocking sys.stdin. Trying to use
    io.TextIOWrapper with io.BytesIO as a buffer gives something that
    behaves differently from sys.stdin. Reading the buffer directly
    through text_wrapper.buffer.read() is fine, but reading the
    TextIOWrapper with read() clears the underlying BytesIO
    buffer. Presumably because it reads the whole thing into the
    wrapper which sys.stdin doesn't do.
    """
    @property
    def buffer(self):
        """ buffer on sys.stdin provides access to bytes."""
        class BytesIOWrapper():
            def __init__(self, string_io):
                self.string_io = string_io

            def read(self, length):
                return self.string_io.read(length).encode("utf-8")

        return BytesIOWrapper(self)


class TestWebExtensionReader(unittest.TestCase):
    def setUp(self):
        self.reader = pwsafe_adapter.WebExtensionDecoder(open("/dev/null", "r", encoding="utf-8"))

    def tearDown(self):
        self.reader.input.close()

    # _read_msg_size
    def test_read_msg_size_str(self):
        with self.assertRaises(pwsafe_adapter.WebExtensionDecodingError):
            self.reader._read_msg_size("\x00\x00")

    def test_read_msg_size_empty(self):
        with self.assertRaises(pwsafe_adapter.WebExtensionDecodingError):
            self.reader._read_msg_size(b"")

    def test_read_msg_size_too_small(self):
        with self.assertRaises(pwsafe_adapter.WebExtensionDecodingError):
            self.reader._read_msg_size(b"\x00\x00")

    def test_read_msg_size_too_big(self):
        with self.assertRaises(pwsafe_adapter.WebExtensionDecodingError):
            self.reader._read_msg_size(b"\x00\x00\x00\x00\x00\x00")

    def test_read_msg_size_0(self):
        msg = struct.pack("@I", 0)
        self.assertEqual(self.reader._read_msg_size(msg), 0)

    def test_read_msg_size_1(self):
        msg = struct.pack("@I", 13)
        self.assertEqual(self.reader._read_msg_size(msg), 13)

    def test_read_msg_size_2(self):
        max_32_bit_unsigned_integer = 2 ** 32 - 1
        msg = struct.pack("@I", max_32_bit_unsigned_integer)
        self.assertEqual(self.reader._read_msg_size(msg), max_32_bit_unsigned_integer)

    # read full msg
    def test_read_full_msg(self):
        input_stream = FakeStdin('\x0d\x00\x00\x00"mozilla.org"\x05\x00\x00\x00"abc"')
        self.reader.set_fd(input_stream)
        self.assertEqual(self.reader.read(), "mozilla.org")
        self.assertEqual(self.reader.read(), "abc")


if __name__ == "__main__":
    unittest.main()
