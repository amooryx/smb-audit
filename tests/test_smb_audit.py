import unittest
from unittest.mock import patch

import smb_audit


def smb1_negotiate_response(dialect_index=0, status=0):
    header = bytearray(32)
    header[:4] = b"\xffSMB"
    header[4] = 0x72
    header[5:9] = status.to_bytes(4, "little")
    header[9] = 0x80
    if status:
        body = b"\x00\x00\x00"
    else:
        body = bytes([1]) + dialect_index.to_bytes(2, "little") + b"\x00\x00"
    return bytes(header) + body


def netbios_frame(payload):
    length = len(payload)
    return bytes([0, (length >> 16) & 1, (length >> 8) & 0xFF, length & 0xFF]) + payload


class FragmentedSocket:
    def __init__(self, data, fragment_size=2):
        self.data = bytearray(data)
        self.fragment_size = fragment_size
        self.sent = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def sendall(self, data):
        self.sent = data

    def recv(self, size):
        size = min(size, self.fragment_size, len(self.data))
        chunk = bytes(self.data[:size])
        del self.data[:size]
        return chunk


class ParseSmbv1NegotiateTests(unittest.TestCase):
    def test_accepts_offered_dialect(self):
        self.assertIs(True, smb_audit._parse_smbv1_negotiate(
            smb1_negotiate_response(dialect_index=4)))

    def test_rejects_server_response_without_dialect(self):
        self.assertIs(False, smb_audit._parse_smbv1_negotiate(
            smb1_negotiate_response(dialect_index=0xFFFF)))

    def test_rejects_smb_error_response(self):
        self.assertIs(False, smb_audit._parse_smbv1_negotiate(
            smb1_negotiate_response(status=0xC00000BB)))

    def test_malformed_or_unexpected_response_is_inconclusive(self):
        response = smb1_negotiate_response()
        self.assertIsNone(smb_audit._parse_smbv1_negotiate(response[:34]))
        self.assertIsNone(smb_audit._parse_smbv1_negotiate(
            smb1_negotiate_response(status=0xC00000BB)[:33]))
        self.assertIsNone(smb_audit._parse_smbv1_negotiate(b"\x00" * len(response)))
        self.assertIsNone(smb_audit._parse_smbv1_negotiate(
            smb1_negotiate_response(dialect_index=5)))


class CheckSmbv1RawTests(unittest.TestCase):
    @patch.object(smb_audit.socket, "create_connection")
    def test_reads_fragmented_framed_response(self, create_connection):
        sock = FragmentedSocket(netbios_frame(smb1_negotiate_response()))
        create_connection.return_value = sock

        result = smb_audit.check_smbv1_raw("127.0.0.1")

        self.assertIs(True, result)
        self.assertIsNotNone(sock.sent)
        create_connection.assert_called_once_with(("127.0.0.1", 445), timeout=8)

    @patch.object(smb_audit.socket, "create_connection")
    def test_oversized_response_is_inconclusive(self, create_connection):
        sock = FragmentedSocket(b"\x00\x00\x10\x01")
        create_connection.return_value = sock

        self.assertIsNone(smb_audit.check_smbv1_raw("127.0.0.1"))
        self.assertEqual(0, len(sock.data))

    @patch.object(smb_audit.socket, "create_connection")
    def test_connection_error_is_inconclusive(self, create_connection):
        create_connection.side_effect = OSError("offline test")

        self.assertIsNone(smb_audit.check_smbv1_raw("127.0.0.1"))


if __name__ == "__main__":
    unittest.main()
