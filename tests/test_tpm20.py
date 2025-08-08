import struct
import unittest
from unittest.mock import MagicMock, patch

from wintermute.cartridges.tpm20 import (
    TPMCommandBuilder,
    TPMCommands,
    TPMException,
    TPMTransport,
    tpm20,
)


class TestTPMCommandBuilder(unittest.TestCase):
    def test_build_command_header_only(self) -> None:
        cmd = TPMCommands.TPMCommands_GetRandom
        cmd_bytes = TPMCommandBuilder.build_command(cmd)

        # Tag (2 bytes), Length (4 bytes), Command Code (4 bytes)
        self.assertEqual(len(cmd_bytes), 10)
        tag, size, cc = struct.unpack(">HII", cmd_bytes)
        self.assertEqual(tag, 0x8001)
        self.assertEqual(size, 10)
        self.assertEqual(cc, cmd.value)

    def test_build_command_with_parameters(self) -> None:
        cmd = TPMCommands.TPMCommands_GetRandom
        params = b"\x00\x10"  # 16 bytes requested
        cmd_bytes = TPMCommandBuilder.build_command(cmd, params)

        tag, size, cc = struct.unpack(">HII", cmd_bytes[:10])
        self.assertEqual(size, 12)
        self.assertEqual(cmd_bytes[10:], params)


class TestTPM(unittest.TestCase):
    def setUp(self) -> None:
        self.mock_transport = MagicMock(spec=TPMTransport)
        self.tpm = tpm20(transport=self.mock_transport)

    def test_execute_calls_transport(self) -> None:
        dummy_response = b"\x80\x01\x00\x00\x00\x0c\x00\x00\x01\x7b\x00\x10"
        self.mock_transport.send_command.return_value = dummy_response

        result = self.tpm.execute(TPMCommands.TPMCommands_GetRandom, b"\x00\x10")
        self.mock_transport.send_command.assert_called_once()
        self.assertEqual(result, dummy_response)

    def test_get_random_valid(self) -> None:
        self.mock_transport.send_command.return_value = b"\x00" * 20
        result = self.tpm.get_random(16)
        self.assertEqual(result, b"\x00" * 20)

    def test_get_random_invalid_low(self) -> None:
        with self.assertRaises(ValueError):
            self.tpm.get_random(0)

    def test_get_random_invalid_high(self) -> None:
        with self.assertRaises(ValueError):
            self.tpm.get_random(100)

    def test_read_public(self) -> None:
        self.mock_transport.send_command.return_value = b"\x00" * 32
        result = self.tpm.read_public(0x81010001)
        self.assertEqual(result, b"\x00" * 32)
        args = self.mock_transport.send_command.call_args[0][0]
        self.assertIn(b"\x81\x01\x00\x01", args)


class TestTPMTransport(unittest.TestCase):
    @patch("builtins.open", create=True)
    def test_send_command_success(self, mock_open: MagicMock) -> None:
        fake_file = MagicMock()
        fake_file.read.return_value = b"\x00" * 16
        fake_file.write.return_value = None
        mock_open.return_value.__enter__.return_value = fake_file

        transport = TPMTransport("/dev/fake")
        result = transport.send_command(b"\x00\x01")
        self.assertEqual(result, b"\x00" * 16)

    @patch("builtins.open", side_effect=IOError("no device"))
    def test_send_command_failure(self, mock_open: MagicMock) -> None:
        transport = TPMTransport("/dev/fake")
        with self.assertRaises(TPMException):
            transport.send_command(b"\x00\x01")


if __name__ == "__main__":
    unittest.main()
