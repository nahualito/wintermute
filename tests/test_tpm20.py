import struct
import unittest
from unittest.mock import MagicMock, patch

from wintermute.cartridges.tpm20 import (
    TPM_RC_SUCCESS,
    TPMCommandBuilder,
    TPMCommands,
    TPMException,
    TPMTransport,
    _parse_response_code,
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
        self.mock_transport.device_path = "/dev/tpm0"
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


class TestParseResponseCode(unittest.TestCase):
    def test_success_code(self) -> None:
        resp = struct.pack(">HII", 0x8001, 10, TPM_RC_SUCCESS)
        self.assertEqual(_parse_response_code(resp), TPM_RC_SUCCESS)

    def test_error_code(self) -> None:
        resp = struct.pack(">HII", 0x8001, 10, 0x00000921)
        self.assertEqual(_parse_response_code(resp), 0x00000921)

    def test_short_response_raises(self) -> None:
        with self.assertRaises(TPMException):
            _parse_response_code(b"\x00" * 5)


def _make_success_response(payload: bytes = b"") -> bytes:
    """Build a minimal TPM 2.0 success response with optional payload."""
    size = 10 + len(payload)
    return struct.pack(">HII", 0x8001, size, TPM_RC_SUCCESS) + payload


def _make_error_response(rc: int) -> bytes:
    """Build a minimal TPM 2.0 error response."""
    return struct.pack(">HII", 0x8001, 10, rc)


class TestNVOperations(unittest.TestCase):
    def setUp(self) -> None:
        self.mock_transport = MagicMock(spec=TPMTransport)
        self.mock_transport.device_path = "/dev/tpm0"
        self.tpm = tpm20(transport=self.mock_transport)

    def test_nv_read(self) -> None:
        self.mock_transport.send_command.return_value = _make_success_response(
            b"\xaa" * 8
        )
        result = self.tpm.nv_read(0x01500000, 8, offset=0)
        self.mock_transport.send_command.assert_called_once()
        self.assertEqual(len(result), 18)  # 10 header + 8 payload

    def test_nv_write(self) -> None:
        self.mock_transport.send_command.return_value = _make_success_response()
        result = self.tpm.nv_write(0x01500000, b"\xbb" * 4, offset=0)
        self.mock_transport.send_command.assert_called_once()
        self.assertEqual(_parse_response_code(result), TPM_RC_SUCCESS)


class TestStartAuthSession(unittest.TestCase):
    def setUp(self) -> None:
        self.mock_transport = MagicMock(spec=TPMTransport)
        self.mock_transport.device_path = "/dev/tpm0"
        self.tpm = tpm20(transport=self.mock_transport)

    def test_start_auth_session(self) -> None:
        self.mock_transport.send_command.return_value = _make_success_response(
            b"\x00" * 4
        )
        result = self.tpm.start_auth_session()
        self.mock_transport.send_command.assert_called_once()
        self.assertEqual(_parse_response_code(result), TPM_RC_SUCCESS)


class TestPCRStateAudit(unittest.TestCase):
    def setUp(self) -> None:
        self.mock_transport = MagicMock(spec=TPMTransport)
        self.mock_transport.device_path = "/dev/tpm0"
        self.tpm = tpm20(transport=self.mock_transport)

    def test_pcr_all_zeros_detected(self) -> None:
        self.mock_transport.send_command.return_value = _make_success_response(
            b"\x00" * 32
        )
        result = self.tpm.test_pcr_state(0)
        self.assertFalse(result["passed"])
        self.assertEqual(result["pcr_index"], 0)
        self.assertTrue(any("all-zeros" in f for f in result["findings"]))

    def test_pcr_all_ones_detected(self) -> None:
        self.mock_transport.send_command.return_value = _make_success_response(
            b"\xff" * 32
        )
        result = self.tpm.test_pcr_state(7)
        self.assertFalse(result["passed"])
        self.assertTrue(any("all-ones" in f for f in result["findings"]))

    def test_pcr_healthy_passes(self) -> None:
        digest = bytes(range(32))  # non-repeating
        self.mock_transport.send_command.return_value = _make_success_response(digest)
        result = self.tpm.test_pcr_state(10)
        self.assertTrue(result["passed"])
        self.assertEqual(result["findings"], [])

    def test_pcr_index_out_of_range(self) -> None:
        with self.assertRaises(ValueError):
            self.tpm.test_pcr_state(24)
        with self.assertRaises(ValueError):
            self.tpm.test_pcr_state(-1)


class TestDALockoutAudit(unittest.TestCase):
    def setUp(self) -> None:
        self.mock_transport = MagicMock(spec=TPMTransport)
        self.mock_transport.device_path = "/dev/tpm0"
        self.tpm = tpm20(transport=self.mock_transport)

    def test_da_lockout_triggered(self) -> None:
        TPM_RC_LOCKOUT = 0x00000921
        responses = [
            _make_error_response(0x0000098E),  # auth fail
            _make_error_response(TPM_RC_LOCKOUT),  # lockout
        ]
        self.mock_transport.send_command.side_effect = responses
        result = self.tpm.test_da_lockout(max_attempts=5)
        self.assertTrue(result["lockout_triggered"])
        self.assertTrue(result["passed"])
        self.assertGreater(result["rejected_count"], 0)

    def test_da_no_rejection_is_finding(self) -> None:
        self.mock_transport.send_command.return_value = _make_success_response()
        result = self.tpm.test_da_lockout(max_attempts=3)
        self.assertFalse(result["passed"])
        self.assertTrue(
            any("dictionary-attack protection" in f for f in result["findings"])
        )

    def test_da_invalid_attempts(self) -> None:
        with self.assertRaises(ValueError):
            self.tpm.test_da_lockout(max_attempts=0)


class TestFuzzCommand(unittest.TestCase):
    def setUp(self) -> None:
        self.mock_transport = MagicMock(spec=TPMTransport)
        self.mock_transport.device_path = "/dev/tpm0"
        self.tpm = tpm20(transport=self.mock_transport)

    def test_fuzz_basic_success(self) -> None:
        self.mock_transport.send_command.return_value = _make_success_response()
        result = self.tpm.fuzz_command(
            TPMCommands.TPMCommands_GetRandom, iterations=10, max_payload_size=64
        )
        self.assertEqual(result["command"], "TPMCommands_GetRandom")
        self.assertEqual(result["iterations"], 10)
        self.assertEqual(result["successes"], 10)
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["crashes"], [])

    def test_fuzz_catches_tpm_exception(self) -> None:
        self.mock_transport.send_command.side_effect = TPMException("device hung")
        result = self.tpm.fuzz_command(
            TPMCommands.TPMCommands_GetRandom, iterations=3, max_payload_size=32
        )
        self.assertEqual(len(result["errors"]), 3)
        self.assertTrue(
            all(e["error_type"] == "TPMException" for e in result["errors"])
        )

    def test_fuzz_catches_os_error(self) -> None:
        self.mock_transport.send_command.side_effect = OSError("driver crash")
        result = self.tpm.fuzz_command(
            TPMCommands.TPMCommands_GetRandom, iterations=2, max_payload_size=32
        )
        self.assertEqual(len(result["crashes"]), 2)

    def test_fuzz_catches_timeout(self) -> None:
        self.mock_transport.send_command.side_effect = TimeoutError("timed out")
        result = self.tpm.fuzz_command(
            TPMCommands.TPMCommands_GetRandom, iterations=2, max_payload_size=32
        )
        self.assertEqual(result["timeouts"], 2)

    def test_fuzz_invalid_params(self) -> None:
        with self.assertRaises(ValueError):
            self.tpm.fuzz_command(TPMCommands.TPMCommands_GetRandom, iterations=0)
        with self.assertRaises(ValueError):
            self.tpm.fuzz_command(TPMCommands.TPMCommands_GetRandom, max_payload_size=0)


if __name__ == "__main__":
    unittest.main()
