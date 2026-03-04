# -*- coding: utf-8 -*-
# pragma pylint: disable=unused-argument, no-self-use, line-too-long
#
# MIT License
#
# Copyright (c) 2024,2025 Enrique Alfonso Sanchez Montellano (nahualito)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import datetime
import logging
import os
import struct
from enum import Enum, unique
from typing import Any, Optional

log = logging.getLogger(__name__)

event_timestamp = (
    str(datetime.datetime.now(datetime.UTC))
    .split(".")[0]
    .replace(" ", "_")
    .replace(":", "-")
)


class TPM_register(Enum):
    """TPM Registers"""

    TPM_ACCESS = 0x0000
    TPM_STS = 0x0001
    TPM_BURST_CNT = 0x0002
    TPM_DATA_FIFO = 0x0005
    TPM_DID_VID = 0x0006
    TPM_REG_NONE = 0xFFFF


@unique
class TPMCommands(Enum):
    """TPM 2.0 Command Codes"""

    # --- Hierarchy / Admin (original) ---
    TPMCommands_NV_UndefineSpaceSpecial = 0x0000011F
    TPMCommands_EvictControl = 0x00000120
    TPMCommands_HierarchyControl = 0x00000121
    TPMCommands_NV_UndefineSpace = 0x00000122
    TPMCommands_ChangeEPS = 0x00000124
    TPMCommands_ChangePPS = 0x00000125
    TPMCommands_Clear = 0x00000126
    TPMCommands_ClearControl = 0x00000127
    TPMCommands_HierarchyChangeAuth = 0x00000129
    TPMCommands_DictionaryAttackLockReset = 0x0000012A
    TPMCommands_DictionaryAttackParameters = 0x0000012B
    TPMCommands_NV_ChangeAuth = 0x0000012C
    TPMCommands_PCR_Event = 0x0000012D
    TPMCommands_PCR_Reset = 0x0000012E
    TPMCommands_SequenceComplete = 0x0000013E
    TPMCommands_SetAlgorithmSet = 0x00000130
    TPMCommands_SetCommandCodeAuditStatus = 0x00000131
    TPMCommands_FieldUpgradeStart = 0x00000132
    TPMCommands_FieldUpgradeData = 0x00000133
    TPMCommands_FirmwareRead = 0x00000134
    TPMCommands_ContextSave = 0x00000135
    TPMCommands_ContextLoad = 0x00000136

    # --- Object Management (original) ---
    TPMCommands_FlushContext = 0x00000165
    TPMCommands_LoadExternal = 0x00000167
    TPMCommands_ReadPublic = 0x00000173
    TPMCommands_ActivateCredential = 0x00000176
    TPMCommands_MakeCredential = 0x00000177
    TPMCommands_Unseal = 0x0000015E
    TPMCommands_ObjectChangeAuth = 0x0000015B
    TPMCommands_CreateLoaded = 0x0000016A
    TPMCommands_Create = 0x00000153
    TPMCommands_Load = 0x00000157
    TPMCommands_Quote = 0x00000158
    TPMCommands_GetSessionAuditDigest = 0x00000160
    TPMCommands_GetCommandAuditDigest = 0x00000161
    TPMCommands_GetTime = 0x00000162
    TPMCommands_Certify = 0x00000163
    TPMCommands_CertifyCreation = 0x0000016C
    TPMCommands_Duplicate = 0x0000015C
    TPMCommands_Rewrap = 0x0000015D
    TPMCommands_Import = 0x0000016B

    # --- Crypto (original) ---
    TPMCommands_RSA_Encrypt = 0x00000184
    TPMCommands_RSA_Decrypt = 0x00000185
    TPMCommands_ECDH_KeyGen = 0x00000186
    TPMCommands_ECDH_ZGen = 0x00000187
    TPMCommands_ECC_Parameters = 0x00000188
    TPMCommands_ZGen_2Phase = 0x00000189
    TPMCommands_EncryptDecrypt = 0x00000164
    TPMCommands_EncryptDecrypt2 = 0x00000193
    TPMCommands_Hash = 0x0000017B
    TPMCommands_HMAC = 0x0000017C
    TPMCommands_MAC = 0x0000017D
    TPMCommands_GetRandom = 0x0000017E
    TPMCommands_StirRandom = 0x0000017F

    # --- NVRAM Operations (new) ---
    TPMCommands_NV_Read = 0x00000148
    TPMCommands_NV_Write = 0x00000149
    TPMCommands_NV_DefineSpace = 0x0000014A
    TPMCommands_NV_ReadPublic = 0x00000169

    # --- Session Management (new) ---
    TPMCommands_StartAuthSession = 0x00000150
    TPMCommands_PolicyRestart = 0x00000151

    # --- PCR (new) ---
    TPMCommands_PCR_Read = 0x00000180
    TPMCommands_PCR_Extend = 0x00000182

    # --- Capability (new) ---
    TPMCommands_GetCapability = 0x0000017A
    TPMCommands_TestParms = 0x0000018A
    TPMCommands_SelfTest = 0x00000143
    TPMCommands_IncrementalSelfTest = 0x00000142
    TPMCommands_Startup = 0x00000144
    TPMCommands_Shutdown = 0x00000145


class TPMException(Exception):
    pass


class TPMTransport:
    """Base class for communicating with TPM via /dev/tpm0 (or simulator).

    Attributes:
        device_path: Path to the TPM device file.
    """

    def __init__(self, device_path: str = "/dev/tpm0"):
        self.device_path = device_path

    def send_command(self, command_bytes: bytes) -> bytes:
        """Send raw command bytes to the TPM and return the response.

        Args:
            command_bytes: Raw TPM command buffer to write.

        Returns:
            Raw response bytes read from the TPM device.

        Raises:
            TPMException: If communication with the TPM device fails.
        """
        try:
            with open(self.device_path, "r+b", buffering=0) as tpm:
                tpm.write(command_bytes)
                response = tpm.read(4096)
                return response
        except Exception as e:
            raise TPMException(f"TPM Communication failed: {e}")


class TPMCommandBuilder:
    """Builds TPM 2.0 command headers and payloads."""

    TPM_TAG_RQU_COMMAND = 0x8001
    TPM_HEADER_SIZE = 10

    @staticmethod
    def build_command(command_code: TPMCommands, parameters: bytes = b"") -> bytes:
        """Build a complete TPM 2.0 command buffer.

        Args:
            command_code: The TPM command to encode.
            parameters: Optional parameter bytes appended after the header.

        Returns:
            Complete command buffer ready to send to the TPM.
        """
        size = TPMCommandBuilder.TPM_HEADER_SIZE + len(parameters)
        header = struct.pack(
            ">HII", TPMCommandBuilder.TPM_TAG_RQU_COMMAND, size, command_code.value
        )
        return header + parameters


# TPM 2.0 response code helpers
TPM_RC_SUCCESS = 0x00000000


def _parse_response_code(response: bytes) -> int:
    """Extract the 4-byte response code from a TPM 2.0 response buffer."""
    if len(response) < 10:
        raise TPMException(
            f"Response too short ({len(response)} bytes); expected >= 10"
        )
    _tag, _size, rc = struct.unpack(">HII", response[:10])
    return int(rc)


class tpm20:
    """Main interface for executing and auditing TPM 2.0 commands.

    Attributes:
        transport: Transport layer for TPM communication.
    """

    def __init__(self, transport: Optional[TPMTransport] = None):
        self.transport = transport or TPMTransport()
        self.options: dict[str, dict[str, str]] = {
            "device_path": {
                "value": self.transport.device_path,
                "description": "Path to the TPM device file",
            }
        }

    def execute(self, command: TPMCommands, parameters: bytes = b"") -> bytes:
        """Execute a TPM command with given parameters.

        Args:
            command: The TPM 2.0 command to execute.
            parameters: Raw parameter bytes for the command.

        Returns:
            Raw response bytes from the TPM.

        Raises:
            TPMException: If the transport layer fails.
        """
        command_buffer = TPMCommandBuilder.build_command(command, parameters)
        response = self.transport.send_command(command_buffer)
        return response

    def get_random(self, num_bytes: int) -> bytes:
        """Get random bytes from the TPM.

        Args:
            num_bytes: Number of random bytes to retrieve (1-64).

        Returns:
            Raw TPM response containing the random bytes.

        Raises:
            ValueError: If num_bytes is outside the 1-64 range.
            TPMException: If communication fails.
        """
        if not (1 <= num_bytes <= 64):
            raise ValueError("num_bytes must be between 1 and 64")
        param = struct.pack(">H", num_bytes)
        resp = self.execute(TPMCommands.TPMCommands_GetRandom, param)
        return resp

    def read_public(self, handle: int) -> bytes:
        """Read the public area of an object in the TPM.

        Args:
            handle: The TPM object handle to read.

        Returns:
            Raw TPM response containing the public area.

        Raises:
            TPMException: If communication fails.
        """
        param = struct.pack(">I", handle)
        return self.execute(TPMCommands.TPMCommands_ReadPublic, param)

    # -------------------------------------------------
    # NVRAM operations
    # -------------------------------------------------

    def nv_read(self, nv_index: int, size: int, offset: int = 0) -> bytes:
        """Read data from an NVRAM index.

        Args:
            nv_index: The NV index handle (e.g. 0x01500000).
            size: Number of bytes to read.
            offset: Byte offset within the NV index to start reading.

        Returns:
            Raw TPM response containing the NV data.

        Raises:
            TPMException: If communication fails or access is denied.
        """
        param = struct.pack(">IHH", nv_index, size, offset)
        return self.execute(TPMCommands.TPMCommands_NV_Read, param)

    def nv_write(self, nv_index: int, data: bytes, offset: int = 0) -> bytes:
        """Write data to an NVRAM index.

        Args:
            nv_index: The NV index handle.
            data: Bytes to write into the NV area.
            offset: Byte offset within the NV index.

        Returns:
            Raw TPM response.

        Raises:
            TPMException: If communication fails or access is denied.
        """
        param = struct.pack(">IH", nv_index, offset) + data
        return self.execute(TPMCommands.TPMCommands_NV_Write, param)

    # -------------------------------------------------
    # Session management
    # -------------------------------------------------

    def start_auth_session(
        self,
        session_type: int = 0x01,
        auth_hash: int = 0x000B,
    ) -> bytes:
        """Start an authorization session on the TPM.

        Args:
            session_type: Session type byte (0x00=HMAC, 0x01=policy, 0x03=trial).
            auth_hash: Algorithm ID for the session hash (default SHA-256 = 0x000B).

        Returns:
            Raw TPM response containing the session handle.

        Raises:
            TPMException: If communication fails.
        """
        param = struct.pack(">BH", session_type, auth_hash)
        return self.execute(TPMCommands.TPMCommands_StartAuthSession, param)

    # -------------------------------------------------
    # Security auditing functions
    # -------------------------------------------------

    def test_pcr_state(self, pcr_index: int) -> dict[str, Any]:
        """Check a PCR bank for brittle or predictable states.

        Reads the specified PCR and analyses the digest for patterns that
        indicate a weak or uninitialised measurement chain (all-zeros,
        all-ones, or repeating-byte values).

        Args:
            pcr_index: The PCR register index to inspect (0-23).

        Returns:
            A dict with keys:
                - ``pcr_index``: The inspected PCR index.
                - ``raw_response_hex``: Hex-encoded raw TPM response.
                - ``findings``: List of human-readable finding strings.
                - ``passed``: ``True`` if no weaknesses were detected.

        Raises:
            ValueError: If pcr_index is outside the 0-23 range.
            TPMException: If communication with the TPM fails.
        """
        if not (0 <= pcr_index <= 23):
            raise ValueError("pcr_index must be between 0 and 23")

        param = struct.pack(">I", pcr_index)
        resp = self.execute(TPMCommands.TPMCommands_PCR_Read, param)

        findings: list[str] = []
        # Skip the 10-byte header to get the digest portion
        digest = resp[10:] if len(resp) > 10 else resp

        if digest == b"\x00" * len(digest):
            findings.append(f"PCR {pcr_index} is all-zeros — no measurements extended")
        elif digest == b"\xff" * len(digest):
            findings.append(
                f"PCR {pcr_index} is all-ones — may indicate a capped/locked PCR"
            )
        elif len(set(digest)) == 1:
            findings.append(
                f"PCR {pcr_index} contains a single repeating byte 0x{digest[0]:02x}"
            )

        return {
            "pcr_index": pcr_index,
            "raw_response_hex": resp.hex(),
            "findings": findings,
            "passed": len(findings) == 0,
        }

    def test_da_lockout(self, max_attempts: int = 5) -> dict[str, Any]:
        """Verify dictionary-attack lockout protection by sending deliberate bad auths.

        Sends up to ``max_attempts`` DictionaryAttackLockReset commands with
        empty (unauthenticated) parameters. A properly configured TPM should
        reject these and eventually enter DA lockout mode. If no rejection is
        observed, the DA policy may be misconfigured.

        Args:
            max_attempts: Number of intentionally bad auth attempts to send.

        Returns:
            A dict with keys:
                - ``attempts``: Number of attempts actually sent.
                - ``rejected_count``: How many returned a non-success RC.
                - ``lockout_triggered``: ``True`` if a lockout RC was observed.
                - ``findings``: List of human-readable finding strings.
                - ``passed``: ``True`` if lockout protections behaved correctly.

        Raises:
            ValueError: If max_attempts is less than 1.
            TPMException: If a transport-level error occurs (not an auth failure).
        """
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")

        rejected = 0
        lockout_triggered = False
        findings: list[str] = []

        # TPM_RC_LOCKOUT is 0x00000921 in the TPM 2.0 spec
        TPM_RC_LOCKOUT = 0x00000921
        TPM_RC_AUTH_FAIL = 0x0000098E

        for i in range(max_attempts):
            try:
                resp = self.execute(
                    TPMCommands.TPMCommands_DictionaryAttackLockReset, b""
                )
                rc = _parse_response_code(resp)
                if rc != TPM_RC_SUCCESS:
                    rejected += 1
                if rc == TPM_RC_LOCKOUT:
                    lockout_triggered = True
                    log.info("DA lockout triggered after %d attempts", i + 1)
                    break
                if rc == TPM_RC_AUTH_FAIL:
                    log.debug("Auth failure on attempt %d (expected)", i + 1)
            except TPMException:
                rejected += 1

        if rejected == 0:
            findings.append(
                "All DA reset attempts succeeded without auth — "
                "dictionary-attack protection may be disabled or misconfigured"
            )
        if not lockout_triggered and max_attempts > 1:
            findings.append(
                f"Lockout was NOT triggered after {max_attempts} bad attempts"
            )

        return {
            "attempts": max_attempts,
            "rejected_count": rejected,
            "lockout_triggered": lockout_triggered,
            "findings": findings,
            "passed": rejected > 0 and lockout_triggered,
        }

    # -------------------------------------------------
    # Fuzzing engine
    # -------------------------------------------------

    def fuzz_command(
        self,
        command: TPMCommands,
        iterations: int = 100,
        max_payload_size: int = 1024,
    ) -> dict[str, Any]:
        """Fuzz a TPM 2.0 command with randomised payloads.

        Builds valid TPM 2.0 headers for ``command`` but appends malformed,
        random-length byte payloads generated via :func:`os.urandom`. Each
        iteration catches :class:`TPMException`, :class:`TimeoutError`, and
        :class:`OSError` to detect kernel driver crashes or TPM interface
        locks on ``/dev/tpm0``.

        Args:
            command: The TPM command code to target.
            iterations: Number of fuzz iterations to run.
            max_payload_size: Maximum random payload length in bytes.

        Returns:
            A dict with keys:
                - ``command``: Name of the fuzzed command.
                - ``iterations``: Total iterations executed.
                - ``successes``: Count of responses with ``TPM_RC_SUCCESS``.
                - ``errors``: List of dicts with ``iteration``, ``error_type``,
                  and ``message`` for each caught exception.
                - ``crashes``: List of dicts for ``OSError`` events that may
                  indicate a kernel driver crash.
                - ``timeouts``: Number of ``TimeoutError`` events.

        Raises:
            ValueError: If iterations < 1 or max_payload_size < 1.
        """
        if iterations < 1:
            raise ValueError("iterations must be >= 1")
        if max_payload_size < 1:
            raise ValueError("max_payload_size must be >= 1")

        successes = 0
        errors: list[dict[str, Any]] = []
        crashes: list[dict[str, Any]] = []
        timeouts = 0

        for i in range(iterations):
            payload_size = int.from_bytes(os.urandom(2), "big") % max_payload_size
            payload = os.urandom(payload_size)
            try:
                resp = self.execute(command, payload)
                rc = _parse_response_code(resp)
                if rc == TPM_RC_SUCCESS:
                    successes += 1
            except TPMException as exc:
                errors.append(
                    {"iteration": i, "error_type": "TPMException", "message": str(exc)}
                )
            except TimeoutError as exc:
                timeouts += 1
                errors.append(
                    {"iteration": i, "error_type": "TimeoutError", "message": str(exc)}
                )
            except OSError as exc:
                crash_entry = {
                    "iteration": i,
                    "error_type": "OSError",
                    "message": str(exc),
                }
                crashes.append(crash_entry)
                errors.append(crash_entry)
                log.warning("Potential driver crash at iteration %d: %s", i, exc)

        return {
            "command": command.name,
            "iterations": iterations,
            "successes": successes,
            "errors": errors,
            "crashes": crashes,
            "timeouts": timeouts,
        }

    # -------------------------------------------------
    # Console command handler
    # -------------------------------------------------

    def do_tpm20(self, *args: str) -> None:
        """Execute TPM commands. Use -p to read public key, -r to get random bytes."""
        parser = argparse.ArgumentParser(prog="tpm20", add_help=False)
        parser.add_argument(
            "-p",
            "--public",
            action="store_true",
            help="Retrieve public key from the TPM",
        )
        parser.add_argument(
            "-r", "--random", action="store_true", help="Get random bytes from the TPM"
        )
        parser.add_argument("-h", "--help", action="store_true", help="Show help")

        try:
            parsed_args = parser.parse_args(args)
            if parsed_args.help:
                parser.print_help()
                return

            if parsed_args.public:
                handle = 0x81000000  # Example handle
                public_key = self.read_public(handle)
                print(f"Public key (hex): {public_key.hex()}")

            if parsed_args.random:
                random_bytes = self.get_random(16)
                print(f"Random bytes (hex): {random_bytes.hex()}")

            if not any([parsed_args.public, parsed_args.random]):
                parser.print_help()

        except SystemExit:
            pass
        except Exception as e:
            print(f"Error: {e}")
