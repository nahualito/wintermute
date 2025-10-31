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

import datetime
import struct
from enum import Enum, unique

from cmd2 import (
    Cmd2ArgumentParser,
    CommandSet,
    with_argparser,
    with_default_category,
)

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


class TPMException(Exception):
    pass


class TPMTransport:
    """Base class for communicating with TPM via /dev/tpm0 (or simulator)

    Attributes:
        device_path (str): Path to the TPM device file.
    """

    def __init__(self, device_path: str = "/dev/tpm0"):
        self.device_path = device_path

    def send_command(self, command_bytes: bytes) -> bytes:
        """
        Sends raw command bytes to the TPM and returns the response
        """
        try:
            with open(self.device_path, "r+b", buffering=0) as tpm:
                tpm.write(command_bytes)
                response = tpm.read(4096)
                return response
        except Exception as e:
            raise TPMException(f"TPM Communication failed: {e}")


class TPMCommandBuilder:
    """Builds TPM command headers and payloads

    Attributes:
        None
    """

    TPM_TAG_RQU_COMMAND = 0x8001
    TPM_HEADER_SIZE = 10

    @staticmethod
    def build_command(command_code: TPMCommands, parameters: bytes = b"") -> bytes:
        # Calculate size
        size = TPMCommandBuilder.TPM_HEADER_SIZE + len(parameters)
        header = struct.pack(
            ">HII", TPMCommandBuilder.TPM_TAG_RQU_COMMAND, size, command_code.value
        )
        return header + parameters


@with_default_category("tpm20")
class tpm20(CommandSet):
    """Main interface for executing TPM commands

    Attributes:
        transport (TPMTransport): Transport layer for TPM communication.
    """

    def __init__(self, transport: TPMTransport = TPMTransport()):
        self.transport = transport
        super().__init__()

    def execute(self, command: TPMCommands, parameters: bytes = b"") -> bytes:
        """Execute a TPM command with given parameters.

        Arguments:
            command (TPMCommands): The TPM command to execute.
            parameters (bytes): The parameters for the command.
        """
        command_buffer = TPMCommandBuilder.build_command(command, parameters)
        response = self.transport.send_command(command_buffer)
        return response

    def get_random(self, num_bytes: int) -> bytes:
        """Get random bytes from the TPM.

        Arguments:
            num_bytes (int): Number of random bytes to retrieve.
        """
        if not (1 <= num_bytes <= 64):
            raise ValueError("num_bytes must be between 1 and 64")
        param = struct.pack(">H", num_bytes)
        resp = self.execute(TPMCommands.TPMCommands_GetRandom, param)
        return resp

    def create_primary(self, hierarchy: int = 0x40000001) -> bytes:
        # Placeholder structure — full creation needs TPMT_PUBLIC etc.
        raise NotImplementedError("Implement CreatePrimary with TPM structures.")

    def read_public(self, handle: int) -> bytes:
        """Read the public area of an object in the TPM.

        Arguments:
            handle (int): The handle of the object to read.
        """
        param = struct.pack(">I", handle)
        return self.execute(TPMCommands.TPMCommands_ReadPublic, param)

    """REPL commands added here for console use"""
    tpm20_parser = Cmd2ArgumentParser()
    tpm20_parser.add_argument(
        "-p", "--public", action="store_true", help="Retrieve publi key from the TPM"
    )
    tpm20_parser.add_argument(
        "-r", "--random", action="store_true", help="Get random bytes from the TPM"
    )

    @with_argparser(tpm20_parser)
    def do_tpm20(self, args) -> None:  # type: ignore
        """Execute TPM commands.
        Use -p to read public key, -r to get random bytes.
        """
        if args.public:
            handle = 0x81000000  # Example handle, replace with actual
            public_key = self.read_public(handle)
            print(public_key.hex())
