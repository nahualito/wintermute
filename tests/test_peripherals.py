import unittest

from wintermute.peripherals import (
    TPM,
    UART,
    Peripheral,
    PeripheralType,
)


class TestPeripheral(unittest.TestCase):
    def test_init_default(self) -> None:
        p = Peripheral()
        self.assertEqual(p.name, "")
        self.assertEqual(p.pins, {})
        self.assertEqual(p.pType, PeripheralType.Unknown)

    def test_toJSON(self) -> None:
        p = Peripheral(name="eth0", pins={"tx": 1}, pType=PeripheralType.Ethernet)
        json_str = p.toJSON()
        self.assertIn('"name": "eth0"', json_str)
        self.assertIn('"pType": 2', json_str)  # Ethernet is 0x02
        self.assertIn('"pins": {', json_str)


class TestUART(unittest.TestCase):
    def test_uart_defaults(self) -> None:
        u = UART()
        self.assertEqual(u.baudrate, 9600)
        self.assertEqual(u.bytesize, 8)
        self.assertEqual(u.parity, "N")
        self.assertEqual(u.stopbits, 1)
        self.assertEqual(u.com_port, "")

    def test_uart_pin_mapping(self) -> None:
        pins = {"tx": "PA1", "rx": "PA2", "gnd": "GND"}
        u = UART(name="debug_uart", pins=pins)
        self.assertEqual(u.tx, "PA1")
        self.assertEqual(u.rx, "PA2")
        self.assertEqual(u.gnd, "GND")


class TestTPM(unittest.TestCase):
    def test_tpm_pin_assignment(self) -> None:
        pins = {
            "mosi": "PA1",
            "miso": "PA2",
            "sclk": "PA3",
            "gnd": "GND",
            "cs": "PB1",
            "rst": "PB2",
            "pirq": "PB3",
            "vcc": "3V3",
        }
        t = TPM(name="tpm0", pins=pins)
        self.assertEqual(t.mosi, "PA1")
        self.assertEqual(t.cs, "PB1")
        self.assertEqual(t.vcc, "3V3")

    def test_tpm_input_header(self) -> None:
        t = TPM()
        result = t._tpm_input_header(0x00C1, 0x0000001A, 0x00000065)
        self.assertEqual(result, b"\x00\xc1\x00\x00\x00\x1a\x00\x00\x00e")

    def test_tpm_pcr_read_req_body(self) -> None:
        t = TPM()
        self.assertEqual(t._tpm_pcr_read_req_body(5), b"\x00\x00\x00\x05")

    def test_tpm_pcr_read_resp_body(self) -> None:
        t = TPM()
        digest = bytes(range(20))
        result = t._tpm_pcr_read_resp_body(digest)
        self.assertEqual(len(result), 20)
        self.assertEqual(result, digest)

    def test_tpm_get_rnd_resp_body(self) -> None:
        t = TPM()
        data = bytes(range(128))
        packed = t._tpm_get_rnd_resp_body(128, data)
        self.assertEqual(packed[:4], b"\x00\x00\x00\x80")
        self.assertEqual(packed[4:], data)

    def test_tpm_op_auth_req_body(self) -> None:
        t = TPM()
        auth = b"AUTH_1234567890123"
        padded_auth = auth.ljust(20, b"\x00")
        result = t._tpm_op_auth_req_body(padded_auth)
        self.assertEqual(len(result), 20)
        self.assertTrue(result.startswith(b"AUTH"))


if __name__ == "__main__":
    unittest.main()
