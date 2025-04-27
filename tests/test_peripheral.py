import json

import pytest

from wintermute.peripherals import Peripheral, PeripheralType


@pytest.fixture
def peripheral() -> Peripheral:
    """pytest fixture to create a peripheral instance."""
    return Peripheral(
        name="TestPeripheral",
        pins={"tx": "uart1", "rx": "uart2", "gnd": "uart3"},
    )


def test_peripheral_creation(peripheral: Peripheral) -> None:
    """Test the creation of the peripheral object."""
    assert peripheral.name == "TestPeripheral"
    assert peripheral.pins == {"tx": "uart1", "rx": "uart2", "gnd": "uart3"}
    assert peripheral.pType == PeripheralType.Unknown


def test_peripheral_tojson(peripheral: Peripheral) -> None:
    """Test the toJSON() function operation for the peripheral object."""
    tojson = json.loads(
        '{\n    "name": "TestPeripheral",\n    "pType": "Unknown",\n    \
                        "pins": {\n        "gnd": "uart3",\n        "rx": "uart2",\n        "tx": "uart1"\n    }\n}'
    )

    assert peripheral.name == tojson["name"]
    assert peripheral.pType.name == tojson["pType"]
    assert peripheral.pins == tojson["pins"]
