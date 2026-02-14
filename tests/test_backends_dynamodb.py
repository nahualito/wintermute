from decimal import Decimal
from unittest.mock import MagicMock, patch

from wintermute.backends.dynamodb import DynamoDBBackend


@patch("boto3.resource")
def test_dynamodb_save_converts_floats(mock_resource: MagicMock) -> None:
    mock_table = MagicMock()
    mock_resource.return_value.Table.return_value = mock_table

    backend = DynamoDBBackend(table_name="TestTable")
    test_data = {"score": 95.5, "tags": ["a", "b"]}

    backend.save("op-1", test_data)

    # Verify Decimal conversion
    called_item = mock_table.put_item.call_args[1]["Item"]
    assert isinstance(called_item["score"], Decimal)
    assert called_item["operation_name"] == "op-1"


@patch("boto3.resource")
def test_dynamodb_load(mock_resource: MagicMock) -> None:
    mock_table = MagicMock()
    mock_table.get_item.return_value = {
        "Item": {"operation_name": "op-1", "data": "val"}
    }
    mock_resource.return_value.Table.return_value = mock_table

    backend = DynamoDBBackend()
    data = backend.load("op-1")
    assert data is not None
    assert data["data"] == "val"
