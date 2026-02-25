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

from decimal import Decimal
from typing import Any, Dict, List, Optional

import boto3

__category__ = "Storage"
__description__ = "Cloud-native persistence via Amazon DynamoDB."
from botocore.exceptions import ClientError


class DynamoDBBackend:
    """Stores operations in an AWS DynamoDB table.

    Examples:
        >>> from wintermute.core import Operation
        >>> from wintermute.backends.dynamodb import DynamoDBBackend
        >>> backend = DynamoDBBackend(
        ...     table_name="WintermuteOperations", create_if_missing=True
        ... )
        >>> Operation.register_backend("dynamodb", backend, make_default=True)
        >>> op = Operation("Project_Test1")
        >>> op.addAnalyst("Ripley", "ripley", "ripley@foobar.com")
        True
        >>> op.save()
        True
        >>> print("Loading from DynamoDB...")
        Loading from DynamoDB...
        >>> op2 = Operation("Project_Test1")
        >>> op2.load()
        True
        >>> print(f"Analyst loaded: {op2.analysts[0].name}")
        Analyst loaded: Ripley
        >>> assert op2.analysts[0].userid == "ripley"
        >>> print("Success! Data round-tripped correctly.")
        Success! Data round-tripped correctly.
    """

    def __init__(
        self,
        table_name: str = "WintermuteOperations",
        region_name: str = "us-east-1",
        partition_key: str = "operation_name",
        create_if_missing: bool = False,
    ):
        self.table_name = table_name
        self.partition_key = partition_key
        self.dynamodb = boto3.resource("dynamodb", region_name=region_name)
        self.table = self.dynamodb.Table(table_name)

        if create_if_missing:
            self._ensure_table_exists()

    def _ensure_table_exists(self) -> None:
        """Checks if table exists, creates it if not."""
        try:
            self.table.load()
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            if error_code == "ResourceNotFoundException":
                print(f"Table {self.table_name} not found. Creating...")
                self.table = self.dynamodb.create_table(
                    TableName=self.table_name,
                    KeySchema=[
                        {"AttributeName": self.partition_key, "KeyType": "HASH"}
                    ],
                    AttributeDefinitions=[
                        {"AttributeName": self.partition_key, "AttributeType": "S"}
                    ],
                    ProvisionedThroughput={
                        "ReadCapacityUnits": 5,
                        "WriteCapacityUnits": 5,
                    },
                )
                # Wait for creation to finish
                self.table.wait_until_exists()
                print(f"Table {self.table_name} created successfully.")
            else:
                raise

    def _float_to_decimal(self, data: Any) -> Any:
        """DynamoDB requires Decimals instead of Floats."""
        if isinstance(data, list):
            return [self._float_to_decimal(i) for i in data]
        elif isinstance(data, dict):
            return {k: self._float_to_decimal(v) for k, v in data.items()}
        elif isinstance(data, float):
            return Decimal(str(data))
        return data

    def save(self, operation_id: str, data: Dict[str, Any]) -> bool:
        # 1. DynamoDB generally dislikes empty strings "" (it prefers null/None),
        #    though newer versions are more tolerant.
        # 2. It HATES python 'float' types. You must convert to Decimal.
        clean_data = self._float_to_decimal(data)

        # Ensure the partition key is present in the item
        clean_data[self.partition_key] = operation_id

        try:
            self.table.put_item(Item=clean_data)
            return True
        except ClientError as e:
            print(f"DynamoDB Save Error: {e}")
            return False

    def load(self, operation_id: str) -> Optional[Dict[str, Any]]:
        try:
            response = self.table.get_item(Key={self.partition_key: operation_id})
            # boto3 returns Decimals. You might want to convert back to float/int here
            # if your app expects strict types, but Python handles Decimal math fine usually.
            if isinstance(response.get("Item"), dict):
                data = response["Item"]
                if isinstance(data, dict):
                    return data
            return None
        except ClientError as e:
            print(f"DynamoDB Load Error: {e}")
            return None

    def list_all(self) -> List[str]:
        # Scan is expensive, but necessary to list all without a secondary index
        try:
            response = self.table.scan(ProjectionExpression=self.partition_key)
            return [item[self.partition_key] for item in response.get("Items", [])]
        except Exception as e:
            print(f"DynamoDB List Error: {e}")
            return []

    def delete(self, operation_id: str) -> bool:
        try:
            self.table.delete_item(Key={self.partition_key: operation_id})
            return True
        except ClientError as e:
            print(f"DynamoDB Delete Error: {e}")
            return False
