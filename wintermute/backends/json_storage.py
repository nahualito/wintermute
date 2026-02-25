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

import json
import logging
import os
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

__category__ = "Storage"
__description__ = "Local JSON-based flat file persistence for offline ops."


class JsonFileBackend:
    """Stores operations as JSON files in a specific directory.

    Examples:
        >>> from wintermute.core import Operation
        >>> from wintermute.backends.json_storage import JsonFileBackend
        >>> backend = JsonFileBackend()
        >>> Operation.register_backend("json_local", backend, make_default=True)
        >>> op = Operation("Project_Test1")
        >>> op.addAnalyst("Ripley", "ripley", "ripley@foobar.com")
        True
        >>> op.save()
        True
        >>> op2 = Operation("Project_Test1")
        >>> op2.load()
        True
        >>> op2
        <wintermute.core.Operation object at 0x745c92ded7c0>
        >>> op2.to_dict()
        {'operation_name': 'Project_Test1',
            'operation_id': '8b5b3662-f597-11f0-a793-54b2030b4724',
            'start_date': '01/19/2026', 'end_date': '01/19/2026',
            'ticket': None,
            'analysts': [
                {
                    'name': 'Ripley',
                    'userid': 'ripley',
                    'email': 'ripley@foobar.com'
                }
            ],
            'devices': [],
            'users': [],
            'cloud_accounts': [],
            'test_plans': [],
            'test_runs': []
        }

    """

    def __init__(self, base_path: str = ".wintermute_data"):
        self.base_path = base_path
        os.makedirs(self.base_path, exist_ok=True)

    def _get_path(self, op_id: str) -> str:
        # Sanitize filename if needed
        safe_name = "".join(x for x in op_id if x.isalnum() or x in "-_")
        return os.path.join(self.base_path, f"{safe_name}.json")

    def save(self, operation_id: str, data: Dict[str, Any]) -> bool:
        path = self._get_path(operation_id)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, default=str)
            return True
        except Exception as e:
            log.error(f"Error saving to {path}: {e}")
            return False

    def load(self, operation_id: str) -> Optional[Dict[str, Any]]:
        path = self._get_path(operation_id)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
                log.error(f"Data in {path} is not a valid dictionary.")
                return None
        except Exception as e:
            log.error(f"Error loading {path}: {e}")
            return None

    def list_all(self) -> List[str]:
        if not os.path.exists(self.base_path):
            return []
        return [
            f.replace(".json", "")
            for f in os.listdir(self.base_path)
            if f.endswith(".json")
        ]

    def delete(self, operation_id: str) -> bool:
        path = self._get_path(operation_id)
        if not os.path.exists(path):
            log.warning(f"Operation {operation_id} not found at {path}")
            return False
        try:
            os.remove(path)
            return True
        except Exception as e:
            log.error(f"Error deleting {path}: {e}")
            return False
