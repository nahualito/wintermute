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

import logging
from collections import defaultdict
from typing import Dict

from wintermute.cloud.aws import IAMRole, IAMUser
from wintermute.core import Device, Operation

log = logging.getLogger(__name__)


def analyze_coverage(operation: Operation) -> Dict[str, int]:
    """
    Efficiently categorizes 271k+ test runs by AWSServiceType.
    """
    log.info("[*] Indexing Operation Assets for fast lookup...")

    # 1. Build a Fast Lookup Index {object_id: object}
    # This prevents us from searching the whole account list for every test run.
    asset_index = {}

    # Index Devices (e.g., Attacker Machine)
    for dev in operation.devices:
        # Use hostname or ip as ID depending on your binding logic
        asset_index[dev.hostname] = dev

    # Index Cloud Assets
    for acc in operation.cloud_accounts:
        # Index Services (EC2, S3, Lambda, etc.)
        if hasattr(acc, "services"):
            for svc in acc.services:
                asset_index[svc.arn] = svc
                # Also index by name if ARNs aren't used in binding
                asset_index[svc.name] = svc

        # Index IAM Users
        if hasattr(acc, "iamusers"):
            for user in acc.iamusers:
                asset_index[user.username] = user

        # Index IAM Roles
        if hasattr(acc, "iamroles"):
            for role in acc.iamroles:
                asset_index[role.role_name] = role

    log.info(f"[*] Indexing complete. Mapped {len(asset_index)} assets.")
    log.info(f"[*] Categorizing {len(operation.test_runs)} test runs...")

    # 2. Iterate and Count
    stats: Dict[str, int] = defaultdict(int)

    for run in operation.test_runs:
        # A run might have multiple bindings, we usually care about the first one (the target)
        if not run.bound:
            stats["GLOBAL_MISC"] += 1
            continue

        target_ref = run.bound[0]  # BoundObjectRef
        obj_id = target_ref.object_id

        # Fast Lookup
        obj = asset_index.get(obj_id)

        if not obj:
            # Fallback: If ID lookup fails, try to guess from Test Case Code prefix
            # e.g., "AWS-S3-..." -> "S3"
            prefix = (
                run.test_case_code.split("-")[1]
                if "-" in run.test_case_code
                else "UNKNOWN"
            )
            stats[f"Unbound ({prefix})"] += 1
            continue

        # 3. Determine Type based on Object Class
        if hasattr(obj, "service_type"):
            # It's an AWSService (EC2, S3, RDS, etc.)
            # If service_type is an Enum, get its value, else use string
            sType = (
                obj.service_type.value
                if hasattr(obj.service_type, "value")
                else str(obj.service_type)
            )
            stats[sType.upper()] += 1

        elif isinstance(obj, (IAMUser, IAMRole)):
            # Group Users and Roles under generic IAM
            stats["IAM"] += 1

        elif isinstance(obj, Device):
            stats["OSINT/GLOBAL"] += 1

        else:
            stats["OTHER"] += 1

    return stats


# --- usage example ---
# Assuming 'op' is your populated Operation object
# counts = analyze_coverage(op)
#
# print(f"{'SERVICE':<20} | {'TEST CASES':<10}")
# print("-" * 35)
# for service, count in sorted(counts.items(), key=lambda item: item[1], reverse=True):
#     print(f"{service:<20} | {count:<10,}")
