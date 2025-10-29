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

from __future__ import annotations

import time
from typing import Callable, TypeVar

T = TypeVar("T")


def with_retries(
    fn: Callable[[], T], *, attempts: int = 3, backoff_sec: float = 0.5
) -> T:
    last_exc: Exception | None = None
    for i in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - surface provider exceptions verbatim
            last_exc = exc
            if i == attempts - 1:
                raise
            time.sleep(backoff_sec * (2**i))
    # mypy: control never reaches here
    assert last_exc is not None
    raise last_exc
