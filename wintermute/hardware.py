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

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .basemodels import BaseModel


@dataclass
class Architecture(BaseModel):
    core: Optional[str] = None
    instruction_set: Optional[str] = None
    cpu_cores: Optional[int] = None
    key_features: Optional[Dict[Any, Any]] = field(default_factory=dict)

    __schema__ = {}
    __enums__ = {}


@dataclass
class Processor(BaseModel):
    processor: Optional[str] = None
    processor_family: Optional[str] = None
    description: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    architecture: Optional[Architecture] | Dict[Any, Any] = field(default_factory=dict)
    endianness: Optional[str] = None
    overall_capabilities: Optional[Dict[Any, Any]] = field(default_factory=dict)
    pinout: Optional[Dict[Any, Any]] = field(default_factory=dict)

    __schema__ = {"Architecture": Architecture}
    __enums__ = {}


@dataclass
class Memory(BaseModel):
    total_physical_memory: Optional[int] = None
    available_physical_memory: Optional[int] = None
    total_virtual_memory: Optional[int] = None
    available_virtual_memory: Optional[int] = None
    page_file_size: Optional[int] = None
    page_file_available: Optional[int] = None

    __schema__ = {}
    __enums__ = {}
