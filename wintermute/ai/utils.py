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

from ..hardware import Processor
from .bootstrap import init_router
from .provider import Router
from .use import simple_chat

logger = logging.getLogger(__name__)


def enrich_processor(processor: Processor, router: Router | None = None) -> Processor:
    if router is None:
        router = init_router()
        logger.debug("Router not defined, initializing inside enrich_processor")

    try:
        answer = simple_chat(
            router,
            f"Provide me with the processor name as processor, core, instruction set, number of cpu_cores, key features, processor family, \
            description, manufacturer, model, architecture, endianness and overall capabilities of the {processor.processor} processor, in the \
            architecture field encompass the core, instruction_set, cpu_cores and key_features. Respond with only the json format with each \
            capability and characteristics, including the general pinout, boot pinout, JTAG pinout, UART pinout as pinout in the json",
            task_tag="ProcessorEnrichment",
        )
    except Exception as e:
        logger.error(f"Error during processor enrichment: {e}")
        return processor

    try:
        answer_json = json.loads(answer)
        _processor = Processor.from_dict(answer_json)
    except json.JSONDecodeError as e:
        logger.error(f"JSON decoding error: {e}")
        return processor
    except TypeError as e:
        logger.error(f"Type error during Processor parsing: {e}")
        return processor
    except Exception as e:
        logger.error(f"Error parsing AI response: {e}")
        return processor
    return _processor
