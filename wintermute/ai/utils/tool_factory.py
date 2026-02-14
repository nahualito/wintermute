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

import inspect
from typing import Any, Callable, List, cast, get_type_hints

from pydantic import create_model

from wintermute.ai.json_types import JSONObject
from wintermute.ai.tools_runtime import Tool


def function_to_tool(func: Callable[..., Any]) -> Tool:
    """
    Converts a standard Python function into a Tool object.
    Wraps the function to handle JSON inputs/outputs automatically.
    """
    func_name = func.__name__
    func_doc = func.__doc__ or "No description provided."

    # 1. GENERATE INPUT SCHEMA
    # Inspect arguments to build the Pydantic model
    type_hints = get_type_hints(func)
    input_fields = {}

    signature = inspect.signature(func)
    for param_name, param in signature.parameters.items():
        if param_name == "self":
            continue

        annotation = type_hints.get(param_name, Any)
        default = param.default

        if default == inspect.Parameter.empty:
            input_fields[param_name] = (annotation, ...)
        else:
            input_fields[param_name] = (annotation, default)

    InputModel = create_model(f"{func_name}_Input", **input_fields)  # type: ignore
    input_schema = cast(JSONObject, InputModel.model_json_schema())

    # 2. GENERATE OUTPUT SCHEMA
    # We inspect the return type.
    # If the function returns `int`, the tool output will be `{"result": int}`.
    return_annotation = type_hints.get("return", Any)

    # Create a dynamic model for the output to get a valid JSON Schema
    OutputModel = create_model(f"{func_name}_Output", result=(return_annotation, ...))
    output_schema = cast(JSONObject, OutputModel.model_json_schema())

    # 3. CREATE THE WRAPPER (The Handler)
    # This transforms the Tool's JSON input into the function's args,
    # and transforms the function's return value back into JSON.
    def adapter_handler(params: JSONObject) -> JSONObject:
        # Validate input using our generated model (optional but safe)
        validated_params = InputModel(**params)

        # Call the actual function with unpacked arguments
        result = func(**validated_params.model_dump())

        # Pack the result into a JSON object matching our output schema
        # Note: If your function already returns a dict, you might want logic here
        # to decide whether to wrap it in "result" or return as is.
        # For consistency, we always wrap strictly typed returns in "result".
        return {"result": result}

    # 4. INSTANTIATE TOOL
    return Tool(
        name=func_name,
        description=func_doc,
        input_schema=input_schema,
        output_schema=output_schema,
        handler=adapter_handler,
    )


def register_tools(functions: List[Callable[..., Any]]) -> List[Tool]:
    return [function_to_tool(f) for f in functions]
