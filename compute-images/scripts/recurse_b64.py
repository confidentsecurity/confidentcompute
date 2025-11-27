#!/usr/bin/env python3.12
# -*- coding: utf-8 -*-
"""Script to extract embedded base64 strings from a JSON file.
"""

import base64
import json
import logging
import os
import re
import sys
from collections.abc import Callable, Iterator
from typing import Final, Union

logging.basicConfig(
    level=logging.DEBUG,
    format="[%(threadName)s] %(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

B64_REGEX: Final[re.Pattern] = re.compile(
    r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
)

Terminal = None | int | float | str
Json = Terminal | list["Json"] | dict[str, "Json"]
Trace = list[Union[str, int, None]]
Extractor = Callable[[str], str | None]


def traverse_terminals(data: Json, trace: Trace = []) -> Iterator[tuple[Terminal, bool, Trace]]:
    if isinstance(data, dict):
        for key, value in data.items():
            yield key, True, trace
            yield from traverse_terminals(value, trace + [key])
    elif isinstance(data, list):
        for i in range(len(data)):
            yield from traverse_terminals(data[i], trace + [i])
    else:
        yield data, False, trace


def _crawl_object(
    data: Json, pattern: re.Pattern, extractor: Extractor, trace: Trace = []
) -> Iterator[tuple[str, bool, Trace, int]]:
    for terminal, is_key, trace in traverse_terminals(data, trace):
        if isinstance(terminal, str):
            matches = re.findall(pattern, terminal)

            for i in range(len(matches)):
                match = matches[i]
                embed_str = extractor(match)

                if embed_str is not None:
                    yield embed_str, is_key, trace, i


def crawl_object(
    data: Json, pattern: re.Pattern, extractor: Extractor, trace: Trace = []
) -> Iterator[tuple[str, bool, Trace, int]]:
    for embed, is_key, _trace, index in _crawl_object(data, pattern, extractor, trace):
        yield embed, is_key, _trace, index

        try:
            nested_data = json.loads(embed)
            # NOTE: None acts an indicator that we recursed into a nested JSON payload.
            yield from crawl_object(nested_data, pattern, extractor, _trace + [None])
        except:
            pass


def trace_to_str(trace: Trace) -> str:
    trace_str = "$"

    for i in range(len(trace)):
        step = trace[i]
        prepend = True
        trace_substr = ""

        if isinstance(step, str):
            trace_substr = f"{step}"
        elif isinstance(step, int):
            trace_substr = f"[{step}]"
            prepend = False
        elif step is None:
            trace_substr = " ∇ $"
            prepend = False
        else:
            assert False, type(step)

        if prepend:
            trace_substr = "." + trace_substr

        trace_str += trace_substr

    return trace_str


def extract_b64(match: str) -> str | None:
    try:
        embed_bytes = base64.b64decode(match, validate=False)
        # Replace invalid sequences with �
        embed_str = embed_bytes.decode("utf-8", errors="replace")
        return embed_str
    except Exception as exc:
        logging.warning(exc)

    return None


def main(av: list[str]) -> int:
    if len(av) != 2:
        print("Usage: recurse_b64 FILE", file=sys.stderr)
        return os.EX_USAGE

    with open(av[1], "r", encoding="utf-8") as f:
        data = json.loads(f.read())

    for embed, is_key, trace, index in crawl_object(data, B64_REGEX, extract_b64):
        trace_str = trace_to_str(trace)
        print(f"----- BEGIN {trace_str}{{{index}}} key={is_key} -----")
        print(f"{embed}")
        print(f"----- END   {trace_str}{{{index}}} key={is_key} -----")

    return os.EX_OK


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:
        sys.exit(os.EX_OK)
