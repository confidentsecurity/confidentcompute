#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Mar  5 14:04:49 2025
"""

import logging
import os
import sys
from configparser import ConfigParser
from pathlib import Path
from typing import Final

import networkx as nx

_log_handler = logging.StreamHandler(sys.stdout)
_log_formatter = logging.Formatter(
    "[%(processName)s][%(threadName)s] %(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s"
)
_log_handler.setFormatter(_log_formatter)
logger = logging.getLogger()
logger.addHandler(_log_handler)
logger.setLevel(logging.DEBUG)

SHELLS: Final[list[str]] = ["/bin/sh", "/bin/bash"]


def assess_prog(prog: str) -> bool:
    uses_shell = False

    # Remove systemd special characters.
    match prog[0]:
        case "@" | "-" | ":" | "+":
            prog = prog[1:]
        case "!":
            if prog[1] == "!":
                prog = prog[2:]
            else:
                prog = prog[1:]
        case _:
            pass

    # Try to resolve the executable.
    match prog[0]:
        case "/":
            pass
        case _:
            logger.warning("Searching in $PATH for the program.")

            for path in os.environ["PATH"].split(":"):
                if (Path(path) / prog).resolve().exists():
                    prog = str((Path(path) / prog).resolve())
                    logger.warning("Found executable at: %s", prog)
                    break

    if prog in SHELLS:
        logger.warning("Service requires a shell: %s", prog)
        uses_shell = True
    elif Path(prog).suffix.lower() == ".sh":
        logger.warning("Service requires a shell (file name): %s", prog)
        uses_shell = True
    else:
        with open(prog, "r", encoding="utf-8") as f:
            try:
                prog_content = f.read().strip()
                first_line = prog_content.splitlines()[0]

                if any(map(lambda shell: f"#!{shell}" in first_line, SHELLS)):
                    logger.warning(
                        "Service requires a shell (shebang detected): %s",
                        first_line,
                    )
                    uses_shell = True
            except UnicodeDecodeError:
                logger.debug("Program is binary encoded, skipping: %s", prog)

    return uses_shell


def interpret_service(service_path: Path) -> tuple[ConfigParser, bool, str | None, str | None]:
    resolved_path = service_path.resolve()
    logger.debug("systemd service %s resolves to: %s", service_path, resolved_path)
    assert resolved_path.is_file()
    content = ConfigParser(strict=False)
    content.read(resolved_path)
    uses_shell = False
    required_by = None
    wanted_by = None

    if "Install" in content:
        if "RequiredBy" in content["Install"]:
            required_by = content["Install"]["RequiredBy"]

        if "WantedBy" in content["Install"]:
            wanted_by = content["Install"]["WantedBy"]

    if "Service" in content:
        if "ExecStartPre" in content["Service"]:
            exec_start_pre = content["Service"]["ExecStartPre"]
            logger.info("Service %s ExecStartPre=%s", service_path, exec_start_pre)
            prog = exec_start_pre.split()[0]

            if assess_prog(prog):
                uses_shell = True

        if "ExecStart" in content["Service"]:
            exec_start = content["Service"]["ExecStart"]
            logger.info("Service %s ExecStart=%s", service_path, exec_start)
            prog = exec_start.split()[0]

            if assess_prog(prog):
                uses_shell = True

        if "ExecStartPost" in content["Service"]:
            exec_start_post = content["Service"]["ExecStartPost"]
            logger.info("Service %s ExecStartPost=%s", service_path, exec_start_post)
            prog = exec_start_post.split()[0]

            if assess_prog(prog):
                uses_shell = True

    return content, uses_shell, required_by, wanted_by


def traverse_deps(dep_dir: Path) -> list[tuple[Path, ConfigParser, bool, str | None, str | None]]:
    logger.debug("Stepping into dependency group: %s", dep_dir)
    assert dep_dir.is_dir()
    services = []

    for path in dep_dir.iterdir():
        match path.suffix.lower():
            case ".service":
                service_path = dep_dir / path
                service, uses_shell, required_by, wanted_by = interpret_service(service_path)
                services.append((service_path, service, uses_shell, required_by, wanted_by))
            case _:
                ...

    return services


def main(av: list[str]) -> int:
    if len(av) != 2:
        print("usage: systemd-graph.py DIR", file=sys.stderr)
        return os.EX_USAGE

    sys_dir = Path(av[1]).resolve()
    assert sys_dir.is_dir()
    logger.info("Attempting to crawl systemd directory: %s", sys_dir)
    dep_groups = {}
    dep_graph = nx.DiGraph()

    for path in sys_dir.iterdir():
        match path.suffix.lower():
            case ".requires":
                dep_dir = sys_dir / path
                deps = traverse_deps(dep_dir)
                dep_groups[dep_dir.name] = deps
            case ".wants":
                dep_dir = sys_dir / path
                deps = traverse_deps(dep_dir)
                dep_groups[dep_dir.name] = deps
            case ".service":
                service_path = sys_dir / path
                service, uses_shell, required_by, wanted_by = interpret_service(service_path)
                dep_graph.add_node(service_path.name, uses_shell=uses_shell)

                if required_by is not None:
                    dep_graph.add_edge(service_path.name, required_by)

                if wanted_by is not None:
                    dep_graph.add_edge(service_path.name, wanted_by)
            case ".mount":
                ...
            case _:
                ...

    for dep_group, deps in dep_groups.items():
        dep_graph.add_node(dep_group)

        for service_path, service, uses_shell, required_by, wanted_by in deps:
            if uses_shell:
                logger.critical("%s uses shell!", service_path)

            dep_graph.add_edge(service_path.name, dep_group)
            dep_graph.add_node(service_path.name, uses_shell=uses_shell)

    nx.nx_pydot.write_dot(dep_graph, f"{'_'.join(sys_dir.parts[1:])}.dot")

    return os.EX_OK


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:
        sys.exit(os.EX_OK)
