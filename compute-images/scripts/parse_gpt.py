#!/usr/bin/env python3.12
# -*- coding: utf-8 -*-
"""Script to parse a TPM GPT event string.
SEE: <https://github.com/ceph/simplegpt/blob/master/simplegpt.py>
"""

import collections
import logging
import os
import struct
import sys
import uuid
from collections.abc import Iterator

from devtools import debug


def _make_fmt(name: str, format: str, extras: list[str] = []):
    type_and_name = [l.split(None, 1) for l in format.strip().splitlines()]
    fmt = "".join(t for (t, n) in type_and_name)
    fmt = "<" + fmt
    tupletype = collections.namedtuple(name, [n for (t, n) in type_and_name if n != "_"] + extras)

    return (fmt, tupletype)


# http://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_table_header_.28LBA_1.29
GPT_HEADER_FORMAT = """
8s signature
4s revision
L header_size
L crc32
4x _
Q current_lba
Q backup_lba
Q first_usable_lba
Q last_usable_lba
16s disk_guid
Q part_entry_start_lba
L num_part_entries
L part_entry_size
L crc32_part_array
"""

GPT_HDR_FMT, GPTHeader = _make_fmt("GPTHeader", GPT_HEADER_FORMAT)

# http://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_entries_.28LBA_2.E2.80.9333.29
GPT_PARTITION_FORMAT = """
16s type
16s unique
Q first_lba
Q last_lba
Q flags
72s name
"""

GPT_PART_FMT, GPTPartition = _make_fmt("GPTPartition", GPT_PARTITION_FORMAT, extras=["index"])

logging.basicConfig(
    level=logging.DEBUG,
    format="[%(threadName)s] %(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)


class GPTError(Exception):
    pass


def read_header(event: bytes) -> GPTHeader:
    # Skip MBR
    data = event[: struct.calcsize(GPT_HDR_FMT)]
    header = GPTHeader._make(struct.unpack(GPT_HDR_FMT, data))

    if header.signature != b"EFI PART":
        raise GPTError(f"Bad signature: {header.signature}")

    if header.revision != b"\x00\x00\x01\x00":
        raise GPTError(f"Bad revision: {header.revision}")

    if header.header_size < 92:
        raise GPTError(f"Bad header size: {header.header_size}")

    header = header._replace(
        disk_guid=str(uuid.UUID(bytes_le=header.disk_guid)),
    )

    return header


def read_partitions(event: bytes, header: GPTHeader, lba_size: int = 50) -> Iterator[GPTPartition]:
    event = event[header.part_entry_start_lba * lba_size :]

    for i in range(1, 1 + header.num_part_entries):
        data = event[: header.part_entry_size]
        event = event[header.part_entry_size :]

        if not data:
            return
        elif len(data) < struct.calcsize(GPT_PART_FMT):
            raise GPTError("Short partition entry")

        part = GPTPartition._make(struct.unpack(GPT_PART_FMT, data) + (i,))

        if part.type == 16 * "\x00":
            continue

        part = part._replace(
            type=str(uuid.UUID(bytes_le=part.type)),
            unique=str(uuid.UUID(bytes_le=part.unique)),
            name=part.name.decode("utf-16").split("\0", 1)[0],
        )
        yield part


def main(av: list[str]) -> int:
    if len(av) != 2:
        print("Usage: parse_gpt GPT_EVENT", file=sys.stderr)
        return os.EX_USAGE

    event = bytes.fromhex(av[1])
    header = read_header(event)
    debug(header)

    for part in read_partitions(event, header):
        debug(part)

    return os.EX_OK


if __name__ == "__main__":
    """Example:
    python3.12 scripts/parse_gpt.py "$(sudo tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements | yq -r '(.events[] | select(.EventType == "EV_EFI_GPT_EVENT")).Event')"
    """
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:
        sys.exit(os.EX_OK)
