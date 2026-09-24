#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bound a tar archive by its raw headers before tarfile reads it.

tarfile consumes GNU long-name and long-link headers and pax headers inside the
call that yields the next member. It reads their data into memory and recurses
into the following header, so counting the members it yields bounds neither the
headers read nor that memory. scan() walks the raw 512-byte headers of the
(decompressed) stream first, with the header parser tarfile uses. It counts
every header, extension headers included, allows only the header types the
caller names, caps extension data and runs of extension headers, refuses pax
records that change a member's size or describe a sparse file, and seeks over
member data without reading it. open_stream() gives the decompressed stream
that is scanned and then handed to tarfile, so both read the same bytes.
"""
import bz2
import gzip
import lzma
from pathlib import Path
import re
import tarfile

BLOCK = tarfile.BLOCKSIZE
EXTENSIONS = {tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK, tarfile.XHDTYPE, tarfile.XGLTYPE,
              tarfile.SOLARIS_XHDTYPE}
PAX = {tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE}
# The canonical release archive is GNU tar with regular files and, for long paths, GNU long names.
RELEASE_TYPES = frozenset({tarfile.REGTYPE, tarfile.GNUTYPE_LONGNAME})
# The prepared inputs may come from GNU tar or Python's pax default: files, directories and name extensions.
INPUT_TYPES = frozenset({tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, tarfile.GNUTYPE_LONGNAME,
                         tarfile.XHDTYPE, tarfile.XGLTYPE})
MAX_EXTENSION = 1 << 16
MAX_RUN = 4
PAX_RECORD = re.compile(rb'([1-9][0-9]{0,8}) ([^=\n]+)=')
COMPRESSED = [(b'\x1f\x8b', gzip.open), (b'BZh', bz2.open), (b'\xfd7zXZ\x00', lzma.open)]


class TarRefused(Exception):
    """A tar archive exceeds the header bounds."""


def refuse_unless(condition, message):
    if not condition:
        raise TarRefused(message)


def open_stream(path):
    """The tar stream of a plain, gzip, bzip2 or xz file, opened for reading."""
    with Path(path).open('rb') as probe:
        magic = probe.read(6)
    for prefix, opener in COMPRESSED:
        if magic.startswith(prefix):
            return opener(path, 'rb')
    return Path(path).open('rb')


def pax_keys(data):
    """The keys of a pax header, parsed strictly: every record exactly as long as its length says."""
    keys, position = [], 0
    while position < len(data):
        match = PAX_RECORD.match(data, position)
        refuse_unless(match is not None, 'malformed pax header')
        end = position + int(match.group(1))
        # The length prefix, key and '=' hold no newline, so a length that is too short or too long for the
        # data fails the terminator check as well.
        refuse_unless(data[end - 1:end] == b'\n' and b'\n' not in data[match.end():end - 1], 'malformed pax header')
        keys.append(match.group(2))
        position = end
    return keys


def scan(stream, limit, types):
    """The number of raw headers before the end marker; refused beyond limit, outside types or the bounds."""
    headers = run = 0
    while True:
        block = stream.read(BLOCK)
        if len(block) < BLOCK or not any(block):
            return headers
        headers += 1
        refuse_unless(headers <= limit, f'too many members: more than {limit} tar headers')
        try:
            info = tarfile.TarInfo.frombuf(block, 'utf-8', 'surrogateescape')
        except tarfile.HeaderError as error:
            raise TarRefused(f'unreadable tar header {headers}: {error}') from None
        refuse_unless(info.type in types, f'tar header type {info.type!r} is not allowed')
        stored = -(-info.size // BLOCK) * BLOCK
        if info.type in EXTENSIONS:
            run += 1
            refuse_unless(run <= MAX_RUN, f'more than {MAX_RUN} tar extension headers in a row')
            refuse_unless(info.size <= MAX_EXTENSION, f'a tar extension header holds {info.size} bytes')
            data = stream.read(stored)
            refuse_unless(len(data) == stored, 'the archive ends inside a tar extension header')
            if info.type in PAX:
                for key in pax_keys(data[:info.size]):
                    refuse_unless(key != b'size' and not key.startswith(b'GNU.sparse'),
                                  'pax record not allowed: ' + key.decode('utf-8', 'replace'))
        else:
            run = 0
            if info.type in tarfile.REGULAR_TYPES:  # tarfile skips data only for regular members
                stream.seek(stored, 1)
