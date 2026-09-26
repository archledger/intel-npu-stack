#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bound a tar archive by its raw headers before tarfile reads it.

tarfile consumes GNU long-name and long-link headers and pax headers inside the
call that yields the next member. It reads their data into memory and recurses
into the following header, so counting the members it yields bounds neither the
headers read nor that memory. scan() walks the raw 512-byte headers of the
(decompressed) stream first, with the header parser tarfile uses. It counts
every header, extension headers included, allows only the header types the
caller names and refuses a negative size. It refuses a regular file named like
a directory, the old v7 directory form: tarfile reads it as a directory, but
after an extension header as a file whose data it skips, so the two would read
different headers. It caps extension data per header and per archive, global
pax data (which tarfile copies into every later member) and runs of extension
headers, all from the declared sizes before any data is read. It refuses pax
records that change a member's size or describe a sparse file, and pax padding
that is not zero, since tarfile would parse records there. It can cap the sum
of the declared member sizes, and it seeks over member data without reading it.
open_stream() gives the decompressed stream that is scanned and then handed to
tarfile, so both read the same bytes.
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
# GNU posix tar adds 90 bytes a member (Python's pax 28): 1 MiB covers the 10000 members 20000 headers hold.
MAX_EXTENSION_TOTAL = 1 << 20
MAX_GLOBAL = 1 << 10  # tarfile copies global pax records into every later member; git archive writes 52 bytes
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


def scan(stream, limit, types, max_bytes=None):
    """The number of raw headers before the end marker; refused beyond limit, outside types or the bounds.

    With max_bytes, the sizes the regular members declare are summed and refused past it before their data is
    skipped, so a compressed stream is never decompressed beyond that budget.
    """
    headers = run = total = extension = global_pax = 0
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
        # frombuf reads the old v7 form of a directory, a regular file named with a trailing slash, as a directory,
        # but tarfile reads it after an extension header as a regular file and skips its data.
        refuse_unless(info.type == block[156:157], f'tar header {headers} is a regular file named like a directory')
        # GNU base-256 can encode a negative size, which would seek backwards or read to the end.
        refuse_unless(info.size >= 0, f'tar header {headers} declares a negative size')
        stored = -(-info.size // BLOCK) * BLOCK
        if info.type in EXTENSIONS:
            run += 1
            refuse_unless(run <= MAX_RUN, f'more than {MAX_RUN} tar extension headers in a row')
            refuse_unless(info.size <= MAX_EXTENSION, f'a tar extension header holds {info.size} bytes')
            extension += info.size
            refuse_unless(extension <= MAX_EXTENSION_TOTAL,
                          f'the tar extension headers hold more than {MAX_EXTENSION_TOTAL} bytes')
            global_pax += info.size if info.type == tarfile.XGLTYPE else 0
            refuse_unless(global_pax <= MAX_GLOBAL,
                          f'the tar headers hold more than {MAX_GLOBAL} bytes of global pax data')
            data = stream.read(stored)
            refuse_unless(len(data) == stored, 'the archive ends inside a tar extension header')
            if info.type in PAX:
                # tarfile parses the whole padded block up to a NUL, so a record in the padding would take effect.
                refuse_unless(not any(data[info.size:]), 'pax header padding is not zero')
                for key in pax_keys(data[:info.size]):
                    refuse_unless(key != b'size' and not key.startswith(b'GNU.sparse'),
                                  'pax record not allowed: ' + key.decode('utf-8', 'replace'))
        else:
            run = 0
            if info.type in tarfile.REGULAR_TYPES:  # tarfile skips data only for regular members
                total += info.size
                refuse_unless(max_bytes is None or total <= max_bytes,
                              f'the regular members declare more than {max_bytes} bytes')
                stream.seek(stored, 1)
