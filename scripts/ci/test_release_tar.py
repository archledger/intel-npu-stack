#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Contract for bounding a tar archive by its raw headers before tarfile reads it."""
import bz2
import gzip
import io
import lzma
import tarfile
import tempfile
import unittest
from pathlib import Path

import release_tar

LONG = 'd/' + 'n' * 150


def header(name, kind=tarfile.REGTYPE, size=0):
    info = tarfile.TarInfo(name)
    info.type, info.size = kind, size
    return info.tobuf(tarfile.GNU_FORMAT, 'utf-8', 'surrogateescape')


def padded(data):
    return data + bytes(-len(data) % tarfile.BLOCKSIZE)


def records(**records):
    """pax records ('_' in a key stands for '.'), each sized as tarfile sizes it."""
    body = b''
    for key, value in records.items():
        text = f' {key.replace("_", ".")}={value}\n'
        length = previous = 0
        while True:
            length = len(text) + len(str(previous))
            if length == previous:
                break
            previous = length
        body += (str(length) + text).encode()
    return body


def pax(kind=tarfile.XHDTYPE, **fields):
    """A pax header with these records."""
    body = records(**fields)
    return header('././@PaxHeader', kind, len(body)) + padded(body)


def longname(name):
    data = name.encode() + b'\0'
    return header('././@LongLink', tarfile.GNUTYPE_LONGNAME, len(data)) + padded(data)


def member(name='a', data=b'x'):
    return header(name, size=len(data)) + padded(data)


END = bytes(2 * tarfile.BLOCKSIZE)


class CountingStream(io.BytesIO):
    """A seekable stream that records how many bytes were read, not skipped."""

    def __init__(self, data):
        super().__init__(data)
        self.read_bytes = 0

    def read(self, size=-1):
        data = super().read(size)
        self.read_bytes += len(data)
        return data


def scan(data, limit=100, types=release_tar.INPUT_TYPES, **kwargs):
    return release_tar.scan(io.BytesIO(data), limit, types, **kwargs)


class Scan(unittest.TestCase):
    def refused(self, message, data, **kwargs):
        with self.assertRaisesRegex(release_tar.TarRefused, message):
            scan(data, **kwargs)

    def test_every_header_counts_including_extension_headers(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w', format=tarfile.GNU_FORMAT) as tar:
            for index in range(3):
                info = tarfile.TarInfo(f'{LONG}{index}')
                tar.addfile(info, io.BytesIO(b''))
        self.assertEqual(scan(stream.getvalue(), types=release_tar.RELEASE_TYPES), 6)
        self.assertEqual(scan(stream.getvalue(), limit=6, types=release_tar.RELEASE_TYPES), 6)
        self.refused('too many members: more than 5 tar headers', stream.getvalue(), limit=5,
                     types=release_tar.RELEASE_TYPES)

    def test_python_pax_archives_count_their_pax_headers(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT) as tar:
            for index in range(3):
                info = tarfile.TarInfo(f'file{index}')
                info.mtime = 1.5  # a fractional mtime is written to a pax header, as tar.add does
                tar.addfile(info, io.BytesIO(b''))
        self.assertEqual(scan(stream.getvalue()), 6)

    def test_extension_data_is_bounded_before_it_is_read(self):
        huge = header('././@LongLink', tarfile.GNUTYPE_LONGNAME, 900 << 20)
        stream = CountingStream(huge + END)
        with self.assertRaisesRegex(release_tar.TarRefused, 'extension header'):
            release_tar.scan(stream, 100, release_tar.INPUT_TYPES)
        self.assertEqual(stream.read_bytes, tarfile.BLOCKSIZE)
        at_limit = header('././@LongLink', tarfile.GNUTYPE_LONGNAME, release_tar.MAX_EXTENSION)
        self.assertEqual(scan(at_limit + bytes(release_tar.MAX_EXTENSION) + member() + END), 2)

    def test_extension_data_is_bounded_across_the_archive_before_it_is_read(self):
        # Every long name stays within its own cap; together they reach the archive's budget exactly.
        name = 'n' * (release_tar.MAX_EXTENSION - 1)
        count = release_tar.MAX_EXTENSION_TOTAL // release_tar.MAX_EXTENSION
        archive = b''.join(longname(f'{name[:-5]}{index:05}') + member(f'f{index}') for index in range(count))
        self.assertEqual(scan(archive + END), 2 * count)
        stream = CountingStream(archive + longname('x') + member('last') + END)
        with self.assertRaisesRegex(release_tar.TarRefused, f'more than {release_tar.MAX_EXTENSION_TOTAL} bytes'):
            release_tar.scan(stream, 1000, release_tar.INPUT_TYPES)
        # Only the headers and the long names within the budget are read; member data is skipped.
        skipped = count * tarfile.BLOCKSIZE
        self.assertEqual((stream.tell(), stream.read_bytes),
                         (len(archive) + tarfile.BLOCKSIZE, len(archive) - skipped + tarfile.BLOCKSIZE))

    def test_global_pax_data_stays_small_because_every_later_member_copies_it(self):
        commit = pax(tarfile.XGLTYPE, comment='0' * 40)  # the one global record git archive writes
        self.assertEqual(scan(commit + member() + member('b') + END), 3)
        body = records(comment='c' * (release_tar.MAX_GLOBAL - 14))
        self.assertEqual(len(body), release_tar.MAX_GLOBAL)
        full = header('././@PaxHeader', tarfile.XGLTYPE, len(body)) + padded(body)
        self.assertEqual(scan(full + member() + END), 2)
        stream = CountingStream(full + member() + commit + member('b') + END)
        with self.assertRaisesRegex(release_tar.TarRefused, f'more than {release_tar.MAX_GLOBAL} bytes of global'):
            release_tar.scan(stream, 100, release_tar.INPUT_TYPES)
        # The second global header is refused from its declared size, before its data is read.
        self.assertEqual((stream.tell(), stream.read_bytes),
                         (len(full) + 3 * tarfile.BLOCKSIZE, len(full) + 2 * tarfile.BLOCKSIZE))
        # Alternating global headers and members, each within every per-header cap, are refused too.
        alternating = b''.join(pax(tarfile.XGLTYPE, **{f'k{index}': 'v' * 200}) + member(f'f{index}')
                               for index in range(40))
        self.refused('bytes of global pax data', alternating + END)

    def test_the_extension_budget_admits_a_posix_archive_at_the_header_limit(self):
        # GNU tar's posix format gives every member a 90-byte pax header: mtime, atime and ctime.
        times = pax(mtime='1790355423.817946055', atime='1790355423.834162715', ctime='1790355423.834162715')
        self.assertEqual(int(tarfile.TarInfo.frombuf(times[:tarfile.BLOCKSIZE], 'utf-8', 'strict').size), 90)
        archive = b''.join(times + member(f'f{index:05}', b'') for index in range(10000)) + END
        self.assertEqual(scan(archive, limit=20000), 20000)

    def test_a_negative_declared_size_is_refused_before_any_seek_or_read(self):
        stream = CountingStream(member('a') + header('b', size=-1536) + member('c') + END)
        with self.assertRaisesRegex(release_tar.TarRefused, 'tar header 2 declares a negative size'):
            release_tar.scan(stream, 100, release_tar.INPUT_TYPES, max_bytes=1 << 20)
        self.assertEqual((stream.read_bytes, stream.tell()), (2 * tarfile.BLOCKSIZE, 3 * tarfile.BLOCKSIZE))
        extension = header('././@LongLink', tarfile.GNUTYPE_LONGNAME, -tarfile.BLOCKSIZE) + padded(b'n\0') + member()
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / 'negative.tar.gz'
            path.write_bytes(gzip.compress(extension + END))
            with release_tar.open_stream(path) as stream:
                with self.assertRaisesRegex(release_tar.TarRefused, 'tar header 1 declares a negative size'):
                    release_tar.scan(stream, 100, release_tar.INPUT_TYPES)

    def test_an_archive_that_ends_inside_extension_data_is_refused(self):
        self.refused('ends inside a tar extension header', header('././@LongLink', tarfile.GNUTYPE_LONGNAME, 600))

    def test_runs_of_extension_headers_are_bounded(self):
        run = b''.join(longname(f'{LONG}{index}') for index in range(release_tar.MAX_RUN))
        self.assertEqual(scan(run + member() + END), release_tar.MAX_RUN + 1)
        self.refused('extension headers in a row', longname(LONG) + run + member() + END)

    def test_only_the_named_header_types_are_allowed(self):
        cases = [
            ('symbolic link', header('link', tarfile.SYMTYPE), release_tar.INPUT_TYPES),
            ('hard link', header('hard', tarfile.LNKTYPE), release_tar.INPUT_TYPES),
            ('GNU sparse', header('sparse', tarfile.GNUTYPE_SPARSE), release_tar.INPUT_TYPES),
            ('long link', header('././@LongLink', tarfile.GNUTYPE_LONGLINK, 2) + padded(b'x\0'),
             release_tar.INPUT_TYPES),
            ('pax in a release archive', pax(mtime='1.5'), release_tar.RELEASE_TYPES),
            ('directory in a release archive', header('dir', tarfile.DIRTYPE), release_tar.RELEASE_TYPES),
        ]
        for label, data, types in cases:
            with self.subTest(label):
                self.refused('is not allowed', data + member() + END, types=types)

    def test_a_regular_file_named_like_a_directory_is_refused(self):
        # tarfile reads this old v7 directory form as a directory, but after an extension header as a regular file
        # whose data it skips: a zero block there would end the scan before headers tarfile goes on to read.
        directory = header('x/', tarfile.AREGTYPE, tarfile.BLOCKSIZE) + bytes(tarfile.BLOCKSIZE)
        hidden = header('link', tarfile.SYMTYPE) + longname('n' * (release_tar.MAX_EXTENSION + 1)) + member()
        for label, before in [('after a long name', longname('abc')), ('after a pax header', pax(path='abc')),
                              ('after a global pax header', pax(tarfile.XGLTYPE, comment='0' * 40)),
                              ('on its own', b'')]:
            with self.subTest(label):
                self.refused('tar header [0-9] is a regular file named like a directory',
                             before + directory + hidden + END)
        self.assertEqual(scan(longname('abc') + header('x', tarfile.AREGTYPE, 1) + padded(b'x') + END), 2)

    def test_pax_records_that_change_the_size_or_declare_sparse_files_are_refused(self):
        self.assertEqual(scan(pax(mtime='1.5', path='a') + member() + END), 2)
        for label, records in [('size', {'size': '0'}), ('sparse map', {'GNU_sparse_map': '0,1'}),
                               ('sparse 1.0', {'GNU_sparse_major': '1', 'GNU_sparse_minor': '0'})]:
            with self.subTest(label):
                self.refused('pax record', pax(**records) + member() + END)
        with self.subTest('global header size'):
            self.refused('pax record', pax(tarfile.XGLTYPE, size='0') + member() + END)

    def test_pax_records_hidden_in_the_block_padding_are_refused(self):
        # tarfile parses the whole padded block up to a NUL, so a record after the declared data would apply.
        visible = records(path='abc')
        for label, hidden in [('size', records(size=tarfile.BLOCKSIZE)),
                              ('sparse', records(GNU_sparse_size=tarfile.BLOCKSIZE))]:
            with self.subTest(label):
                data = header('././@PaxHeader', tarfile.XHDTYPE, len(visible)) + padded(visible + hidden)
                self.refused('pax header padding is not zero', data + header('abc') + bytes(tarfile.BLOCKSIZE)
                             + header('link', tarfile.SYMTYPE) + END)
        with self.subTest('global header'):
            data = header('././@PaxHeader', tarfile.XGLTYPE, len(visible)) + padded(visible + b'\n')
            self.refused('pax header padding is not zero', data + member() + END)

    def test_malformed_pax_records_are_refused(self):
        for label, body in [('bad length', b'99 mtime=1\n'), ('no newline', b'11 mtime=1x'),
                            ('no equals sign', b'8 mtime\n'), ('not a number', b'x mtime=1\n'),
                            ('newline in a value', b'13 mtime=1\n2\n')]:
            with self.subTest(label):
                data = header('././@PaxHeader', tarfile.XHDTYPE, len(body)) + padded(body)
                self.refused('malformed pax header', data + member() + END)

    def test_declared_member_sizes_are_bounded_before_their_data_is_skipped(self):
        data = member(data=bytes(600)) + header('big', size=10 << 20) + END
        self.assertEqual(release_tar.scan(io.BytesIO(member(data=bytes(600)) + END), 100, release_tar.INPUT_TYPES,
                                          max_bytes=600), 1)
        stream = io.BytesIO(data)
        with self.assertRaisesRegex(release_tar.TarRefused, 'regular members declare more than 1000 bytes'):
            release_tar.scan(stream, 100, release_tar.INPUT_TYPES, max_bytes=1000)
        # one header and two data blocks for the first member, then the header of the oversized one
        self.assertEqual(stream.tell(), 4 * tarfile.BLOCKSIZE, 'the oversized member must not be skipped')
        self.refused('declare more than 599 bytes', member(data=bytes(600)) + END, max_bytes=599)

    def test_member_data_is_skipped_not_read(self):
        stream = CountingStream(member(data=bytes(4 << 20)) + END)
        self.assertEqual(release_tar.scan(stream, 100, release_tar.INPUT_TYPES), 1)
        self.assertLessEqual(stream.read_bytes, 2 * tarfile.BLOCKSIZE)

    def test_the_scan_stops_at_the_end_marker(self):
        self.assertEqual(scan(member() + END + member('after')), 1)
        self.assertEqual(scan(member()), 1)

    def test_an_unreadable_header_is_refused(self):
        corrupt = bytearray(member('b'))
        corrupt[0] = ord('c')  # the checksum no longer matches
        self.refused('unreadable tar header', member() + bytes(corrupt) + END)


class Streams(unittest.TestCase):
    def test_compressed_archives_are_scanned_after_decompression(self):
        data = member() + member('b') + END
        with tempfile.TemporaryDirectory() as work:
            for name, compress in [('plain.tar', bytes), ('a.tar.gz', gzip.compress), ('a.tar.bz2', bz2.compress),
                                   ('a.tar.xz', lzma.compress)]:
                with self.subTest(name):
                    path = Path(work) / name
                    path.write_bytes(compress(data))
                    with release_tar.open_stream(path) as stream:
                        self.assertEqual(release_tar.scan(stream, 100, release_tar.INPUT_TYPES), 2)
                        stream.seek(0)
                        with tarfile.open(fileobj=stream, mode='r:') as tar:
                            self.assertEqual(tar.getnames(), ['a', 'b'])


if __name__ == '__main__':
    unittest.main()
