#!/usr/bin/env python3
from struct import pack, unpack, calcsize
from binascii import hexlify
import os.path, os
import argparse
from fnmatch import fnmatch
import io
import hashlib
import zlib
import sys
#import cProfile

VPK_NOT_IN_ARCHIVE = 0x7FFF

class VPKFile(object):
    header = None
    tree = None
    basename = None

    arch_fds = None

    def __init__(self):
        self.arch_fds = {}

    def get_fd(self, idx):
        if idx not in self.arch_fds:
            self.arch_fds[idx] = open('%s%03d.vpk' % (self.basename, idx), 'rb')
        return self.arch_fds[idx]

    def close(self):
        for (k, v) in arch_fds.items():
            v.close()
            del arch_fds[k]

    def open_entry(self, entry):
        return VPKIO(self, entry)


class VPKIO(io.IOBase):
    _entry = None
    _vpk = None
    _size = None
    pos = None
    def __init__(self, vpkd, entry):
        self.pos = 0
        self._entry = entry
        self._vpk = vpkd
        self._size = entry.preloadBytes + entry.entryLength

    def read(self, n=-1):
        if n == -1:
            return self.readall()
        start = self.pos
        end = start + n
        ps = self._entry.preloadBytes
        (seg1, seg2) = (None, None)
        if end <= ps:
            seg1 = (start, end)
        elif start < ps and ps < end:
            seg1 = (start, ps)
            seg2 = (0, min(end - ps, self._entry.entryLength))
        else:
            seg2 = (start - ps, min(end - ps, self._entry.entryLength))

        if seg1:
            seg1 = self._entry.preload[seg1[0]:seg1[1]]
        if seg2:
            if self._entry.archiveIndex != VPK_NOT_IN_ARCHIVE:
                fd = self._vpk.get_fd(self._entry.archiveIndex)
                fd.seek(self._entry.entryOffset + seg2[0])
                seg2 = fd.read(seg2[1] - seg2[0])
            else:
                seg2 = None
        if seg1 is None and seg2 is None:
            return None
        ret = (seg1 or b'') + (seg2 or b'')
        self.pos += len(ret)
        return ret

    def readall(self):
        if self._entry.archiveIndex == VPK_NOT_IN_ARCHIVE:
            return self._entry.preload
        ret = b''
        if self._entry.preload is not None:
            ret = self._entry.preload
        if self_entry.archiveIndex != VPK_NOT_IN_ARCHIVE:
            fd = self._vpk.get_fd(self._entry.archiveIndex)
            fd.seek(self._entry.entryOffset)
            ret += fd.read(self._entry.entryLength)
        self.pos = self._size
        return ret

    def readinto(self, fd):
        count = 0
        while True:
            block = self.read(2048)
            if not block:
                break
            count += fd.write(block)
        return count

    def seek(self, offset, whence=0):
        npos = self.pos
        if whence == 0:
            npos = offset
        elif whence == 1:
            npos += offset
        elif whence == 2:
            npos = self._size - offset
        self.pos = min(max(0, npos), self._size)
        return self.pos



class VPKHeader(object):
    version = None
    treeLength = None


class VPKHeader2(VPKHeader):
    footerLength = None
    Unknown1 = None
    Unknown2 = None
    Unknown3 = None


class VPKDirectoryEntry(object):
    crc = None
    preloadBytes = None
    archiveIndex = None
    entryOffset = None
    entryLength = None

    dir = None
    filename = None
    fullpath = None
    preload = None
    def __str__(self):
        return str([self.filename, self.crc, self.preloadBytes, self.archiveIndex, self.entryOffset, self.entryLength])


VPK_MAGIC = 0x55aa1234


def read_vpk_file(fname):
    '''
    given a filename, reads and parses a VPK file
    '''
    with open(fname, 'rb') as fd:
        header = read_vpk_header(fd)
        rawTree = fd.read(header.treeLength)
        if len(rawTree) != header.treeLength: raise Exception('Could not read tree')
        footer = None

        if isinstance(header, VPKHeader2):
            footer = fd.read(header.footerLength)
            if len(footer) != header.footerLength: raise Exception('Could not read footer')

        tree = read_vpk_tree(rawTree)

        ret = VPKFile()
        ret.header = header
        ret.tree = tree
        ret.basename = fname[:-7]
        return ret


def read_vpk_header(fd):
    '''
    given a file descriptor, reads VPK file header
    '''
    header = None
    magic = fd.read(4)
    if len(magic) < 4:
        raise Exception('Could not read magic, file is too small?')

    if unpack('I', magic)[0] != VPK_MAGIC:
        raise Exception('Bad VPK magic, not a VPK file?')

    version = fd.read(4)
    if len(version) < 4: raise Exception('file is too small?')
    (version,) = unpack('I', version)

    if version == 1:
        header = VPKHeader()
        header.version = version
        treeLength = fd.read(4)
        if len(treeLength) < 4: raise Exception('file is too small?')
        (header.treeLength,) = unpack('I', treeLength)

    elif version == 2:
        header = VPKHeader2()
        header.version = version
        fmt = '5I'
        rest = fd.read(calcsize(fmt))
        if len(rest) < calcsize(fmt): raise Exception('Could not read header')
        (header.treeLength, header.Unknown1, header.footerLength,
                header.Unknown2, header.Unknown3) = unpack(fmt, rest)

    else:
        raise Exception('Unsupported version')

    return header


def read_null_string(data):
    '''
    read null-terminated string from {data} bytearray starting at position {pos}
    '''
    buf = data.__raw
    pos = data.tell()
    end = None
    try:
        end = buf.index(0, pos) + 1
    except ValueError as e:
        end = len(buf)
    return data.read(end - pos)[:-1]

def read_vpk_tree(raw):
    data = io.BytesIO(raw)
    setattr(data, '__raw', raw)
    tree = []
    while True:
        ext = read_null_string(data)
        if not ext:
            break
        while True:
            path = read_null_string(data)
            if not path:
                break
            tree.extend(read_vpk_dir(data, ext, path))
    return tree


def read_vpk_dir(data, ext, path):
    content = []
    ext = b'' if ext == b' ' else b'.' + ext
    path = b'' if path == b' ' else path + b'/'

    while True:
        filename = read_null_string(data)
        if not filename:
            break

        entry = read_vpk_entry(data)
        entry.dir = path
        entry.filename = filename + ext
        entry.fullpath = path + filename + ext

        if entry.preloadBytes or entry.archiveIndex == VPK_NOT_IN_ARCHIVE:
            entry.preload = data.read(entry.preloadBytes)

        content.append(entry)
    return content


VPK_ENTRY_FMT = 'IHHIIH'
VPK_ENTRY_SIZE = calcsize(VPK_ENTRY_FMT)
def read_vpk_entry(data):
    raw = data.read(VPK_ENTRY_SIZE)
    entry = VPKDirectoryEntry()
    (entry.crc, entry.preloadBytes, entry.archiveIndex, entry.entryOffset,
            entry.entryLength, terminator) = unpack(VPK_ENTRY_FMT, raw)
    if terminator != 0xffff:
        raise Exception('bad VPK directory entry terminator')
    return entry

def iterlen(it):
    l = 0
    for x in it:
        l += len(x)
    return l

def stream_checksums(fd):
    sha = hashlib.sha1()
    crc = zlib.crc32(b'')
    while True:
        block = fd.read(2048)
        if not block:
            break
        sha.update(block)
        crc = zlib.crc32(block, crc)
    return [crc, sha.digest()]

def _calc_checksums(fil, tree):
    for s in tree:
        #print(fil.open_entry(s).readall())
        checksums = stream_checksums(fil.open_entry(s))
        fname = s.fullpath.decode('ascii')
        #crc = '%08x' % (checksums[0] & 0xFFFFFFFF)

        if checksums[0] != s.crc:
            sys.stderr.write('WARNING: incorrect checksum for file %s (%08x:%08x)\n' % \
                    (fname, s.crc, checksums[0]))
            #raise Exception()
        yield [hexlify(checksums[1]).decode('ascii'), fname]

def _stream_crc(fd):
    crc = zlib.crc32(b'')
    while True:
        block = fd.read(2048)
        if not block:
            break
        crc = zlib.crc32(block, crc)
    return crc

def main(argv):
    parser = argparse.ArgumentParser(description='PYVPK - reading and extracting vpk files')
    parser.add_argument('file', nargs=1, help='vpk file to process')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('-x', '--extract', dest='wildcard', nargs='*', help='wildcards for extracting')
    mode.add_argument('-t', '--verify', action='store_true',
                      help='verify integrity by checking crc32 of each file')
    mode.add_argument('-l', '--list', action='store_true',
                      help='list files in vpk')
    mode.add_argument('-c', '--checksums', action='store_true',
                      help='print crc32 and sha1 for each file in vpk')
    parser.add_argument('-S', '--no-sort', dest='nosort', action='store_true',
                        help='do not sort files when printing. may speed up output')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='verbose output')
    parser.add_argument('-d', '--destination', nargs=1, dest='dest',
                        help='destination directory for extraction')
    #parser.add_argument('-o', '--output', nargs=1,
    #                    help='if single file is extracted, specify file name')
    ns = parser.parse_args()

    if ns.list:
        vpkfile = read_vpk_file(ns.file[0])
        tree = vpkfile.tree
        if not ns.nosort:
            tree = sorted(tree, key=lambda e: e.fullpath)
        for f in tree:
            print(f.fullpath.decode('ascii'))

    if ns.wildcard is not None:
        dest = ns.dest[0] if ns.dest else '.'
        if not os.path.isdir(dest):
            sys.stdout.write('destination "%s" is not a directory' % dest)
            return 2
        vpkfile = read_vpk_file(ns.file[0])
        sortedTree = sorted(vpkfile.tree, key=lambda e: e.fullpath)
        for f in sortedTree:
            ofile = False
            fname = f.fullpath.decode('ascii')
            dname = f.dir.decode('ascii')
            if not ns.wildcard:
                ofile = True
            else:
                for w in ns.wildcard:
                    if fnmatch(fname, w):
                        ofile = True
                        break
            if ofile:
                if ns.verbose:
                    print(fname)
                ofile = os.path.join(dest, fname)
                odir = os.path.join(dest, dname)
                if os.path.exists(odir) and not os.path.isdir(odir):
                    raise Exception('%s exists and is not a directory!')
                if not os.path.exists(odir):
                    os.makedirs(odir)
                with open(ofile, 'wb') as fd:
                    vpkfile.open_entry(f).readinto(fd)

    if ns.checksums:
        vpkfile = read_vpk_file(ns.file[0])
        # optimize for serial reading
        sortedTree = sorted(vpkfile.tree, key=lambda e: (e.archiveIndex, e.entryOffset))
        checksums = _calc_checksums(vpkfile, sortedTree)
        if not ns.nosort:
            checksums = sorted(checksums, key=lambda e: e[1])
        for r in checksums:
            print(' '.join(r))

    if ns.verify:
        vpkfile = read_vpk_file(ns.file[0])
        badfiles = 0
        sortedTree = sorted(vpkfile.tree, key=lambda e: (e.archiveIndex, e.entryOffset))
        for f in sortedTree:
            crc = _stream_crc(vpkfile.open_entry(f))
            if crc != f.crc:
                badfiles += 1
                print('%s'.format(f.fullname.decode('')))
        if badfiles:
            sys.stderr.write('%d files are corrupted' % badfiles)
            return 1


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt as k:
        sys.exit(3)

