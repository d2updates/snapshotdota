#!/usr/bin/env python3
import hashlib
from fnmatch import fnmatch
import sys, os, io

def sha1stream(fd):
    sha1 = hashlib.sha1()
    while True:
        block = fd.read(2048)
        if not block:
            break
        sha1.update(block)
    return sha1.hexdigest()

if __name__ == '__main__':
    exclude = ['*/cache_*', '*/guides/workshop/*', '*.vpk']
    root = sys.argv[1]
    checksums = []
    for dirn, dirs, files in os.walk(root):
        printdirn = dirn[len(root):]
        for fn in files:
            printfn = os.path.join(printdirn, fn).replace('\\', '/')
            fn = os.path.join(dirn, fn)
            fnm = fn.replace('\\', '/')
            skip = False
            for e in exclude:
                if fnmatch(fnm, e):
                    skip = True
            if skip:
                continue

            with open(fn, 'rb') as fd:
                sha = sha1stream(fd)
                checksums.append([sha, printfn])
    checksums.sort(key=lambda e: e[1])
    for l in checksums:
        print('%s %s' % (l[0], l[1]))
