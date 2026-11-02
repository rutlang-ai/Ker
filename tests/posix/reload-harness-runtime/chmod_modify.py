#!/usr/bin/env python3
"""Change modes only on owned files inside an allowlisted fixture tree."""

import os
import re
import stat
import sys

from rm_tmp_file import DIR_FLAGS, open_workspace, target_components


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2 or not re.fullmatch(r"0?[0-7]{3}", args[0]):
        print("usage: chmod_modify.sh OCTAL_MODE ABSOLUTE_FIXTURE_PATH", file=sys.stderr)
        return 2
    mode = int(args[0], 8)
    try:
        parts = target_components(args[1])
        root_fd = open_workspace()
        parent_fd = os.dup(root_fd)
        os.close(root_fd)
        try:
            for part in parts[:-1]:
                info = os.stat(part, dir_fd=parent_fd, follow_symlinks=False)
                if info.st_uid != os.getuid() or not stat.S_ISDIR(info.st_mode):
                    raise PermissionError("fixture parent is not an owned directory")
                child_fd = os.open(part, DIR_FLAGS, dir_fd=parent_fd)
                opened = os.fstat(child_fd)
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    os.close(child_fd)
                    raise PermissionError("fixture parent changed")
                os.close(parent_fd)
                parent_fd = child_fd
            name = parts[-1]
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if info.st_uid != os.getuid() or stat.S_ISLNK(info.st_mode):
                raise PermissionError("target is not an owned non-symlink fixture")
            flags = DIR_FLAGS if stat.S_ISDIR(info.st_mode) else os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(name, flags, dir_fd=parent_fd)
            try:
                opened = os.fstat(fd)
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise PermissionError("target changed")
                os.fchmod(fd, mode)
            finally:
                os.close(fd)
        finally:
            os.close(parent_fd)
        return 0
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
