#!/usr/bin/env python3
"""Remove only fixtures created below the private reload-test workspace."""

import os
import re
import stat
import sys


ROOT_NAME = "workspace"
ALLOWED_TOP = re.compile(r"reload-(?:unit|owned)-[A-Za-z0-9_-]+\Z")
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def fail(message):
    print(message, file=sys.stderr)
    return 2


def owned(st):
    if st.st_uid != os.getuid():
        raise PermissionError("fixture ownership changed")


def remove_contents(directory_fd):
    for name in os.listdir(directory_fd):
        if name in ("", ".", "..") or "/" in name:
            raise ValueError("invalid directory entry")
        item = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        owned(item)
        if stat.S_ISDIR(item.st_mode):
            child_fd = os.open(name, DIR_FLAGS, dir_fd=directory_fd)
            try:
                child = os.fstat(child_fd)
                if (child.st_dev, child.st_ino) != (item.st_dev, item.st_ino):
                    raise PermissionError("fixture directory changed during cleanup")
                remove_contents(child_fd)
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=directory_fd)
        else:
            # unlinkat removes symlinks themselves; it never follows their target.
            os.unlink(name, dir_fd=directory_fd)


def target_components(value):
    if not value.startswith("/") or "\x00" in value:
        raise ValueError("target must be an absolute fixture path")
    raw = value.split("/")
    if any(part in (".", "..") for part in raw):
        raise ValueError("relative traversal is forbidden")
    parts = [part for part in raw if part]
    if parts[:2] != ["data", ROOT_NAME] or len(parts) < 3:
        raise ValueError("target is outside the fixture workspace")
    if not ALLOWED_TOP.fullmatch(parts[2]):
        raise ValueError("target is outside the fixture allowlist")
    return parts[2:]


def open_workspace():
    root_fd = os.open("/", DIR_FLAGS)
    try:
        data_fd = os.open("data", DIR_FLAGS, dir_fd=root_fd)
    finally:
        os.close(root_fd)
    try:
        return os.open(ROOT_NAME, DIR_FLAGS, dir_fd=data_fd)
    finally:
        os.close(data_fd)


def remove_target(workspace_fd, parts):
    parent_fd = os.dup(workspace_fd)
    try:
        for part in parts[:-1]:
            st = os.stat(part, dir_fd=parent_fd, follow_symlinks=False)
            owned(st)
            if not stat.S_ISDIR(st.st_mode):
                raise ValueError("fixture parent is not a real directory")
            child_fd = os.open(part, DIR_FLAGS, dir_fd=parent_fd)
            child_st = os.fstat(child_fd)
            if (child_st.st_dev, child_st.st_ino) != (st.st_dev, st.st_ino):
                os.close(child_fd)
                raise PermissionError("fixture parent changed during cleanup")
            os.close(parent_fd)
            parent_fd = child_fd

        name = parts[-1]
        try:
            st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return 0
        owned(st)
        if stat.S_ISDIR(st.st_mode):
            child_fd = os.open(name, DIR_FLAGS, dir_fd=parent_fd)
            try:
                current = os.fstat(child_fd)
                if (current.st_dev, current.st_ino) != (st.st_dev, st.st_ino):
                    raise PermissionError("fixture target changed during cleanup")
                remove_contents(child_fd)
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=parent_fd)
        else:
            os.unlink(name, dir_fd=parent_fd)
        return 0
    finally:
        os.close(parent_fd)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        return fail("usage: rm_tmp_file.sh ABSOLUTE_FIXTURE_PATH")
    try:
        parts = target_components(args[0])
        workspace_fd = open_workspace()
        try:
            return remove_target(workspace_fd, parts)
        finally:
            os.close(workspace_fd)
    except (OSError, ValueError) as error:
        return fail(str(error))


if __name__ == "__main__":
    sys.exit(main())
