"""Conservative capacity checks for a selected hugetlbfs mount."""
import os
from pathlib import Path
import re


def _unescape_mount_field(value):
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), value)


def _parse_size(value):
    match = re.fullmatch(r'([0-9]+)([KMGTPE]?)(?:B)?', value, re.IGNORECASE)
    if not match:
        raise ValueError('invalid hugetlbfs size: ' + value)
    scale = {'': 1, 'K': 1024, 'M': 1024**2, 'G': 1024**3,
             'T': 1024**4, 'P': 1024**5, 'E': 1024**6}[match.group(2).upper()]
    return int(match.group(1)) * scale


def _mount_for(path, mountinfo_text):
    target = Path(path).resolve(strict=True)
    matches = []
    for line in mountinfo_text.splitlines():
        before, separator, after = line.partition(' - ')
        if not separator:
            continue
        left, right = before.split(), after.split()
        if len(left) < 6 or len(right) < 3 or right[0] != 'hugetlbfs':
            continue
        mountpoint = Path(_unescape_mount_field(left[4]))
        try:
            if os.path.commonpath((str(target), str(mountpoint))) != str(mountpoint):
                continue
        except ValueError:
            continue
        options = set(left[5].split(',')) | set(right[2].split(','))
        matches.append((len(mountpoint.parts), mountpoint, options))
    if not matches:
        raise ValueError('selected directory is not on a hugetlbfs mount')
    _, mountpoint, options = max(matches, key=lambda item: item[0])
    return mountpoint, options


def _hugepage_class(sysfs_root, page_size):
    if page_size % 1024:
        raise ValueError('selected hugepage size is not a whole number of KiB')
    directory = Path(sysfs_root) / f'hugepages-{page_size // 1024}kB'
    free = int((directory / 'free_hugepages').read_text().strip())
    reserved = int((directory / 'resv_hugepages').read_text().strip())
    return free, reserved


def _capacity_error(requested_bytes, page_size, free_pages, reserved_pages,
                    mount_free_pages=None):
    if requested_bytes <= 0 or page_size <= 0 or min(free_pages, reserved_pages) < 0:
        return 'invalid hugepage capacity data'
    needed = (requested_bytes + page_size - 1) // page_size
    available = max(0, free_pages - reserved_pages)
    if available < needed:
        return (f'selected {page_size}-byte hugepage pool has {available} unreserved pages; '
                f'{needed} are needed for {requested_bytes} bytes')
    if mount_free_pages is not None and mount_free_pages < needed:
        return (f'selected hugetlbfs mount has {mount_free_pages} quota pages available; '
                f'{needed} are needed for {requested_bytes} bytes')
    return None


def hugepage_capacity_error(path, requested_bytes, *, mountinfo_path='/proc/self/mountinfo',
                            sysfs_root='/sys/kernel/mm/hugepages'):
    """Return a conservative prerequisite error, or None when capacity is sufficient.

    The mount's statvfs block size identifies its page class. Global pool counts
    come from the matching sysfs hstate, not HugePages_Free for the default class.
    Unbounded hugetlbfs mounts may report zero or -1 blocks; that means no mount
    quota, so only an explicitly bounded or finite statfs quota is checked.
    """
    directory = Path(path)
    if not directory.is_dir():
        return 'selected hugepage directory does not exist'
    if not os.access(directory, os.W_OK):
        return 'selected hugepage directory is not writable'
    try:
        mountinfo = Path(mountinfo_path).read_text()
        _, options = _mount_for(directory, mountinfo)
        stats = os.statvfs(directory)
        page_size = int(stats.f_bsize or stats.f_frsize)
        explicit_page_size = next((item.split('=', 1)[1] for item in options
                                   if item.startswith('pagesize=')), None)
        if explicit_page_size is not None:
            configured_page_size = _parse_size(explicit_page_size)
            if page_size and page_size != configured_page_size:
                raise ValueError('hugetlbfs pagesize option disagrees with statvfs block size')
            page_size = configured_page_size
        if page_size <= 0:
            raise ValueError('cannot determine selected hugetlbfs page size')
        free_pages, reserved_pages = _hugepage_class(sysfs_root, page_size)
        blocks = int(stats.f_blocks)
        unbounded_blocks = blocks in (0, -1, (1 << 64) - 1)
        bounded = (any(item.startswith('size=') for item in options) or
                   (blocks > 0 and not unbounded_blocks))
        mount_free_pages = int(stats.f_bavail) if bounded else None
        return _capacity_error(requested_bytes, page_size, free_pages, reserved_pages,
                               mount_free_pages)
    except (OSError, ValueError, OverflowError) as error:
        return 'cannot verify selected hugetlbfs capacity: ' + str(error)
