"""Helpers shared by the runtime-service subprocess fixtures."""
import os
from pathlib import Path
import tempfile


def atomic_content_marker(path, content, before_publish=None):
    """Publish a complete content marker at once, optionally pausing before link."""
    target = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=f'.{target.name}.', dir=target.parent)
    try:
        with os.fdopen(fd, 'w', encoding='ascii') as marker:
            marker.write(content)
            marker.flush()
            os.fsync(marker.fileno())
        if before_publish is not None:
            before_publish(Path(temporary), target)
        os.link(temporary, target)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
