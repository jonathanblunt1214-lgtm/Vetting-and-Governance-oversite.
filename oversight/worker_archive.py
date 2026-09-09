import json
import os
import shutil
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath

MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_TOTAL_BYTES = 200 * 1024 * 1024


def normalized(name):
    return name.replace('\\', '/')


def extract_worker_archive(archive, output):
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise ValueError('Worker archive output must start empty.')
    queue = None
    learning = None
    selected = []
    seen = set()
    total = 0
    with zipfile.ZipFile(archive) as bundle:
        for info in bundle.infolist():
            name = normalized(info.filename)
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts:
                raise ValueError('Worker archive contains an unsafe path.')
            if name == 'sources/':
                continue
            if name in seen:
                raise ValueError('Worker archive contains a duplicate entry.')
            seen.add(name)
            if info.flag_bits & 0x1:
                raise ValueError('Worker archive entries must not be encrypted.')
            if stat.S_ISLNK(info.external_attr >> 16):
                raise ValueError('Worker archive entries must not be symbolic links.')
            if info.file_size > MAX_FILE_BYTES:
                raise ValueError('Worker archive entry exceeds the extraction bound.')
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise ValueError('Worker archive exceeds the total extraction bound.')
            if name == 'sources/source-queue.json':
                if queue is not None:
                    raise ValueError('Worker archive contains a duplicate queue.')
                queue = (info, name)
            elif len(path.parts) == 1 and name.endswith('.learning.json'):
                if learning is not None:
                    raise ValueError('Worker archive contains multiple learning envelopes.')
                learning = (info, name)
            else:
                raise ValueError(f'Worker archive contains an unexpected structural entry: {name}')
        if queue is None or learning is None:
            raise ValueError('Worker archive must contain one queue and one learning envelope.')
        for info, name in (queue, learning):
            target = output.joinpath(*PurePosixPath(name).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with bundle.open(info) as source, os.fdopen(descriptor, 'wb') as destination:
                shutil.copyfileobj(source, destination, length=1024 * 1024)
            selected.append(name)
    print(json.dumps({'extracted': selected, 'totalBytes': total}))
    return selected


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('Usage: worker_archive.py <archive.zip> <empty-output-directory>')
    try:
        extract_worker_archive(sys.argv[1], sys.argv[2])
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        raise SystemExit(str(error)) from error
