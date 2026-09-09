import tempfile
import unittest
import zipfile
from pathlib import Path

from oversight.worker_archive import extract_worker_archive


class WorkerArchiveTest(unittest.TestCase):
    def bundle(self, entries):
        root = Path(tempfile.mkdtemp(prefix='worker-archive-'))
        archive = root / 'worker.zip'
        with zipfile.ZipFile(archive, 'w') as output:
            for name, content in entries:
                output.writestr(name, content)
        return root, archive, root / 'out'

    def test_extracts_windows_separator_archive_into_canonical_paths(self):
        root, archive, output = self.bundle([('sources\\source-queue.json', '{}'), ('state.learning.json', '{}')])
        self.addCleanup(lambda: __import__('shutil').rmtree(root))
        self.assertEqual(extract_worker_archive(archive, output), ['sources/source-queue.json', 'state.learning.json'])
        self.assertEqual((output / 'sources' / 'source-queue.json').read_text(), '{}')

    def test_rejects_extra_traversal_duplicate_and_missing_entries(self):
        cases = [
            [('sources/source-queue.json', '{}'), ('state.learning.json', '{}'), ('extra.txt', 'x')],
            [('sources/source-queue.json', '{}'), ('../state.learning.json', '{}')],
            [('sources/source-queue.json', '{}'), ('one.learning.json', '{}'), ('two.learning.json', '{}')],
            [('sources/source-queue.json', '{}')],
        ]
        for entries in cases:
            with self.subTest(entries=[name for name, _ in entries]):
                root, archive, output = self.bundle(entries)
                self.addCleanup(lambda root=root: __import__('shutil').rmtree(root))
                with self.assertRaises(ValueError):
                    extract_worker_archive(archive, output)


if __name__ == '__main__':
    unittest.main()
