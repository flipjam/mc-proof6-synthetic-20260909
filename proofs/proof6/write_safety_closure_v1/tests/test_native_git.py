"""Real Git processes and local bare repos only; no network/remotes outside scratch."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class NativeGit(unittest.TestCase):
    def test_nonforce_sibling_has_one_canonical_winner(self):
        root = Path(__file__).resolve().parents[1]
        scratch = root / 'tests' / '.native-scratch'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='sibling-', dir=scratch) as location:
            path = Path(location).resolve()
            self.assertTrue(path.is_relative_to(scratch.resolve()))
            source, provider = path/'source.git', path/'provider.git'
            env = dict(os.environ, GIT_AUTHOR_NAME='Offline Fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid',
                       GIT_COMMITTER_NAME='Offline Fixture', GIT_COMMITTER_EMAIL='fixture@example.invalid',
                       GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_ALLOW_PROTOCOL='file', GIT_TERMINAL_PROMPT='0')
            def git(repo, *args, data=None, check=True):
                return subprocess.run(['git', '-C', str(repo), *args], input=data, text=True,
                    capture_output=True, env=env, timeout=20, check=check)
            for repo in (source, provider):
                subprocess.run(['git', 'init', '--bare', str(repo)], env=env, capture_output=True, check=True, timeout=20)
            blob = git(source, 'hash-object', '-w', '--stdin', data='offline record\n').stdout.strip()
            tree = git(source, 'mktree', data=f'100644 blob {blob}\toperation.json\n').stdout.strip()
            parent = git(source, 'commit-tree', tree, data='offline SEND_ARMED fixture\n').stdout.strip()
            first = git(source, 'commit-tree', tree, '-p', parent, data='completion one\n').stdout.strip()
            second = git(source, 'commit-tree', tree, '-p', parent, data='completion two\n').stdout.strip()
            ref = 'refs/heads/offline-journal-fixture'
            git(source, 'push', str(provider), parent+':'+ref)
            git(source, 'push', str(provider), second+':'+ref)
            loser = git(source, 'push', str(provider), first+':'+ref, check=False)
            self.assertNotEqual(loser.returncode, 0)
            self.assertEqual(git(provider, 'rev-parse', ref).stdout.strip(), second)
            self.assertEqual(git(source, 'rev-parse', first+'^').stdout.strip(), parent)
            self.assertEqual(git(source, 'rev-parse', second+'^').stdout.strip(), parent)
        scratch.rmdir()


if __name__ == '__main__':
    unittest.main(verbosity=2)
