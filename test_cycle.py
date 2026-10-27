import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("cycle.py")


def call(*args, cwd=None):
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True)


class AuditCycleTest(unittest.TestCase):
    def test_merged_changes_passes_fixes_and_checkpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp) / "repo"
            root.mkdir()
            for argv in (("git", "init", "-q", "-b", "main"),
                         ("git", "config", "user.name", "Test"),
                         ("git", "config", "user.email", "test@example.com")):
                self.assertEqual(call(*argv, cwd=root).returncode, 0)

            source = root / "app.py"
            source.write_text("print('baseline')\n")
            call("git", "add", "app.py", cwd=root)
            call("git", "commit", "-qm", "known reviewed baseline", cwd=root)
            base = call("git", "rev-parse", "HEAD", cwd=root).stdout.strip()
            for name, content in (("Merge PR #12", "print('new feature')\n"),
                                  ("Merge PR #13", "print('unsafe')\n")):
                source.write_text(content)
                call("git", "commit", "-qam", name, cwd=root)

            initial = call(sys.executable, str(SCRIPT), "init", "--repo", str(root),
                           "--ref", "main", "--audited-commit", base)
            self.assertEqual(initial.returncode, 0, initial.stderr)
            status = self.status(root)
            self.assertEqual(status["state"], "unaudited")
            self.assertEqual(status["pending_commits"], 2)
            self.assertEqual(len(status["pending_changes"]), 2)

            fake = pathlib.Path(temp) / "fake-claude.py"
            fake.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "diff = sys.stdin.read()\n"
                "findings = [] if 'secured' in diff else [{"
                "'severity':'high','location':'app.py:1','issue':'Unsafe path',"
                "'suggestion':'Validate input'}]\n"
                "print(json.dumps({'subtype':'success','is_error':False,"
                "'structured_output':{'summary':'Security-only result','findings':findings,"
                "'limitations':['Diff only']},'modelUsage':{'claude-test':{"
                "'inputTokens':100,'outputTokens':20,'cacheCreationInputTokens':10,"
                "'cacheReadInputTokens':5}}}))\n"
            )
            fake.chmod(0o755)
            first = self.audit(root, fake, "v12")
            first_record = json.loads(first.read_text())
            self.assertEqual(first_record["total_tokens"], 135)
            self.assertEqual(len(first_record["audit"]["findings"]), 1)
            rejected = call(sys.executable, str(SCRIPT), "mark-audited", "--repo", str(root),
                            "--run", str(first))
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("findings", rejected.stderr)

            fake_source = fake.read_text()
            fake.write_text(fake_source.replace("if 'secured' in diff", "if True"))
            same_tip = self.audit(root, fake, "v12b")
            rejected_same_tip = call(sys.executable, str(SCRIPT), "mark-audited",
                                     "--repo", str(root), "--run", str(same_tip))
            self.assertNotEqual(rejected_same_tip.returncode, 0)
            self.assertIn("land fixes", rejected_same_tip.stderr)
            fake.write_text(fake_source)

            source.write_text("print('secured')\n")
            call("git", "commit", "-qam", "Fix security finding", cwd=root)
            second = self.audit(root, fake, "v13")
            current = self.status(root)
            self.assertEqual(current["pending_commits"], 3)
            self.assertEqual(current["measured_tokens_this_cycle"], 405)
            self.assertEqual(len(current["passes"]), 3)
            self.assertEqual(current["passes"][2]["findings"], 0)

            marked = call(sys.executable, str(SCRIPT), "mark-audited", "--repo", str(root),
                          "--run", str(second))
            self.assertEqual(marked.returncode, 0, marked.stderr)
            clean = self.status(root)
            self.assertEqual(clean["state"], "audited")
            self.assertEqual(clean["pending_commits"], 0)
            self.assertEqual(clean["last_completed_cycle"]["measured_tokens"], 405)
            self.assertEqual(len(clean["last_completed_passes"]), 3)
            self.assertEqual(clean["last_completed_passes"][2]["models"], ["claude-test"])

            source.write_text("print('another merge')\n")
            call("git", "commit", "-qam", "Merge PR #14", cwd=root)
            self.assertEqual(self.status(root)["state"], "unaudited")
            self.assertEqual(self.status(root)["pending_commits"], 1)

    def audit(self, root, fake, label):
        result = call(sys.executable, str(SCRIPT), "audit", "--repo", str(root),
                      "--claude", str(fake), "--label", label)
        self.assertEqual(result.returncode, 0, result.stderr)
        return pathlib.Path(result.stdout.splitlines()[0])

    def status(self, root):
        result = call(sys.executable, str(SCRIPT), "status", "--repo", str(root), "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)


if __name__ == "__main__":
    unittest.main()
