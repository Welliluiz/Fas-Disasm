import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXE = ROOT / "Fas-Disasm.exe"
INPUT_SAMPLE = ROOT / "example" / "3darray.fas"


@unittest.skipUnless(shutil.which("wine"), "wine not installed")
@unittest.skipUnless(os.environ.get("FAS_DISASM_RUN_WINE") == "1", "set FAS_DISASM_RUN_WINE=1 to run integration test")
class WineIntegrationTest(unittest.TestCase):
    def test_disasm_generates_output_files(self) -> None:
        self.assertTrue(EXE.exists(), "Fas-Disasm.exe is missing")
        self.assertTrue(INPUT_SAMPLE.exists(), "input sample is missing")

        with tempfile.TemporaryDirectory() as td:
            tmpdir = pathlib.Path(td)
            in_file = tmpdir / "sample.fas"
            shutil.copy2(INPUT_SAMPLE, in_file)

            cmd = ["wine", str(EXE), str(in_file)]
            proc = subprocess.run(
                cmd,
                cwd=str(ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=120,
                check=False,
            )

            # Tool exits are environment-dependent under wine; validate artifacts instead.
            out_txt = tmpdir / "sample.fas.txt"
            out_lsp = tmpdir / "sample.fas_.lsp"
            self.assertTrue(out_txt.exists(), f"expected output not found. exit={proc.returncode}")
            self.assertTrue(out_lsp.exists(), f"expected output not found. exit={proc.returncode}")


if __name__ == "__main__":
    unittest.main()
