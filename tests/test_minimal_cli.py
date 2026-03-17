import pathlib
import json
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CLI = ROOT / "fasdisasm_min.py"


class MinimalCliTest(unittest.TestCase):
    def parse_streams(self, path: pathlib.Path) -> list[tuple[str, bytes]]:
        data = path.read_bytes()
        reader = __import__("fasdisasm_min")
        module = reader
        stream_reader = module.ByteReader(data)
        first_char = module.skip_whitespace_ex(stream_reader)

        if first_char == "#":
            stream_reader.read_until(b"#")
            function_length = int(stream_reader.read_until(b"m").decode("latin-1"))
            function_stream, *_ = module.extract_stream(stream_reader, function_length)
            stream_reader.read_until(b"#")
            resource_length = int(stream_reader.read_until(b"m").decode("latin-1"))
            resource_stream, *_ = module.extract_stream(stream_reader, resource_length)
        else:
            while stream_reader.tell() < min(len(data), 1024):
                char = stream_reader.read_char()
                if not (char.isalnum() or char == "-"):
                    break
            function_length = module.read_number(stream_reader)
            function_stream, *_ = module.extract_stream(stream_reader, function_length)
            resource_length = module.read_number(stream_reader)
            resource_stream, *_ = module.extract_stream(stream_reader, resource_length)

        return [("function", function_stream), ("resource", resource_stream)]

    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(CLI), *args],
            cwd=str(ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_protected_lisp_decrypt_matches_expected_fixture(self) -> None:
        source = ROOT / "example" / "AutoCAD PROTECTED LISP file" / "3darray_ENC.lsp"
        expected = ROOT / "example" / "AutoCAD PROTECTED LISP file" / "3darray_ENC_Dec.lsp"

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = pathlib.Path(tmpdir)
            input_copy = tmpdir_path / source.name
            output_path = tmpdir_path / "decoded.lsp"
            shutil.copy2(source, input_copy)

            proc = self.run_cli(str(input_copy), "--output", str(output_path))

            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            self.assertTrue(output_path.exists())
            self.assertEqual(output_path.read_bytes(), expected.read_bytes())

    def test_vlx_split_extracts_files(self) -> None:
        source = ROOT / "example" / "_vlx" / "test.VLX"

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = pathlib.Path(tmpdir)
            output_dir = tmpdir_path / "split"

            proc = self.run_cli(str(source), "--output", str(output_dir))

            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            extracted_files = sorted(path for path in output_dir.rglob("*") if path.is_file())
            self.assertGreater(len(extracted_files), 0)
            self.assertTrue(any(path.suffix.lower() == ".fas" for path in extracted_files))

    def test_fas_extracts_streams(self) -> None:
        source = ROOT / "example" / "3darray.fas"

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = pathlib.Path(tmpdir)
            output_dir = tmpdir_path / "fas_out"

            proc = self.run_cli(str(source), "--output", str(output_dir))

            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            fct_path = output_dir / "3darray.fas.fct"
            res_path = output_dir / "3darray.fas.res"
            metadata_path = output_dir / "3darray.fas.metadata.json"
            dump_path = output_dir / "3darray.fas.txt"
            semantic_path = output_dir / "3darray.fas.sem.txt"
            pseudo_path = output_dir / "3darray.fas.pseudo.lsp"
            lsp_path = output_dir / "3darray.fas.lsp"

            self.assertTrue(fct_path.exists())
            self.assertTrue(res_path.exists())
            self.assertTrue(metadata_path.exists())
            self.assertTrue(dump_path.exists())
            self.assertTrue(semantic_path.exists())
            self.assertTrue(pseudo_path.exists())
            self.assertTrue(lsp_path.exists())
            self.assertGreater(fct_path.stat().st_size, 0)
            self.assertGreater(res_path.stat().st_size, 0)

            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual(metadata["kind"], "fas")
            self.assertEqual(metadata["version"], "FAS4-FILE")
            self.assertEqual(metadata["function_stream_length"], fct_path.stat().st_size)
            self.assertEqual(metadata["resource_stream_length"], res_path.stat().st_size)
            dump_text = dump_path.read_text(encoding="utf-8")
            self.assertIn("[function_stream]", dump_text)
            self.assertIn("DEFUN", dump_text)
            self.assertIn("LD_STR", dump_text)
            self.assertIn("IVARS", dump_text)
            self.assertIn("LD_LIST", dump_text)
            self.assertNotIn("OP_0x", dump_text)
            self.assertNotIn("DECODE_ERROR", dump_text)
            semantic_text = semantic_path.read_text(encoding="utf-8")
            self.assertIn("[resource_stream]", semantic_text)
            self.assertIn("SET G[", semantic_text)
            self.assertIn("CALL", semantic_text)
            self.assertIn("DEF_FUNC_FROM_STACK", semantic_text)
            self.assertIn("BRANCH if", semantic_text)
            self.assertNotIn("SEMANTIC_ERROR", semantic_text)
            self.assertNotIn("PAD_00", semantic_text)
            pseudo_text = pseudo_path.read_text(encoding="utf-8")
            lsp_text = lsp_path.read_text(encoding="utf-8")
            self.assertIn("(defun AI_ABORT", pseudo_text)
            self.assertIn("(defun C:3DARRAY", pseudo_text)
            self.assertIn("(defun-ref C:3DARRAY", pseudo_text)
            self.assertIn(":L_", pseudo_text)
            self.assertIn("(block :entry", pseudo_text)
            self.assertIn("(block :L_", pseudo_text)
            self.assertIn("(cond", pseudo_text)
            self.assertIn("(case-dispatch ", pseudo_text)
            self.assertIn("(if ", pseudo_text)
            self.assertIn("(unless ", pseudo_text)
            self.assertIn("(setq G[", pseudo_text)
            self.assertNotIn("(func ", pseudo_text)
            self.assertNotIn("(defun-ref", lsp_text)
            self.assertIn("; decompiled fas FAS4-FILE", lsp_text)
            self.assertNotIn(";;; [resource_stream]", lsp_text)
            self.assertNotIn("; :entry", lsp_text)
            self.assertNotIn("; :L_", lsp_text)
            self.assertNotIn("; preds=", lsp_text)
            self.assertNotIn("branch-if nil", lsp_text)
            self.assertNotIn("branch-if T", lsp_text)
            self.assertNotIn("(if T", lsp_text)
            self.assertNotIn("(if nil", lsp_text)
            self.assertNotIn("(MODES )", lsp_text)
            self.assertNotIn("(P-ARRAY )", lsp_text)
            self.assertNotIn("(R-ARRAY )", lsp_text)
            self.assertIn("(block :entry", lsp_text)
            self.assertNotIn("\n)\n  (setq G[137] *ERROR*)\n", lsp_text)
            self.assertIn("(defun AI_ABORT", lsp_text)
            self.assertIn("(defun fn_0019", lsp_text)
            self.assertIn("(setq G[137] *ERROR*)", lsp_text)
            block_names = set(re.findall(r"^\s*\(block ([^\s)]+)", lsp_text, flags=re.MULTILINE))
            goto_targets = set(re.findall(r"\(goto (:L_[0-9A-F]+)\)", lsp_text))
            self.assertTrue(goto_targets.issubset(block_names), sorted(goto_targets - block_names))
            self.assertIn(":L_09CD", block_names)
            self.assertNotIn("(block :L_0254", lsp_text)
            self.assertNotIn("(block :L_08C3", lsp_text)
            self.assertNotIn("(block :L_0974", lsp_text)
            self.assertNotIn("(block :L_097A", lsp_text)
            self.assertNotIn("(block :L_098C", lsp_text)
            self.assertIn("(goto :L_0999)", lsp_text)
            pseudo_g_count = len(re.findall(r"G\[\d+\]", pseudo_text))
            lsp_g_count = len(re.findall(r"G\[\d+\]", lsp_text))
            self.assertLess(lsp_g_count, pseudo_g_count)

    def test_control_flow_targets_land_on_instruction_boundaries(self) -> None:
        import fasdisasm_min as module

        flow_kinds = {"BRANCH", "GOTO", "CALL_BY_OFFSET", "CALL_VL_ARX", "JMP2_NOPOP", "CONTINUE_AT"}
        samples = [
            ROOT / "example" / "3darray.fas",
            ROOT / "example" / "duall.fas",
            ROOT / "example" / "vlinit.fsl",
        ]

        for sample in samples:
            if not sample.exists():
                continue
            for label, stream in self.parse_streams(sample):
                starts: set[int] = set()
                instructions: list[tuple[int, str, dict[str, object]]] = []
                offset = 0
                while offset < len(stream):
                    next_offset, kind, payload = module.parse_semantic_instruction(stream, offset)
                    starts.add(offset)
                    instructions.append((offset, kind, payload))
                    self.assertGreater(next_offset, offset, f"{sample.name} {label} stalled at {offset:#x}")
                    offset = next_offset

                bad_targets: list[tuple[int, str, int]] = []
                for offset, kind, payload in instructions:
                    if kind not in flow_kinds:
                        continue
                    target = int(payload["target"])
                    if kind in {"CALL_BY_OFFSET", "CALL_VL_ARX", "JMP2_NOPOP", "CONTINUE_AT"}:
                        if 0 <= target < len(stream) and target not in starts:
                            bad_targets.append((offset, kind, target))
                        continue
                    if target < 0 or target > len(stream):
                        bad_targets.append((offset, kind, target))
                    elif target < len(stream) and target not in starts:
                        bad_targets.append((offset, kind, target))

                self.assertEqual([], bad_targets, f"{sample.name} {label} misaligned targets: {bad_targets[:10]}")

    def test_fsl_extracts_streams(self) -> None:
        source = ROOT / "example" / "vlinit.fsl"

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = pathlib.Path(tmpdir)
            output_dir = tmpdir_path / "fsl_out"

            proc = self.run_cli(str(source), "--output", str(output_dir))

            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            metadata_path = output_dir / "vlinit.fsl.metadata.json"
            dump_path = output_dir / "vlinit.fsl.txt"
            semantic_path = output_dir / "vlinit.fsl.sem.txt"
            pseudo_path = output_dir / "vlinit.fsl.pseudo.lsp"
            self.assertTrue(metadata_path.exists())
            self.assertTrue(dump_path.exists())
            self.assertTrue(semantic_path.exists())
            self.assertTrue(pseudo_path.exists())
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual(metadata["kind"], "fsl")
            self.assertGreater(metadata["function_stream_length"], 0)
            self.assertGreater(metadata["resource_stream_length"], 0)
            self.assertIn("[resource_stream]", dump_path.read_text(encoding="utf-8"))
            self.assertIn("[resource_stream]", semantic_path.read_text(encoding="utf-8"))
            self.assertIn("(defun-ref require", pseudo_path.read_text(encoding="utf-8"))

    def test_large_fas_with_truncated_tail_still_generates_outputs(self) -> None:
        source = ROOT / "example" / "duall.fas"

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = pathlib.Path(tmpdir)
            output_dir = tmpdir_path / "duall_out"

            proc = self.run_cli(str(source), "--output", str(output_dir))

            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            dump_path = output_dir / "duall.fas.txt"
            semantic_path = output_dir / "duall.fas.sem.txt"
            pseudo_path = output_dir / "duall.fas.pseudo.lsp"
            lsp_path = output_dir / "duall.fas.lsp"
            self.assertTrue(dump_path.exists())
            self.assertTrue(semantic_path.exists())
            self.assertTrue(pseudo_path.exists())
            self.assertTrue(lsp_path.exists())
            dump_text = dump_path.read_text(encoding="utf-8")
            self.assertIn("LD_REAL '6.25'", dump_text)
            self.assertNotIn("DECODE_ERROR", dump_text)
            pseudo_text = pseudo_path.read_text(encoding="utf-8")
            lsp_text = lsp_path.read_text(encoding="utf-8")
            self.assertNotIn("Traceback", pseudo_text)
            self.assertNotIn("stack-empty", pseudo_text)
            self.assertIn("(defun-ref", pseudo_text)
            self.assertIn("; decompiled fas FAS4-FILE", lsp_text)


if __name__ == "__main__":
    unittest.main()
