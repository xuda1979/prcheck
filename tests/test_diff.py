"""Unit tests for the unified diff parser."""

from prcheck.diff import compute_stats, parse_diff

SAMPLE = """diff --git a/a.py b/a.py
index 123..456 100644
--- a/a.py
+++ b/a.py
@@ -1,3 +1,4 @@
 line1
-line2
+line2b
+line2c
 line3
"""


def test_parse_basic_count():
    files = parse_diff(SAMPLE)
    assert len(files) == 1
    fd = files[0]
    assert fd.old_path == "a.py"
    assert fd.new_path == "a.py"
    assert fd.added == 2
    assert fd.removed == 1


def test_line_numbers_new():
    files = parse_diff(SAMPLE)
    adds = list(files[0].added_texts())
    # first add line is line 2 in new file; second is line 3
    assert adds[0][0] == 2
    assert adds[1][0] == 3
    assert adds[0][1] == "line2b"
    assert adds[1][1] == "line2c"


def test_new_file_status():
    blob = (
        "diff --git a/new.py b/new.py\n"
        "new file mode 100644\n"
        "index 000..abc\n"
        "--- /dev/null\n"
        "+++ b/new.py\n"
        "@@ -0,0 +1,2 @@\n"
        "+import os\n"
        "+os.system('x')\n"
    )
    files = parse_diff(blob)
    assert files[0].status == "added"
    assert files[0].new_path == "new.py"
    assert files[0].added == 2


def test_stats():
    files = parse_diff(SAMPLE)
    st = compute_stats(files)
    assert st["insertions"] == 2
    assert st["deletions"] == 1
    assert st["files_changed"] == 1
