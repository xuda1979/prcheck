#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成「源代码.txt」（软件著作权申请用样本）。

读取 ../prcheck 与 ../action 下的真实源码，删除注释、空行与文档字符串后，
按「核心规则引擎在前、CLI/管线在后」的顺序排列；取前 1500 行 + 后 1500 行
（= 前30页 + 后30页，每页 50 行），拼接为 全文 60 页 3000 行 的可识别程序
片段。每页页眉为左对齐「prcheck V1.0」，页脚为「第 N 页」。

A4 纵向、正文宋体五号的要求在打印/转 PDF 时按此设定即可，TXT 源文件本身
不嵌入字体信息。

运行：python3 gen_source.py
"""
from __future__ import annotations

import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent
OUT = ROOT / "源代码.txt"
HEADER = "prcheck V1.0"
LINES_PER_PAGE = 50
PAGES = 60
FRONT_PAGES = PAGES // 2

# 题头说明：随申请材料一并提交，注明申请人与开发单位。
HEAD_BLOCK = [
    "prcheck V1.0 源代码（按 A4 纵向、宋体五号、每页 50 行排版）",
    "=" * 70,
    "软件名称：prcheck（PR 安全清单与 OpenAPI 变更门禁分析工具）  版本号：V1.0",
    "著作权人/申请人：许达    开发单位：中国移动研究院",
    "源程序总量：约 5315 行（去除空行、注释与文档字符串后约 3435 行），"
    "本申请共提交 60 页。",
    "排版说明：每页第一行为页眉『prcheck V1.0』（左对齐），其后为 50 行源代码，",
    "最后一行为页脚页码。请使用 A4 纵向纸、正文宋体五号（10.5 磅）、",
    "页边距上下 2.54cm 打印。源代码按模块顺序节选如下：",
    "=" * 70,
]

# 模块展示顺序：核心规则引擎与差异/OpenAPI 分析在前，CLI 与 GitHub 集成在后。
ORDER = [
    "prcheck/rules.py",
    "prcheck/engine.py",
    "prcheck/issues.py",
    "prcheck/diff.py",
    "prcheck/openapi.py",
    "prcheck/cache.py",
    "prcheck/render.py",
    "prcheck/cli.py",
    "prcheck/llm.py",
    "prcheck/__init__.py",
    "prcheck/__main__.py",
    "action/run_action.py",
    "action/gh_comment.py",
    "action/webhook.py",
]


def stripped_lines(path: pathlib.Path, labels: bool = True) -> list[str]:
    """去注释、去空行、去 docstring 后的代码行；label=True 时前置模块名行。"""
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        lines = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    else:
        skip: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.body and isinstance(node.body[0], ast.Expr):
                    e = node.body[0]
                    if isinstance(e.value, ast.Constant) and isinstance(e.value.value, str):
                        skip.update(range(e.lineno, (e.end_lineno or e.lineno) + 1))
        lines = [
            l
            for i, l in enumerate(text.splitlines(), 1)
            if l.strip() and not l.strip().startswith("#") and i not in skip
        ]
    if not labels:
        return lines
    rel = path.relative_to(ROOT.parent)
    return ["# ==== %s ====" % rel] + lines


def main() -> None:
    ordered: list[pathlib.Path] = []
    for rel in ORDER:
        ordered.append(ROOT.parent / rel)
    # 追加未列入 ORDER 的模块（保持稳定顺序）
    seen = {p for p in ordered}
    for sub in ("prcheck", "action"):
        for p in sorted((ROOT.parent / sub).glob("*.py")):
            if "__pycache__" not in p.parts and p not in seen:
                ordered.append(p)

    flow: list[str] = []
    for p in ordered:
        if p.exists():
            flow.extend(stripped_lines(p))

    total = len(flow)
    target = PAGES * LINES_PER_PAGE  # 3000
    if total > target:
        half = target // 2
        flow = flow[:half] + flow[total - half:]  # 前30页 + 后30页
    while len(flow) < target:
        flow.append("")
    flow = flow[:target]

    pages = [flow[i * LINES_PER_PAGE:(i + 1) * LINES_PER_PAGE]
             for i in range(PAGES)]
    out: list[str] = list(HEAD_BLOCK) + [""]
    for idx, page in enumerate(pages, 1):
        out.append(HEADER)
        out.extend(page)
        out.append("第 %d 页" % idx)
    OUT.write_text("\n".join(out) + "\n", encoding="utf-8")
    sys.stdout.write(
        "OK: total=%d sample=%d pages=%d -> %s\n"
        % (total, len(flow), PAGES, OUT)
    )


if __name__ == "__main__":
    import sys
    main()
