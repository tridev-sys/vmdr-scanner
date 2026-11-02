"""Benchmark answer key: every planted flaw, generated deterministically.

Each flaw is one endpoint of the benchmark app with one exploitable input. Parameter names vary on
purpose, so a scanner that only tries the names its templates know about misses some flaws.

Classes: sqli, xss, ssti, lfi, rce, ssrf (query parameter), idor and exposure (path based).
"""

PARAMS = ["q", "id", "search", "file", "name", "url", "host", "page", "path", "input", "data", "ref"]
QUERY_CLASSES = ["sqli", "xss", "ssti", "lfi", "rce", "ssrf"]
PATH_CLASSES = ["idor", "exposure"]


def flaws() -> list[dict]:
    items: list[dict] = []
    for cls in QUERY_CLASSES:
        for n, param in enumerate(PARAMS):
            items.append({
                "id": f"{cls}-{param}",
                "cls": cls,
                "path": f"/bm/{cls}/{n}",
                "param": param,
                "location": "query",
            })
    for cls in PATH_CLASSES:
        for n in range(len(PARAMS) // 2):
            items.append({
                "id": f"{cls}-{n}",
                "cls": cls,
                "path": f"/bm/{cls}/{n}",
                "param": None,
                "location": "path",
            })
    return items


def answer_key() -> dict:
    return {"version": 1, "flaws": flaws()}


if __name__ == "__main__":
    import json
    import pathlib

    out = pathlib.Path(__file__).with_name("answer_key.json")
    out.write_text(json.dumps(answer_key(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(flaws())} flaws to {out}")
