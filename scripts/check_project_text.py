from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN_TERMS = [
    "\u56fd\u5956",
    "\u7b54\u8fa9",
    "\u4fe1\u5b89\u8d5b",
    "national_award",
    "Task22",
]

MOJIBAKE_PATTERNS = ["????", "\ufffd"]
CHECK_SUFFIXES = {".md", ".py", ".ps1", ".ts", ".tsx", ".json", ".yaml", ".yml"}
SKIP_DIRS = {".git", "node_modules", "frontend/dist", "__pycache__", ".pytest_cache", "venv", ".venv"}

def skip(path):
    rel = path.relative_to(ROOT).as_posix()
    return any(rel == d or rel.startswith(d + "/") for d in SKIP_DIRS)

def main():
    findings = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or skip(path) or path.suffix.lower() not in CHECK_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        rel = path.relative_to(ROOT).as_posix()

        for term in FORBIDDEN_TERMS:
            if term in text:
                findings.append((rel, "forbidden", term))

        for pattern in MOJIBAKE_PATTERNS:
            if pattern in text:
                findings.append((rel, "mojibake", pattern))

    if findings:
        print("Project text check findings:")
        for rel, kind, value in findings:
            print(f"- {rel}: {kind}: {value}")
    else:
        print("Project text check passed.")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
