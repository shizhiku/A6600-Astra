import base64, json, os, sys, urllib.parse, urllib.request

OWNER, REPO, REF = "HabibAlShaikh", "anlock6600", "main"
FILES = [
    "scripts/extract_a6600.py",
    "docs/install-path.md",
    "docs/preload-path.md",
    "docs/uart-shell.md",
    "docs/implementation-plan.md",
    "manifests/sha256.txt",
    "research/manifests/a6600-files.txt",
]

def get(path):
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/contents/{urllib.parse.quote(path)}?ref={REF}"
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json", "User-Agent": "dsh-review"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

sys.stdout.reconfigure(encoding="utf-8")
for p in FILES:
    try:
        d = get(p)
        data = base64.b64decode(d["content"])
        dst = os.path.join("fw_repos", "anlock6600", p.replace("/", os.sep))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        open(dst, "wb").write(data)
        print(f"OK {len(data):7d} {p}")
    except Exception as e:
        print(f"FAIL {p} -> {e}")
