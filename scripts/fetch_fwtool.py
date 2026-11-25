import base64, json, os, sys, urllib.parse, urllib.request

OWNER, REPO, REF = "ma1co", "fwtool.py", "master"
FILES = [
    "fwtool/sony/fdat.py",
    "fwtool/sony/constants.py",
    "fwtool/sony/dat.py",
    "fwtool/io/__init__.py",
    "fwtool/util/__init__.py",
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
        dst = os.path.join("fw_repos", "fwtool", p.replace("/", os.sep))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        open(dst, "wb").write(data)
        print(f"OK {len(data):7d} {p}")
    except Exception as e:
        print(f"FAIL {p} -> {e}")
