import base64, json, os, sys, time, urllib.parse, urllib.request

OWNER, REPO, REF = "PCIEARIA", "A6400-Extra-Menu", "main"
OUT = "a6400em"
FILES = [
    "README.md",
    "CONTRIBUTING.md",
    "NOTICE",
    "THIRD_PARTY.md",
    "ACKNOWLEDGEMENTS.md",
    "CHANGELOG.md",
    "docs/部署與操作規範.md",
    "docs/編譯與目錄.md",
    "docs/開發與架構細節.md",
    "docs/功能狀態.md",
    "docs/授權說明.md",
    "docs/發佈檢查.md",
    "tools/pmca_deploy_v3_clite.py",
    "tools/build_autoexec_hook.py",
    "tools/check_public_tree.py",
    "camera/film_paths.h",
    "camera/Makefile.film",
    ".github/workflows/ci.yml",
]

def api(path):
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/contents/{urllib.parse.quote(path)}?ref={REF}"
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "dsh-review",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

os.makedirs(OUT, exist_ok=True)
ok = fail = 0
for p in FILES:
    try:
        d = api(p)
        data = base64.b64decode(d["content"])
        dst = os.path.join(OUT, p.replace("/", os.sep))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as f:
            f.write(data)
        print(f"OK   {len(data):7d}  {p}")
        ok += 1
    except Exception as e:
        print(f"FAIL           {p}  -> {e}")
        fail += 1
    time.sleep(0.3)
print(f"\nok={ok} fail={fail}")
