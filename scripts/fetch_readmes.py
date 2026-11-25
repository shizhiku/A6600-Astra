import base64, json, os, sys, urllib.parse, urllib.request

REPOS = [
    "HabibAlShaikh/anlock6600",
    "madwyn/fwtool_ori",
    "suxia2008/sony-a6000-fw-toolkit",
    "ivica00/sony-a6400-research",
    "cokeenet/zve10-qemu",
    "CliffVale/sony-a6000-firmware-research",
]
NAMES = ["README.md", "readme.md", "README.MD", "README.rst"]

def get(url):
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "dsh-review",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

sys.stdout.reconfigure(encoding="utf-8")
os.makedirs("fw_repos", exist_ok=True)
for repo in REPOS:
    text = None
    for nm in NAMES:
        try:
            d = get(f"https://api.github.com/repos/{repo}/contents/{nm}")
            text = base64.b64decode(d["content"]).decode("utf-8", "replace")
            break
        except Exception:
            continue
    slug = repo.replace("/", "__")
    print("=" * 100)
    print(repo)
    if text is None:
        print("  (no README found)")
        continue
    with open(os.path.join("fw_repos", slug + ".md"), "w", encoding="utf-8") as f:
        f.write(text)
    print(text[:3500])
