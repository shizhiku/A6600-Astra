"""Create a NEW image copying an existing one and replacing one library file."""
from pathlib import Path
import argparse, shutil, subprocess, hashlib, json, sys
sys.path.insert(0, str(Path(__file__).parent))
R = Path('<WORKSPACE>')
P = argparse.ArgumentParser()
P.add_argument('--image', required=True); P.add_argument('--lib', required=True)
P.add_argument('--path', default='/lib/a5pFw.so'); P.add_argument('--output', required=True)
A = P.parse_args()
src = Path(A.image); dst = Path(A.output); lib = Path(A.lib)
if dst.exists() or src.resolve() == dst.resolve(): raise SystemExit('Output must be new')
D = dst.parent / (dst.stem + '-patch'); D.mkdir(exist_ok=False, parents=True)
cmd = D / 'commands'; cmd.write_text(f'rm {A.path}\nwrite {lib} {A.path}\nsif {A.path} mode 0100755\n')
shutil.copy2(src, dst)
x = subprocess.run(['debugfs', '-w', '-f', str(cmd), str(dst)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
(D / 'debugfs.log').write_bytes(x.stdout)
if x.returncode: raise SystemExit('debugfs failed')
from importlib.machinery import SourceFileLoader
u = SourceFileLoader('u', str(R / '02-脚本/97_ext2.py')).load_module()
f = u.Ext2(str(dst)); idx = {p: i for p, i, dr in f.walk() if not dr}
payload = f.read_file(idx[A.path])
if hashlib.sha256(payload).hexdigest() != hashlib.sha256(lib.read_bytes()).hexdigest():
    raise SystemExit('verify failed')
rep = {'source': str(src), 'image': str(dst), 'lib': str(lib),
       'image_sha256': hashlib.sha256(dst.read_bytes()).hexdigest(),
       'lib_sha256': hashlib.sha256(lib.read_bytes()).hexdigest(), 'verified': True}
(D / 'manifest.json').write_text(json.dumps(rep, indent=2))
arc = R / '03-证据/ASTRA-97' / D.name; arc.mkdir(exist_ok=False, parents=True)
for n in ['manifest.json', 'debugfs.log']: shutil.copy2(D / n, arc / n)
print(json.dumps(rep, indent=2))
