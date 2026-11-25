"""Check astra7 image libraries are intact (a5pFw, a5bObj, a5pFwBoot)."""
import sys
import hashlib
sys.path.insert(0, '<WORKSPACE>/02-脚本')
from importlib.machinery import SourceFileLoader

R = '<WORKSPACE>'
u = SourceFileLoader('u', R + '/02-脚本/97_ext2.py').load_module()
f = u.Ext2('/root/astra/97/m1-verified/astra-m1-astra7.img')
idx = {p: i for p, i, d in f.walk() if not d}

for path in ('/lib/a5pFw.so', '/lib/a5bObj.so', '/lib/a5pFwBoot.so',
             '/usr/lib/a5pFw.so', '/usr/lib/a5bObj.so'):
    if path not in idx:
        print('%-24s MISSING' % path)
        continue
    b = f.read_file(idx[path])
    print('%-24s size=%-10d sha=%s' % (path, len(b),
                                       hashlib.sha256(b).hexdigest()[:32]))

print()
print('=== also check bridge lib ===')
for p in idx:
    if 'astra' in p.lower() or 'bridge' in p.lower():
        print(' ', p, f.inode(idx[p])[1])
