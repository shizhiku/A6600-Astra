import sys
sys.path.insert(0, '<WORKSPACE>/02-脚本')
from importlib.machinery import SourceFileLoader

u = SourceFileLoader('u', '<WORKSPACE>/02-脚本/97_ext2.py').load_module()
f = u.Ext2('/root/astra/97/m1-verified/astra-m1-astra7.img')
ns = [(p, i) for p, i, d in f.walk() if not d and 'Obj' in p]
for p, i in ns:
    size = f.inode(i)[1]
    print(p, size)
