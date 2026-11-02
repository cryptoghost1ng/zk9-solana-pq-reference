"""Independent bottom-up subtree oracle: no mutable node map or Rust code."""
import hashlib,json
from functools import lru_cache
from pathlib import Path
def parent(level,left,right):return hashlib.sha3_512(b'ZK9MRK01'+level.to_bytes(4,'little')+left+right).digest()
empty=[bytes(64)]
for l in range(32):empty.append(parent(l,empty[l],empty[l]))
cases=[]
for count in (0,1,2,3,12,16,17,1000):
    leaves=[hashlib.sha3_512(b'leaf'+i.to_bytes(8,'little')).digest() for i in range(count)]
    @lru_cache(None)
    def subtree(height,start):
        if start>=count:return empty[height]
        if height==0:return leaves[start]
        return parent(height-1,subtree(height-1,start),subtree(height-1,start+(1<<(height-1))))
    paths=[]
    for i in sorted(set([0,count//2,count-1])) if count else []:
        paths.append(dict(index=i,siblings=[subtree(l,((i>>l)^1)<<l).hex() for l in range(32)]))
    cases.append(dict(count=count,root=subtree(32,0).hex(),paths=paths))
Path(__file__).with_name('tree-vectors.json').write_text(json.dumps(cases,indent=2)+'\n')
