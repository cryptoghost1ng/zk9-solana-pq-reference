"""Read-only composition analysis of the archived public capsule of privacy-live-02 (real sponsored payments on a local synthetic validator).
Decodes every captured transaction and groups it by payment (the buffer/source account) and by instruction role, with the compute units each one consumed.
It reads one archived file and writes one new evidence file; it proves nothing about privacy and says nothing about mainnet.
usage: analyze_capsule.py LABEL   (a new label each time; existing evidence is never overwritten)"""
import base64,collections,hashlib,json,re,statistics,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent;WORK=ROOT.parent
CAPSULE=WORK/'solana-multiwallet-privacy-v1/evidence/privacy-live-02/public-capsule'
label=sys.argv[1] if len(sys.argv)==2 else None
assert label and re.fullmatch(r'[a-z0-9-]+',label),'a new evidence label is required'
out=ROOT/'evidence'/(label+'.json');assert not out.exists(),'evidence is never overwritten'
A='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58(b):
    n=int.from_bytes(b,'big');s=''
    while n:n,r=divmod(n,58);s=A[r]+s
    return '1'*(len(b)-len(b.lstrip(b'\0')))+s
def cu16(buf,i):
    n=0;shift=0
    while True:
        x=buf[i];i+=1;n|=(x&0x7f)<<shift;shift+=7
        if not x&0x80:return n,i
def decode(raw):
    i=0;n,i=cu16(raw,i);i+=64*n
    if raw[i]&0x80:i+=1  # v0 prefix
    i+=3;k,i=cu16(raw,i);keys=[raw[i+32*j:i+32*(j+1)] for j in range(k)];i+=32*k+32
    m,i=cu16(raw,i);ixs=[]
    for _ in range(m):
        p=raw[i];i+=1;na,i=cu16(raw,i);acc=list(raw[i:i+na]);i+=na;nd,i=cu16(raw,i);data=raw[i:i+nd];i+=nd
        ixs.append((b58(keys[p]),[b58(keys[a]) for a in acc],data))
    return b58(keys[0]),ixs
cfg=json.load(open(CAPSULE/'CONFIG.json'))
SYSTEM='1'*32;BUDGET='ComputeBudget111111111111111111111111111111'
wires={f.name:f.stat().st_size for f in CAPSULE.glob('*.wire')}
by_len={v:k for k,v in wires.items()}
txs=json.load(open(CAPSULE/'TRANSACTIONS.json'))
# stage names of the staged verifier by op code (from solana-relay-performance-v1/candidate/proof-progress.mjs nextStep)
OPS={0:'proof-create',1:'format',3:'prefix',4:'openings',5:'fri',6:'input-init',7:'input-mmcs',8:'reduction-init',9:'reduction',10:'fold-init',11:'fold',12:'round-init',13:'round',14:'air-context',15:'quotient',16:'air-init',17:'air'}
pay=collections.defaultdict(lambda:{'rows':[],'wire_len':None,'kind':None})
other=collections.Counter();first_ts={};last_ts={}
for t in txs:
    if t['err'] is not None:continue
    payer,ixs=decode(base64.b64decode(t['raw']))
    cu=t['rpc_meta'].get('computeUnitsConsumed');fee=t['rpc_meta'].get('fee');limit=None
    for prog,acc,data in ixs:
        if prog==BUDGET and data[:1]==b'\x02':limit=struct.unpack('<I',data[1:5])[0]
    body=[(p,a,d) for p,a,d in ixs if p not in (BUDGET,)]
    role=None;src=None
    for prog,acc,data in body:
        if prog==cfg['buffer_program']:
            src=acc[0]
            if data[:1]==b'\x00':role='buffer-init';pay[src]['wire_len']=struct.unpack('<I',data[1:5])[0]
            elif data[:1]==b'\x01':role='chunk'
            elif data[:1]==b'\x02':role='buffer-seal'
            else:role='buffer-op-%d'%data[0]
        elif prog!=SYSTEM and prog!=cfg['program'] and len(acc)>=2 and prog not in (cfg['buffer_program'],):
            # verifier program: accounts = [receipt, source, authority, buffer program, buffer programdata]
            if len(acc)==5 and data:
                src=acc[1];role=OPS.get(data[0],'verifier-op-%d'%data[0])
        elif prog==cfg['program']:
            role='pool-op-%d'%(data[0] if data else -1)
    if role is None:
        other['system/other']+=1;continue
    if src is None:
        other[role]+=1;continue
    pay[src]['rows'].append((role,cu,fee,limit,t['block_time'],t['slot']))
def stats(v):
    v=sorted(v);return {'n':len(v),'cu_min':v[0],'cu_median':statistics.median(v),'cu_p95':v[int(.95*(len(v)-1))],'cu_max':v[-1]} if v else None
res={'source':str(CAPSULE.relative_to(WORK)),'transactions_captured':len(txs),'transactions_not_attributed_to_a_payment':dict(other),'payments':[]}
for src,p in pay.items():
    kind=None
    if p['wire_len'] in by_len:kind=by_len[p['wire_len']].split('.')[1]
    rows=p['rows'];byrole=collections.defaultdict(list)
    for role,cu,fee,limit,bt,slot in rows:byrole[role].append((cu,limit))
    t0=min(r[4] for r in rows);t1=max(r[4] for r in rows);slots=max(r[5] for r in rows)-min(r[5] for r in rows)
    res['payments'].append({'source_account':src,'wire_bytes':p['wire_len'],'kind':kind,'transactions':len(rows),'wall_seconds_by_block_time':t1-t0,'slots_spanned':slots,
        'seconds_per_transaction_by_block_time':round((t1-t0)/len(rows),3) if rows else None,'fees_lamports':sum(r[2] or 0 for r in rows),
        'by_role':{r:{**stats([c for c,_ in v if c is not None]),'compute_limit_requested_max':max([l for _,l in v if l] or [0])} for r,v in sorted(byrole.items(),key=lambda kv:-len(kv[1]))}})
res['payments'].sort(key=lambda x:x['transactions'])
res['capsule_manifest_sha256']=hashlib.sha256((CAPSULE/'TRANSACTIONS.json').read_bytes()).hexdigest()
res['scope']='Composition of archived local synthetic payments (privacy-live-02). Not a measurement of the current relay service, not mainnet, no privacy claim.'
out.write_text(json.dumps(res,indent=1)+'\n')
for p in res['payments']:
    print(p['kind'],p['wire_bytes'],'tx',p['transactions'],'s',p['wall_seconds_by_block_time'],'s/tx',p['seconds_per_transaction_by_block_time'])
    for r,v in p['by_role'].items():print('   %-14s n=%-5d cu median %-8s p95 %-8s max %-8s  limit<=%s'%(r,v['n'],v['cu_median'],v['cu_p95'],v['cu_max'],v['compute_limit_requested_max']))
print('unattributed',dict(other))
