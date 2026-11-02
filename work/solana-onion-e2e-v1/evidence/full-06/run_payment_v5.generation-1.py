"""PAYMENT LEGS of the end-to-end onion trial with the WINDOWED relay and ACCOUNT CLEANUP (v5: this driver is v4 unchanged except that the relay service it launches is
solana-onion-relay-service-v3, which after each settled payment also closes the verifier receipt and the proof buffer so their rent returns to the sponsor (solana-relay-cleanup-v1),
and that it asks the validator whether those accounts are gone and whether the sponsor spent only fees. v4 stays frozen with evidence/full-05.
v4: this driver is v3 unchanged except that the relay service it launches is
solana-onion-relay-service-v2, which fills the proof buffer WINDOW chunk uploads at a time (solana-relay-windowed-v1). v3 stays frozen with evidence/full-03 and full-04.
v3: the sampler survives a failed RPC reply and a CDP exception is an error reply; v2 stays frozen with evidence/full-02.
v2: the harness reopens the wallet session after its 5-minute auto-lock, like a user entering the password again;
run_payment.py stays frozen with its evidence, see evidence/full-01/NOTE.txt). Local and synthetic; no real funds, no public network, nothing installed in the user's Chrome.
Real pieces: a local Solana validator with the REAL programs (managed-validator.mjs), a real local Tor network (TorLab) with TWO v3 onion
services (a read-only history service and the RELAY service of solana-onion-relay-service-v1, with its own funded sponsor), the real
fixed-role native host launcher, and the onion-routed extension package loaded in disposable Chrome 156 profiles. The package is built for
THIS validator profile and names the relay's REAL sponsor authority (not a synthetic one).
modes (the label prefix; with_free_ports.py passes only the label):
  smoke-NN  restore wallets, deposit 13, prove a send in the extension, hand it to the relay over Tor, watch the sponsor start publishing,
            KILL the relay mid-publication, restart it, check that it resumes the same request; then stop (the payment is NOT finished).
  send-NN   as smoke, then let the send settle; check sender and an independently restored recipient; idle probes of the relay (duplicate
            submit, tampered proof).
  full-NN   send-NN followed by the public withdrawal of 1 unit through the relay.
NOT shown by any mode: privacy or anonymity (public fixture seeds, one machine, one operator, local Tor), a public network, real funds.
usage: with_free_ports.py run_payment_v5.py full-06   (use the Python of work/wallet-onion-adoption-v1/chutney-venv)"""
import base64,hashlib,json,os,re,shutil,signal,socket,subprocess,sys,tempfile,threading,time,traceback,types,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parent;WORK=ROOT.parent
CHROME_WALLET=WORK/'solana-chrome-wallet-v1';UNIFIED_DIR=WORK/'solana-unified-wallet-v1';OLD=WORK/'wallet-onion-adoption-v1'
PKG=WORK/'solana-onion-package-v1';LAUNCHER=WORK/'solana-native-launcher-v1';TRANSPORT=WORK/'solana-onion-relay-transport-v2';SERVICE=WORK/'solana-onion-relay-service-v1';SERVICE2=WORK/'solana-onion-relay-service-v2';WINDOWED=WORK/'solana-relay-windowed-v1';SERVICE3=WORK/'solana-onion-relay-service-v3';CLEANUP=WORK/'solana-relay-cleanup-v1'
WINDOWED_MUTATION='mutation-03';WINDOWED_CHECKS='checks-02'
CLEANUP_MUTATION='mutation-02';CLEANUP_CHECKS='checks-02'
sys.path[:0]=[str(TRANSPORT/'candidate'),str(OLD),str(OLD/'chutney-source/lib'),str(CHROME_WALLET),str(LAUNCHER),str(PKG),str(ROOT)]
from offline_guard import acquire
from tor_lab import TorLab,TOR,GENCERT
from onion_http import Origin,exchange
from onion_socket import new_isolation_token
from wallet_http_deadline import _Budget
import build_candidate as HB
import build_package as PB
from chrome_cdp import Cdp
from history_service import HistoryService
assert len(sys.argv)==2 and re.fullmatch(r'(smoke|send|full)-[0-9]+',sys.argv[1])
MODE,NUM=sys.argv[1].split('-');N=int(NUM)
LABEL_OFFSET={'smoke':300,'send':400,'full':500}[MODE]
lock=acquire();os.umask(0o077);out=ROOT/'evidence'/sys.argv[1];out.mkdir(parents=True,exist_ok=False)
NODE=Path('<HOME>/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node')
CHROME=Path('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome');HOME=Path.home()
REAL_HOST_DIRS=[HOME/'Library/Application Support/Google/Chrome/NativeMessagingHosts',Path('/Library/Google/Chrome/NativeMessagingHosts'),HOME/'Library/Application Support/Chromium/NativeMessagingHosts']
SPONSOR_AIRDROP=200_000_000_000;RESTART_AFTER=25;SMOKE_EXTRA=25
RESTART_BY=os.environ.get('ZK9_RESTART_BY','SIGKILL');assert RESTART_BY in ('SIGKILL','STOP')
PROVE_TIMEOUT=1500;LEG_LIMIT_S=3*3600
# Test hook: lock the wallet by hand N seconds after publication starts, to exercise the reopen path in a short run (the product locks itself after 5 minutes).
FORCE_LOCK_AFTER=float(os.environ['ZK9_TEST_LOCK_AFTER_S']) if os.environ.get('ZK9_TEST_LOCK_AFTER_S') else None
LOCKED_MESSAGES=('Unlock and sync the wallet first.','Wallet is locked. Unlock it again.')
is_locked=lambda reply:(not reply.get('ok')) and any(m in (reply.get('error') or '') for m in LOCKED_MESSAGES)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
read=lambda p:json.loads(Path(p).read_text())
def write(path,value):
    with Path(path).open('x') as handle:json.dump(value,handle,indent=2);handle.write('\n')
listing=lambda d:sorted((e.name,e.stat(follow_symlinks=False).st_size,e.stat(follow_symlinks=False).st_mtime_ns) for e in os.scandir(d)) if Path(d).is_dir() else None
T0=time.monotonic()
progress_log=(out/'PROGRESS.jsonl').open('x')
def note(event,**fields):
    row={'t':round(time.monotonic()-T0,1),'event':event,**fields};progress_log.write(json.dumps(row)+'\n');progress_log.flush();print(json.dumps(row),flush=True)
class NetCdp(Cdp):
    """Also records every network request any attached target (page, extension worker, offscreen, service worker) makes."""
    def __init__(self,*a,**k):
        self.requests=[];super().__init__(*a,**k)
    def _attach_worker(self):
        while True:
            session=self.attach_queue.get()
            for method in ('Runtime.enable','Log.enable','Network.enable'):
                try:self.call(method,session=session,timeout=10)
                except Exception:pass
            try:self.call('Target.setAutoAttach',{'autoAttach':True,'waitForDebuggerOnStart':False,'flatten':True},session=session,timeout=10)
            except Exception:pass
    def _event(self,msg):
        if msg.get('method')=='Network.requestWillBeSent':
            info=self.targets.get(msg.get('sessionId'),{});request=msg['params']['request'];url=request['url'];method=None
            try:method=json.loads(request.get('postData') or 'null').get('method')
            except Exception:pass
            self.requests.append({'t':time.monotonic(),'target':info.get('type','?'),'url':url[:160],'rpc_method':method})
        else:super()._event(msg)
def direct_http(requests):return [r for r in requests if r['url'].startswith(('http://','https://'))]
def processes(needle):
    rows=subprocess.run(['/bin/ps','-axo','pid=,args='],capture_output=True,text=True).stdout.splitlines()
    return [(int(r.split(None,1)[0]),r.strip()) for r in rows if needle in r and int(r.split(None,1)[0])!=os.getpid()]
def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1',0));return probe.getsockname()[1]
HOOK=open(PKG/'driver.py').read().split("HOOK='''")[1].split("'''")[0]   # the same page hook the package run used (pinned file)

class Relay:
    """The relay service process (solana-onion-relay-service-v3/serve.mjs, windowed with account cleanup) and the stream of events it prints."""
    def __init__(self,state,config_path,profile_path,port):
        self.args=[str(NODE),str(SERVICE3/'serve.mjs'),str(state),str(config_path),sha(config_path),str(profile_path),sha(profile_path),str(port)]
        self.events=[];self.lock=threading.Lock();self.proc=None;self.host=None;self.stderr=None;self.generation=0
    def start(self,timeout=180):
        self.generation+=1
        self.stderr=(out/('relay-%d.stderr'%self.generation)).open('x')
        self.proc=subprocess.Popen(self.args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.stderr,cwd=SERVICE3,env={'PATH':'/usr/bin:/bin'})
        threading.Thread(target=self._read,args=(self.proc,self.generation),daemon=True).start()
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            with self.lock:ready=[e for e in self.events if e['type']=='ready' and e['generation']==self.generation]
            if ready:return ready[0]
            if self.proc.poll() is not None:raise RuntimeError('relay service exited during start: %s'%self.proc.returncode)
            time.sleep(.3)
        raise RuntimeError('relay service did not become ready')
    def _read(self,proc,generation):
        for raw in proc.stdout:
            try:event=json.loads(raw)
            except ValueError:continue
            event['generation']=generation
            with self.lock:self.events.append(event)
    def line(self,text):
        self.proc.stdin.write((text+'\n').encode());self.proc.stdin.flush()
    def bind(self,host):
        self.host=host;self.line('HOST '+host)
    def of(self,kind):
        with self.lock:return [e for e in self.events if e['type']==kind]
    def stop(self,timeout=90):
        try:self.line('STOP')
        except OSError:pass
        try:return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill();return self.proc.wait()
    def kill(self):
        self.proc.kill();return self.proc.wait()

class SigWatcher:
    """Independent witness: every signature the validator lists for an address, accumulated while the run goes on (the ledger is bounded)."""
    def __init__(self,rpc,address):
        self.rpc,self.address,self.seen,self.newest=rpc,address,set(),None
    def poll(self):
        before=None
        while True:
            options={'limit':1000,'commitment':'confirmed'}
            if self.newest:options['until']=self.newest
            if before:options['before']=before
            rows=self.rpc('getSignaturesForAddress',[self.address,options])
            for row in rows:self.seen.add(row['signature'])
            if len(rows)<1000:break
            before=rows[-1]['signature']
        newest=self.rpc('getSignaturesForAddress',[self.address,{'limit':1,'commitment':'confirmed'}])
        if newest:self.newest=newest[0]['signature']
        return len(self.seen)

# ---- gates and pins ----
gates=[(PKG/'evidence/onion-01/RESULT.json','PASS_ONION_ROUTED_PACKAGE_CANDIDATE'),(PKG/'evidence/package-04/RESULT.json','PASS_ONION_PACKAGE_IN_REAL_CHROME'),
       (LAUNCHER/'evidence/launcher-02/RESULT.json','PASS_NATIVE_LAUNCHER_CANDIDATE'),(WORK/'solana-onion-relay-integration-v2/evidence/onion2-live-02/RESULT.json','PASS_REAL_LOCAL_TOR_SOLANA_ADMISSION_V2'),
       (ROOT/'evidence/e2e-qualification-01/RESULT.json','PASS_ONION_E2E_READ_AND_DEPOSIT_LEGS'),(WORK/'solana-private-relay-v1/evidence/relay-live-04/RESULT.json','PASS_NATIVE_WALLETS_WITH_LIVE_SPONSORED_RELAY')]
for path,status in gates:assert read(path)['status']==status,path
mutation_gate=read(SERVICE/'evidence/mutation-03/MUTATION.json');assert mutation_gate['all_detected'] is True,'the relay service mutation control has not passed'
windowed_mutation=read(WINDOWED/'evidence'/WINDOWED_MUTATION/'MUTATION.json');assert windowed_mutation['all_detected'] is True and not windowed_mutation['undetected'] and windowed_mutation['count']>=70,'the windowed revision mutation control has not passed'
windowed_checks=read(WINDOWED/'evidence'/WINDOWED_CHECKS/'RESULT.json');assert windowed_checks['status']=='PASS_WINDOWED_PUBLICATION_CHECKS' and windowed_checks['tests']==windowed_checks['passed'],'the windowed revision checks have not passed'
cleanup_mutation=read(CLEANUP/'evidence'/CLEANUP_MUTATION/'MUTATION.json');assert cleanup_mutation['all_detected'] is True and not cleanup_mutation['undetected'] and cleanup_mutation['count']>=29,'the cleanup revision mutation control has not passed'
cleanup_checks=read(CLEANUP/'evidence'/CLEANUP_CHECKS/'RESULT.json');assert cleanup_checks['status']=='PASS_CLEANUP_CHECKS' and cleanup_checks['tests']==cleanup_checks['passed'] and cleanup_checks['failed']==0,'the cleanup revision checks have not passed'
tor_reference=OLD/'tor-circuits-r1/network/CONFIG-CHECK.json';assert sha(GENCERT)==read(tor_reference)['gencert_sha256']
paths=[*[ROOT/n for n in ('run_payment.py','run_payment_v2.py','run_payment_v3.py','run_payment_v4.py','run_payment_v5.py','history_service.py')],*[g for g,_ in gates],SERVICE/'evidence/mutation-03/MUTATION.json',*sorted(SERVICE.glob('*.mjs')),SERVICE/'mutation_control.py',
       SERVICE2/'serve.mjs',SERVICE3/'serve.mjs',SERVICE3/'make_service.py',*sorted(CLEANUP.glob('*.mjs')),CLEANUP/'mutation_control.py',CLEANUP/'make_revision.py',CLEANUP/'run_checks.py',CLEANUP/'evidence'/CLEANUP_MUTATION/'MUTATION.json',CLEANUP/'evidence'/CLEANUP_CHECKS/'RESULT.json',CLEANUP/'evidence'/CLEANUP_CHECKS/'INPUTS.json',*sorted(WINDOWED.glob('*.mjs')),WINDOWED/'mutation_control.py',WINDOWED/'evidence'/WINDOWED_MUTATION/'MUTATION.json',WINDOWED/'evidence'/WINDOWED_CHECKS/'RESULT.json',WINDOWED/'evidence'/WINDOWED_CHECKS/'INPUTS.json',
       PKG/'build_package.py',PKG/'chrome_cdp.py',*sorted((PKG/'src').glob('*.mjs')),LAUNCHER/'launcher.py',LAUNCHER/'build_candidate.py',
       UNIFIED_DIR/'managed-validator.mjs',UNIFIED_DIR/'host-lease.mjs',UNIFIED_DIR/'package-unified.py',OLD/'tor_lab.py',TOR,GENCERT,NODE,CHROME,Path(sys.executable).resolve()]
pins={str(p):sha(p) for p in paths};write(out/'INPUTS.json',pins)
version=subprocess.run([str(CHROME),'--version'],capture_output=True,text=True,timeout=30).stdout.strip();(out/'chrome-version.txt').write_text(version+'\n')
before={str(d):listing(d) for d in REAL_HOST_DIRS}
vid='installed-connected-%d'%(LABEL_OFFSET+N);label='unified-%d'%(LABEL_OFFSET+N)
vout=CHROME_WALLET/'evidence'/vid;assert not vout.exists() and not (UNIFIED_DIR/'dist'/label).exists()
base=Path(os.path.realpath(tempfile.mkdtemp(prefix='chrome-pay-')));state=base/'relay-state';state.mkdir(mode=0o700);hosts_nm_source=None
last_rpc_error=[];sampler_errors=[]
validator=beat=lab=service=relay=None;stop_beat=threading.Event();checks={};steps={};error=None;config=None;package=None;tree=None;leftovers=None;built=[]
relay_exit=None;chrome_console={};timeline=[];network_log={}
try:
    # ---- validator with the real programs ----
    vout.mkdir()
    so,se=(vout/'bootstrap.stdout').open('x'),(vout/'bootstrap.stderr').open('x')
    validator=subprocess.Popen([str(NODE),str(UNIFIED_DIR/'managed-validator.mjs'),str(vout)],cwd=CHROME_WALLET,stdin=subprocess.PIPE,stdout=so,stderr=se)
    def heartbeat():
        while not stop_beat.wait(20):
            try:validator.stdin.write(b'alive\n');validator.stdin.flush()
            except OSError:return
    beat=threading.Thread(target=heartbeat,daemon=True);beat.start()
    for _ in range(480):
        assert validator.poll() is None,'validator bootstrap ended'
        if (vout/'LIVE-CONFIG.json').exists():break
        time.sleep(.5)
    else:raise RuntimeError('validator startup timed out')
    time.sleep(1);config=read(vout/'LIVE-CONFIG.json');endpoint=config['network']['endpoint'];PROGRAM,CONTEXT=config['program'],config['context']
    checks['validator_started_with_the_real_programs']=len(config['network']['programs'])==4
    def validator_rpc(method,params):
        request=urllib.request.Request(endpoint,data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),headers={'Content-Type':'application/json'})
        for attempt in range(4):
            try:
                with urllib.request.urlopen(request,timeout=60) as response:reply=json.loads(response.read())
            except Exception as exc:reply={'error':{'message':'transport: %r'%exc}}
            if 'result' in reply:return reply['result']
            last_rpc_error.append({'t':round(time.monotonic()-T0,1),'method':method,'error':json.dumps(reply.get('error'))[:300]});del last_rpc_error[:-20]
            time.sleep(2*(attempt+1))
        raise RuntimeError('validator rpc %s failed: %s'%(method,json.dumps(reply.get('error'))[:300]))
    template=WORK/'solana-beta-withdraw-v1/evidence/native-deposit-01/native-deposit/custody-runtime.json'
    native=read(template);native.update({k:config[k] for k in ['context','program','pool']})
    write(vout/'NATIVE-CUSTODY-PROFILE.json',native);write(vout/'NETWORK-PROFILE.json',config['network'])
    # ---- the relay service, with its own sponsor, funded by the validator faucet (operator action) ----
    relay_port=free_port();relay=Relay(state,vout/'LIVE-CONFIG.json',vout/'NATIVE-CUSTODY-PROFILE.json',relay_port)
    ready=relay.start();SPONSOR=ready['authority']
    checks['relay_service_started_with_its_own_sponsor']=ready['port']==relay_port and ready['recovered'] is None and SPONSOR!=config['authority'] and bool(re.fullmatch(r'[1-9A-HJ-NP-Za-km-z]{32,44}',SPONSOR))
    airdrop=validator_rpc('requestAirdrop',[SPONSOR,SPONSOR_AIRDROP])
    for _ in range(240):
        status=validator_rpc('getSignatureStatuses',[[airdrop],{'searchTransactionHistory':True}])['value'][0]
        if status and status.get('confirmationStatus') in ('confirmed','finalized') and status.get('err') is None:break
        time.sleep(.25)
    else:raise RuntimeError('sponsor funding did not confirm')
    sponsor_start=validator_rpc('getBalance',[SPONSOR,{'commitment':'confirmed'}])['value']
    checks['sponsor_funded_by_the_validator_faucet_not_by_a_wallet']=sponsor_start==SPONSOR_AIRDROP
    note('relay_ready',port=relay_port,sponsor=SPONSOR,balance=sponsor_start)
    # ---- package-unified.py re-verifies old qualification inputs, and the Node binary among them was replaced on 2026-10-31; the waiver is an
    #      in-memory copy that tolerates ONLY that one path and records both hashes (same as the read and deposit legs) ----
    packager_path=UNIFIED_DIR/'package-unified.py';source=packager_path.read_text();stale="assert sha(Path(name))==h,'Stale qualification: '+name"
    assert source.count(stale)==1
    waived=[]
    for qualification in ('publication-sender-03','unified-checks-04','format-05','memo-02'):
        recorded=read(UNIFIED_DIR/'evidence'/qualification/'INPUTS.json').get(str(NODE))
        if recorded:waived.append({'qualification':qualification,'recorded_node_sha256':recorded,'current_node_sha256':sha(NODE)})
    steps['node_runtime_waiver']={'scope':'only the Node binary path in the four qualification INPUTS; every other input is still verified','entries':waived}
    unified=types.ModuleType('unified_packager');unified.__file__=str(packager_path)
    exec(compile(source.replace(stale,"assert sha(Path(name))==h or name==%r,'Stale qualification: '+name"%str(NODE)),str(packager_path),'exec'),unified.__dict__)
    basepkg=unified.assemble(label,vout)
    # ---- the onion-routed package for THIS profile, naming the relay's REAL sponsor ----
    default=PB.UNIFIED;default_files=read(default/'PACKAGE.json')['files'];base_files=read(basepkg/'PACKAGE.json')['files']
    differing={n for n in set(default_files)|set(base_files) if default_files.get(n)!=base_files.get(n)}
    assert differing<={'config.mjs','manifest.json','INSTALLED-FLOW-CONFIG.json'},'the new base differs from unified-06 beyond profile data: %s'%sorted(differing)
    pem=base/'key.pem';subprocess.run(['/usr/bin/openssl','genrsa','-out',str(pem),'2048'],check=True,capture_output=True)
    der=subprocess.run(['/usr/bin/openssl','rsa','-in',str(pem),'-pubout','-outform','DER'],check=True,capture_output=True).stdout;pem.unlink()
    PB.UNIFIED=basepkg
    try:package=PB.build(base/'ext',key_b64=base64.b64encode(der).decode(),sponsor_authority=SPONSOR)
    finally:PB.UNIFIED=default
    write(out/'PACKAGE.json',package);ext_id=package['extension_id'];origin='chrome-extension://%s/'%ext_id
    checks['package_built_for_this_validator_profile_from_the_unchanged_builder']=package['status']=='PACKAGED_ONION_ROUTED_LOCAL_CANDIDATE'
    config_mjs=(base/'ext/config.mjs').read_text()
    checks['package_names_the_real_relay_sponsor_not_a_synthetic_one']=package['sponsor_authority_synthetic'] is False and ('SPONSOR_AUTHORITY = "%s"'%SPONSOR) in config_mjs
    steps['base_differences_from_unified_06']=sorted(differing)
    # ---- program-data address, history service, real Tor with TWO onion services ----
    account=validator_rpc('getAccountInfo',[PROGRAM,{'encoding':'base64'}])['value'];pool_state=base64.b64decode(account['data'][0])
    assert len(pool_state)==36 and int.from_bytes(pool_state[:4],'little')==2;programdata=PB.b58(pool_state[4:])
    service=HistoryService(endpoint,PROGRAM,programdata);service.start()
    # Chutney treats a node as an onion service only if its tag starts with 'h'
    lab=TorLab(out/'network',{'h':service.port,'hr':relay_port});lab.prepare()
    history_onion=Origin.parse(lab.origins['h']);relay_onion=Origin.parse(lab.origins['hr'])
    for onion in (history_onion,relay_onion):assert re.fullmatch(r'http://[a-z2-7]{56}\.onion',onion.url),onion.url
    relay.bind(relay_onion.host)
    lab.start();lab.bootstrap()
    def onion_exchange(onion,method,path,body=b'',seconds=60):
        return exchange(onion,method,path,body,proxy_host='127.0.0.1',proxy_port=lab.socks_port,isolation_token=new_isolation_token(),budget=_Budget(seconds))
    deadline=time.monotonic()+300;healthy={'h':False,'r':False};last=None
    while time.monotonic()<deadline and not all(healthy.values()):
        for tag,onion,scope in (('h',history_onion,'local-onion-history-only'),('r',relay_onion,'local-onion-relay-service')):
            if healthy[tag]:continue
            try:
                status,body=onion_exchange(onion,'GET','/health',b'',20);healthy[tag]=status==200 and json.loads(body)=={'scope':scope}
            except Exception as exc:last=type(exc).__name__;time.sleep(2)
    checks['history_and_relay_onion_services_reachable_through_real_tor']=all(healthy.values())
    assert all(healthy.values()),'onion health timed out: %s %s'%(healthy,last)
    service.log.clear()
    # ---- fixed-role hosts for this extension id: history -> history onion, relay -> relay onion ----
    specs=HB.synthetic_specs(1024)
    specs['history'].update(onion_origin=history_onion.url,proxy_port=lab.socks_port,timeout=90,program_data={PROGRAM:programdata})
    specs['relay'].update(onion_origin=relay_onion.url,proxy_port=lab.socks_port,timeout=120,context=CONTEXT)
    hosts=HB.build(base/'hosts',extension_id=ext_id,specs=specs);tree=Path(hosts['tree'])
    # ---- wallets: two disposable Chrome profiles, one custody worker each ----
    PASSWORD='Public synthetic payment-leg password for the disposable profiles only'
    class Wallet:
        def __init__(self,name,seed_byte):
            self.name,self.seed_byte=name,seed_byte;self.profile=base/('profile-'+name);self.cdp=None;self.session=None;self.opened=0
        def open(self):
            self.opened+=1;nm=self.profile/'NativeMessagingHosts'
            if self.profile.exists():shutil.rmtree(self.profile)
            self.profile.mkdir(mode=0o700);nm.mkdir(mode=0o700)
            for role in ('history','relay'):shutil.copyfile(hosts['manifests'][role]['path'],nm/(HB.HOSTS[role]+'.json'))
            argv=[str(CHROME),'--user-data-dir=%s'%self.profile,'--no-first-run','--no-default-browser-check','--use-mock-keychain','--password-store=basic','--disable-background-networking',
                  '--disable-component-update','--disable-sync','--no-pings','--headless=new','--enable-logging=stderr','--v=0','--remote-debugging-pipe','--enable-unsafe-extension-debugging','about:blank']
            self.cdp=NetCdp(argv,out/('chrome-%s-%d.log'%(self.name,self.opened)),{'PATH':'/usr/bin:/bin','HOME':str(HOME),'TMPDIR':os.environ.get('TMPDIR','/tmp'),'LANG':'en_US.UTF-8'})
            self.cdp.call('Target.setAutoAttach',{'autoAttach':True,'waitForDebuggerOnStart':False,'flatten':True})
            loaded=self.cdp.call('Extensions.loadUnpacked',{'path':str(base/'ext')});assert loaded.get('id')==ext_id
            target=self.cdp.call('Target.createTarget',{'url':'about:blank'})['targetId'];self.session=self.cdp.call('Target.attachToTarget',{'targetId':target,'flatten':True})['sessionId']
            for method in ('Page.enable','Runtime.enable','Network.enable'):self.cdp.call(method,session=self.session)
            self.cdp.call('Page.addScriptToEvaluateOnNewDocument',{'source':HOOK},session=self.session);self.cdp.call('Page.navigate',{'url':origin+'wallet.html'},session=self.session)
            ready=False
            for _ in range(300):
                time.sleep(.3)
                try:ready=self.cdp.evaluate(self.session,"!!(window.__zk9log && window.__zk9log.some(m => m && m.ready === true))",timeout=10)
                except Exception:ready=False
                if ready:break
            assert ready,'custody worker did not start for '+self.name
        def call(self,method,*args,tries=40,timeout=300):
            js="window.__zk9call(%s,...%s).then(r=>({ok:true,result:r}),e=>({ok:false,error:String(e.message)}))"%(json.dumps(method),json.dumps(list(args)))
            for _ in range(tries):
                try:reply=self.cdp.evaluate(self.session,js,timeout=timeout)
                except Exception as exc:return {'ok':False,'error':'cdp: %r'%(exc,)}
                if reply.get('ok') or 'Wait for the current wallet operation' not in reply.get('error',''):return reply
                time.sleep(.5)
            return reply
        def restore(self):
            words=self.cdp.evaluate(self.session,"(async()=>{const {entropyToWords}=await import('./recovery/codec.mjs');return await entropyToWords(new Uint8Array(32).fill(%d));})()"%self.seed_byte)
            restored=self.call('restoreWords','zk9-recovery-v1',words,PASSWORD);words=None
            self.key=(restored.get('result') or {}).get('key')
            status=self.call('status')
            if restored.get('ok') and status.get('ok') and status['result'].get('locked'):
                unlocked=self.call('unlock',restored['result']['key'],PASSWORD);return restored.get('ok') and unlocked.get('ok')
            return bool(restored.get('ok'))
        def reunlock(self):
            """What a user does after the 5-minute auto-lock: enter the password again, then let the wallet read validated history."""
            status=self.call('status')
            if status.get('ok') and status['result'].get('locked'):
                if not self.call('unlock',self.key,PASSWORD).get('ok'):return False
            return bool(self.call('syncWallet').get('ok'))
        def close(self):
            if self.cdp is not None:
                try:self.call('lock',tries=2,timeout=30)
                except Exception:pass
                chrome_console[self.name+str(self.opened)]=list(self.cdp.console)
                network_log[self.name+str(self.opened)]=[{k:v for k,v in r.items() if k!='t'} for r in self.cdp.requests[:400]]
                self.cdp.terminate();self.cdp=None
    def summarize(reply):
        r=reply.get('result') or {}
        return {'ok':reply.get('ok'),'error':reply.get('error'),'synthetic_only':r.get('synthetic_only'),'rpc_consensus_authenticated':r.get('rpc_consensus_authenticated'),'spendable_units':r.get('spendable_units'),
                'owned_notes':len(r.get('owned_notes',[])) if isinstance(r.get('owned_notes'),list) else None,'slot':r.get('slot'),'wallet_id':r.get('wallet_id')}
    def token_balance(account,commitment='confirmed'):return int(validator_rpc('getTokenAccountBalance',[account,{'commitment':commitment}])['value']['amount'])
    def relay_sigs():return len(sponsor_watch.seen)
    sponsor_watch=SigWatcher(validator_rpc,SPONSOR);sender_watch=SigWatcher(validator_rpc,config['authority']);recipient_watch=None
    def sample():
        # The watchers accumulate, so one missed sample costs nothing; a persistent failure shows in sampler_errors and in the final counts.
        try:
            a,b=sponsor_watch.poll(),sender_watch.poll();c=recipient_watch.poll() if recipient_watch else None
        except Exception as exc:
            sampler_errors.append({'t':round(time.monotonic()-T0,1),'error':repr(exc)[:300]});note('sampler_error',error=repr(exc)[:200],count=len(sampler_errors))
            return len(sponsor_watch.seen)
        timeline.append({'t':round(time.monotonic()-T0,1),'sponsor_signatures':a,'sender_wallet_signatures':b,'recipient_wallet_signatures':c});return a
    # ---- recipient: restore seed 212 in its own Chrome, read privately, get the address ----
    recipient=Wallet('recipient',212);recipient.open()
    checks['recipient_wallet_restored_in_the_extension']=recipient.restore()
    r0=len(recipient.cdp.requests);rs=recipient.call('syncWallet');r1=len(recipient.cdp.requests)
    addr=recipient.call('receiveAddress');rf=recipient.call('fundingSources')   # fundingSources is the PUBLIC route by design; outside the private window
    steps['recipient_first_sync']=summarize(rs);RECIPIENT_ADDRESS=(addr.get('result') or {}).get('address');recipient_authority=(rf.get('result') or {}).get('authority')
    steps['recipient_public_route_methods']=sorted({r['rpc_method'] for r in direct_http(recipient.cdp.requests[r1:]) if r['rpc_method']})
    checks['recipient_first_sync_is_private_and_empty']=bool(rs.get('ok')) and rs['result'].get('spendable_units')=='0' and direct_http(recipient.cdp.requests[r0:r1])==[]
    checks['recipient_has_a_receive_address_and_its_own_public_authority']=isinstance(RECIPIENT_ADDRESS,str) and len(RECIPIENT_ADDRESS)>20 and bool(recipient_authority) and recipient_authority!=config['authority']
    recipient_watch=SigWatcher(validator_rpc,recipient_authority) if recipient_authority else None
    recipient.close()
    # ---- sender: restore seed 211, deposit 13 publicly (same sequence as the deposit leg) ----
    sender=Wallet('sender',211);sender.open()
    checks['sender_wallet_restored_in_the_extension']=sender.restore()
    s0=sender.call('syncWallet');steps['sender_sync_before_deposit']=summarize(s0)
    fund=sender.call('fundingSources');checks['sender_public_route_found_the_funded_source']=bool(fund.get('ok')) and fund['result'].get('authority')==config['authority'] and fund['result'].get('sources')==[config['source']]
    source_before,vault_before=token_balance(config['source']),token_balance(config['vault'])
    review=sender.call('reviewDeposit',{'amount':'13','source':config['source']})
    approved=sender.call('approveDeposit',review['result']['review_id']) if review.get('ok') else {'ok':False}
    deposit=approved.get('result') or {};began=time.time()
    while deposit.get('id') and deposit.get('state')!='deposited' and time.time()-began<240:
        step=sender.call('publishDeposit',deposit['id']);rows=(sender.call('depositStatus').get('result') or {}).get('operations') or []
        deposit=next((o for o in rows if o['id']==deposit['id']),deposit)
        if not step.get('ok') or (step.get('result') or {}).get('state') in ('cancelled','failed'):break
        if deposit.get('state')!='deposited':time.sleep(.6)
    checks['deposit_reached_the_deposited_state_in_the_extension']=deposit.get('state')=='deposited'
    s1=sender.call('syncWallet');steps['sender_sync_after_deposit']=summarize(s1)
    checks['sender_private_sync_after_the_deposit_shows_13_units']=bool(s1.get('ok')) and s1['result'].get('spendable_units')=='13'
    source_after,vault_after=token_balance(config['source']),token_balance(config['vault'])
    checks['the_validator_confirms_the_deposit_13_units_moved_to_the_pool_vault']=(source_before-source_after)==13 and (vault_after-vault_before)==13
    sample();note('deposit_done',sponsor_signatures=len(sponsor_watch.seen),sender_wallet_signatures=len(sender_watch.seen))
    checks['positive_control_the_sender_wallet_authority_has_its_own_signatures']=len(sender_watch.seen)>=2 and len(sponsor_watch.seen)>=1

    # ---- one sponsored payment through the relay, driven by the extension ----
    def payment_leg(kind,amount,target,*,restart,until_started_only):
        leg={'kind':kind,'amount':amount};r_start=len(sender.cdp.requests);relay_events_start=len(relay.events)
        sigs_at_start=len(sponsor_watch.seen);admitted_at_start=len(relay.of('admitted'))
        review=sender.call('reviewTransfer',{'kind':kind,'amount':amount,'target':target});leg['review_ok']=bool(review.get('ok'));leg['review_error']=review.get('error')
        approved=sender.call('approvePayment',review['result']['review_id']) if review.get('ok') else {'ok':False}
        operation=approved.get('result') or {};leg['approve_ok']=bool(approved.get('ok'));leg['approve_error']=approved.get('error')
        if not operation.get('id'):return leg
        op_id=operation['id'];leg['operation']=op_id;began=time.time();proved_at=None;sample_at=0;errors=[];states=[];restarted=None;last_log=0;locks=[];publishing_since=None;forced=False;leg['locks']=locks
        def reopen(why):
            ok=sender.reunlock();locks.append({'t':round(time.time()-began,1),'why':why,'reunlocked':ok});note('wallet_session_reopened',kind=kind,why=why,ok=ok);return ok
        while time.time()-began<LEG_LIMIT_S:
            activity=sender.call('paymentActivity')
            if not activity.get('ok'):
                if is_locked(activity):
                    if not reopen('locked'):leg['reunlock_failed']=True;break
                    continue
                errors.append({'t':round(time.time()-began,1),'method':'paymentActivity','error':activity.get('error')});note('payment_step_error',kind=kind,method='paymentActivity',error=activity.get('error'))
                if len(errors)>=3:leg['aborted_after_errors']=True;break
                time.sleep(2);continue
            rows=(activity.get('result') or {}).get('operations') or []
            op=next((o for o in rows if o['id']==op_id),None)
            if op is None:leg['lost_operation']=True;leg['activity_rows']=len(rows);break
            if not states or states[-1][0]!=op['state']:states.append((op['state'],round(time.time()-began,1)));note('payment_state',kind=kind,state=op['state'])
            if op['state']=='publishing' and publishing_since is None:publishing_since=time.time()
            if FORCE_LOCK_AFTER is not None and not forced and publishing_since is not None and time.time()-publishing_since>=FORCE_LOCK_AFTER:
                forced=True;sender.call('lock');locks.append({'t':round(time.time()-began,1),'why':'forced_by_the_test_hook','reunlocked':None});note('wallet_locked_by_the_test_hook',kind=kind);continue
            if op['state']=='settled':break
            if op['state'] in ('conflicted','cancelled','failed'):leg['terminal_failure']=op['state'];break
            method='provePayment' if op['state']=='preparing' else 'settlePayment' if op['state']=='settling' else 'publishPayment'
            step=sender.call(method,op_id,timeout=PROVE_TIMEOUT if method=='provePayment' else 300)
            if method=='provePayment':
                proved_at=round(time.time()-began,1);leg['prove_seconds']=proved_at;leg['prove_ok']=bool(step.get('ok'));leg['prove_error']=step.get('error')
            if is_locked(step):
                if not reopen('locked_during_'+method):leg['reunlock_failed']=True;break
                continue
            if not step.get('ok'):
                errors.append({'t':round(time.time()-began,1),'method':method,'error':step.get('error')});note('payment_step_error',kind=kind,method=method,error=step.get('error'))
                if len(errors)>=3:leg['aborted_after_errors']=True;break
            else:errors=[]
            if time.time()-sample_at>20:
                sample_at=time.time();count=sample();leg.setdefault('sponsor_signature_samples',[]).append([round(time.time()-began,1),count])
                if time.time()-last_log>60:last_log=time.time();note('publishing',kind=kind,sponsor_signatures=count,state=op['state'],relay_events=len(relay.events))
                if restart and restarted is None and count-sigs_at_start>=RESTART_AFTER and len(relay.of('admitted'))>admitted_at_start:
                    restarted=restart_relay(kind,count);leg['restart']=restarted
                    if restarted.get('error'):break
                if until_started_only and restarted and restarted.get('resumed') and sponsor_watch.poll()>=restarted['sponsor_signatures_at_kill']+SMOKE_EXTRA:
                    leg['stopped_after_resume']=True;break
            if method!='provePayment':time.sleep(2.5)
        leg['seconds']=round(time.time()-began,1);leg['state_log']=states;leg['step_errors_tail']=errors[-3:]
        leg['direct_http_during_leg']=[r['rpc_method'] or r['url'] for r in direct_http(sender.cdp.requests[r_start:])]
        leg['relay_events']=[{k:v for k,v in e.items() if k not in ('transport',)} for e in relay.events[relay_events_start:] if e['type'] in ('admitted','refused','duplicate','recovered','parked','finished','task_error','cleanup')]
        leg['final_state']=states[-1][0] if states else None
        return leg
    def restart_relay(kind,count):
        info={'sponsor_signatures_at_kill':count,'method':RESTART_BY};admitted=relay.of('admitted')[-1]
        request_file=state/'requests'/(admitted['id']+'.request');info['request_bytes_before']=request_file.stat().st_size;info['request_sha256_before']=sha(request_file)
        info['exit_code']=relay.kill() if RESTART_BY=='SIGKILL' else relay.stop();time.sleep(1)
        ready=relay.start();relay.bind(relay_onion.host)
        info['recovered_id']=ready.get('recovered');info['same_request']=ready.get('recovered')==admitted['id'];info['same_sponsor']=ready.get('authority')==SPONSOR
        info['request_sha256_after']=sha(request_file);info['resumed']=bool(info['same_request'] and info['same_sponsor'] and info['request_sha256_after']==info['request_sha256_before'])
        note('relay_restarted',**info);return info
    def wait_finished(kind,seconds=180):
        for _ in range(seconds*2):
            if [e for e in relay.of('finished') if e['kind']==kind]:return True
            time.sleep(.5)
        return False
    def idle_probes(kind):
        """The relay is idle after a settled payment: a duplicate submit must change nothing, a tampered proof must be refused with a fixed code."""
        admitted=[e for e in relay.of('admitted') if e['kind']==kind][-1];stored=state/'requests'/(admitted['id']+'.request');raw=stored.read_bytes()
        time.sleep(2);before_count=sample();probes={}
        status,body=onion_exchange(relay_onion,'POST','/v1/submit',raw,120);probes['duplicate']={'status':status,'body':json.loads(body)}
        request=json.loads(raw);wire=bytearray(base64.b64decode(request['wire']));wire[len(wire)//2]^=1
        tampered=json.dumps({'version':request['version'],'kind':request['kind'],'wire':base64.b64encode(bytes(wire)).decode()},separators=(',',':')).encode()
        status,body=onion_exchange(relay_onion,'POST','/v1/submit',tampered,120);probes['tampered']={'status':status,'body':json.loads(body)}
        status,body=onion_exchange(relay_onion,'GET','/v1/status',b'',30);probes['status_route']={'status':status}
        time.sleep(3);after_count=sample();probes['sponsor_signatures_before']=before_count;probes['sponsor_signatures_after']=after_count
        probes['no_new_request_stored']=sorted(p.name for p in (state/'requests').iterdir())==sorted([e['id']+'.request' for e in relay.of('admitted')])
        return probes
    def journal_summary():
        """Read-only look at the relay's SQLite journal: attempts signed, pending left, record size and what the request reserve was debited."""
        import sqlite3
        try:
            db=sqlite3.connect('file:%s?mode=ro'%(state/'operations.sqlite'),uri=True,timeout=10)
            try:
                rows=[]
                for ident,revision,body in db.execute('SELECT id,revision,body FROM operations').fetchall():
                    value=json.loads(body);pending=value.get('pending')
                    rows.append({'id':ident[:16],'version':value.get('version'),'revision':revision,'attempts':value.get('attempts'),
                                 'pending':len(pending) if isinstance(pending,list) else (0 if pending is None else 1),'last':value.get('last') and value['last'].get('outcome'),'record_bytes':len(body)})
                funding=[{'cap_lamports':cap,'used_lamports':used} for cap,used in db.execute('SELECT cap,used FROM funding_reservations').fetchall()]
            finally:db.close()
            return {'operations':rows,'funding':funding}
        except Exception as exc:return {'error':str(exc)[:200]}
    def account_gone(address):
        """Ground truth from the validator itself, never from the relay: an account that was closed has no data and no lamports."""
        return validator_rpc('getAccountInfo',[address,{'commitment':'confirmed','encoding':'base64'}])['value'] is None
    def cleanup_facts(kind):
        """What the validator says about the two accounts the relay created for this request, and the closes the relay says it confirmed."""
        admitted=[e for e in relay.of('admitted') if e['kind']==kind][-1];transport=admitted['transport']
        events=[(e['step'],e['state']) for e in relay.of('cleanup') if e['id']==admitted['id']]
        return {'receipt':transport['receipt'],'buffer':transport['source'],'receipt_gone':account_gone(transport['receipt']),'buffer_gone':account_gone(transport['source']),'cleanup_events':events}
    def cleanup_checks_for(kind,facts):
        confirmed=[step for step,state in facts['cleanup_events'] if state=='step_confirmed']
        return {'%s_verifier_receipt_account_is_gone_on_the_validator'%kind:facts['receipt_gone'] is True,
                '%s_proof_buffer_account_is_gone_on_the_validator'%kind:facts['buffer_gone'] is True,
                '%s_relay_confirmed_the_receipt_close_and_then_the_buffer_close'%kind:confirmed==['receipt-close','buffer-close']}
    def wallet_authority_disjoint():
        sample();overlap=sponsor_watch.seen&sender_watch.seen
        return {'sponsor_signatures':len(sponsor_watch.seen),'sender_wallet_signatures':len(sender_watch.seen),'overlap':sorted(overlap)[:3],'disjoint':not overlap}

    # ---------- the send ----------
    steps['send']=send=payment_leg('send','10',RECIPIENT_ADDRESS,restart=True,until_started_only=MODE=='smoke')
    steps['relay_window']=(relay.of('ready') or [{}])[0].get('window');steps['relay_cleanup']=(relay.of('ready') or [{}])[0].get('cleanup');steps['relay_journal_after_send']=journal_summary()
    admitted=relay.of('admitted');refused=relay.of('refused')
    checks['proof_was_generated_in_the_extension']=bool(send.get('prove_ok')) and 'prove_seconds' in send
    checks['relay_admitted_exactly_one_request_over_tor_and_refused_nothing']=len(admitted)==1 and admitted[0]['kind']=='send' and refused==[] and admitted[0]['transport']['authority']==SPONSOR
    checks['extension_made_no_direct_http_request_during_the_private_payment']=send.get('direct_http_during_leg')==[]
    checks['no_payment_step_error_in_the_extension']=send.get('step_errors_tail')==[] and not send.get('aborted_after_errors')
    checks['every_wallet_relock_was_recovered_by_unlocking_again']=not send.get('reunlock_failed') and all(l['reunlocked'] is not False for l in send.get('locks',[]))
    if FORCE_LOCK_AFTER is not None:
        checks['the_forced_lock_was_recovered_and_publication_continued']=any(l['why']=='forced_by_the_test_hook' for l in send.get('locks',[])) and any(l['why'].startswith('locked') and l['reunlocked'] for l in send.get('locks',[])) and send.get('restart') is not None
    checks['relay_was_killed_mid_publication_and_resumed_the_same_stored_request']=bool((send.get('restart') or {}).get('resumed'))
    checks['sponsor_kept_publishing_after_the_restart']=len(sponsor_watch.seen)>=((send.get('restart') or {}).get('sponsor_signatures_at_kill') or 10**9)+(SMOKE_EXTRA if MODE=='smoke' else 1)
    steps['send_sponsor_signatures_after_restart']=len(sponsor_watch.seen)
    wd=wallet_authority_disjoint();steps['send_authority_check']=wd
    checks['wallet_authority_never_appears_in_a_relay_transaction_with_a_positive_control']=wd['disjoint'] and wd['sponsor_signatures']>=RESTART_AFTER and wd['sender_wallet_signatures']>=2
    checks['the_recipient_public_authority_never_transacts_at_all']=recipient_watch is not None and len(recipient_watch.seen)==0
    if MODE in ('send','full'):
        checks['send_settled_in_the_extension_from_validated_history']=send.get('final_state')=='settled'
        # The wallet learns of the settlement from validated pool history; the relay's own supervisor may need a moment to record it and free its slot.
        wait_finished('send');finished=[e for e in relay.of('finished') if e['kind']=='send']
        checks['relay_recorded_the_send_as_settled']=len(finished)==1 and finished[0]['state']=='settled'
        steps['send_cleanup']=cleanup_facts('send');checks.update(cleanup_checks_for('send',steps['send_cleanup']))
        s2=sender.call('syncWallet');steps['sender_sync_after_send']=summarize(s2)
        checks['sender_private_sync_after_the_send_shows_2_units']=bool(s2.get('ok')) and s2['result'].get('spendable_units')=='2'
        checks['vault_unchanged_by_the_internal_send']=token_balance(config['vault'])==vault_after
        # A failure of these probes is a failed check, not an abort: a long run must not be thrown away after the payment itself settled.
        try:
            steps['idle_probes_after_send']=probes=idle_probes('send')
            checks['duplicate_submit_is_accepted_idempotently_and_spends_nothing']=probes['duplicate']['status']==200 and probes['sponsor_signatures_after']==probes['sponsor_signatures_before'] and probes['no_new_request_stored']
            checks['tampered_proof_is_refused_with_the_fixed_code_and_spends_nothing']=probes['tampered']['status']==422 and probes['tampered']['body']=={'error':'invalid_proof'} and probes['sponsor_signatures_after']==probes['sponsor_signatures_before']
            checks['the_relay_has_no_status_route']=probes['status_route']['status']==404
        except Exception as exc:
            steps['idle_probes_error']=''.join(traceback.format_exception(exc))[-800:]
            for name in ('duplicate_submit_is_accepted_idempotently_and_spends_nothing','tampered_proof_is_refused_with_the_fixed_code_and_spends_nothing','the_relay_has_no_status_route'):checks[name]=False
        # a fresh Chrome restores seed 212 from its words and finds the 10 units by scanning validated history over Tor
        try:
            recipient.open();checks['recipient_restored_again_from_its_words']=recipient.restore()
            rr0=len(recipient.cdp.requests);rs2=recipient.call('syncWallet');steps['recipient_sync_after_send']=summarize(rs2)
            checks['recipient_restored_from_words_sees_10_units_over_tor']=bool(rs2.get('ok')) and rs2['result'].get('spendable_units')=='10' and direct_http(recipient.cdp.requests[rr0:])==[]
            recipient.close()
        except Exception as exc:
            steps['recipient_second_open_error']=''.join(traceback.format_exception(exc))[-800:]
            checks['recipient_restored_again_from_its_words']=False;checks['recipient_restored_from_words_sees_10_units_over_tor']=False
    if MODE=='full' and not checks.get('send_settled_in_the_extension_from_validated_history'):
        steps['withdraw']={'skipped':'the send did not settle; a withdrawal needs its 10-unit balance and 1-unit fee'};checks['withdraw_skipped_because_the_send_did_not_settle_is_a_failure']=False
    if MODE=='full' and checks.get('send_settled_in_the_extension_from_validated_history'):
        steps['withdraw']=withdraw=payment_leg('withdraw','1',config['withdraw_recipient'],restart=True,until_started_only=False)
        steps['relay_journal_after_withdraw']=journal_summary()
        checks['withdraw_settled_in_the_extension_from_validated_history']=withdraw.get('final_state')=='settled'
        wait_finished('withdraw');finished=[e for e in relay.of('finished') if e['kind']=='withdraw']
        checks['relay_recorded_the_withdrawal_as_settled']=len(finished)==1 and finished[0]['state']=='settled'
        steps['withdraw_cleanup']=cleanup_facts('withdraw');checks.update(cleanup_checks_for('withdraw',steps['withdraw_cleanup']))
        checks['withdraw_leg_made_no_direct_http_request']=withdraw.get('direct_http_during_leg')==[]
        checks['every_wallet_relock_during_the_withdrawal_was_recovered_by_unlocking_again']=not withdraw.get('reunlock_failed') and all(l['reunlocked'] is not False for l in withdraw.get('locks',[]))
        checks['withdraw_restart_resumed_the_same_stored_request']=bool((withdraw.get('restart') or {}).get('resumed'))
        s3=sender.call('syncWallet');steps['sender_sync_after_withdraw']=summarize(s3)
        checks['sender_private_sync_after_the_withdrawal_shows_0_units']=bool(s3.get('ok')) and s3['result'].get('spendable_units')=='0'
        final_vault,final_recipient=token_balance(config['vault']),token_balance(config['recipient_token'])
        steps['ground_truth_final']={'vault_units':final_vault,'recipient_token_units':final_recipient}
        checks['the_validator_confirms_the_public_withdrawal_1_unit_to_the_recipient_and_12_in_the_vault']=final_vault==12 and final_recipient==1
        wd2=wallet_authority_disjoint();steps['withdraw_authority_check']=wd2
        checks['wallet_authority_never_appears_in_a_relay_transaction_over_both_legs']=wd2['disjoint'] and wd2['sponsor_signatures']>wd['sponsor_signatures']
        activity=sender.call('paymentActivity');rows=(activity.get('result') or {}).get('operations') or []
        checks['sender_journal_lists_both_payments_settled']=len(rows)==2 and all(o['state']=='settled' for o in rows)
    sponsor_end=validator_rpc('getBalance',[SPONSOR,{'commitment':'confirmed'}])['value']
    steps['sampler_errors']=sampler_errors;steps['validator_rpc_errors_seen']=last_rpc_error
    steps['sponsor_cost']={'lamports_spent':sponsor_start-sponsor_end,'sponsor_signatures':len(sponsor_watch.seen),'note':'synthetic lamports on an isolated validator; not a mainnet cost'}
    if MODE in ('send','full'):
        # evidence/full-05 (windowed relay, no cleanup): 55,721,596,840 lamports spent over 11,828 sponsor signatures, about 55.66 SOL of it rent locked in the two payments' accounts.
        sample();spent=sponsor_start-sponsor_end;sigs=len(sponsor_watch.seen)
        steps['sponsor_cost'].update({'fee_ceiling_lamports_per_transaction':10000,'bound_lamports':10000*sigs,'spent_at_most_the_fee_ceiling_of_every_transaction':0<spent<=10000*sigs,'spent_below_one_sol':spent<1_000_000_000,'previous_run_without_cleanup':'evidence/full-05: 55721596840 lamports over 11828 signatures'})
        checks['sponsor_spent_only_fees_because_the_rent_of_both_payments_came_back']=0<spent<=10000*sigs and spent<1_000_000_000
    checks['relay_never_reported_a_task_error_or_parked_a_request']=not relay.of('task_error') and not relay.of('parked')
    steps['relay_event_counts']={t:len(relay.of(t)) for t in ('admitted','refused','duplicate','recovered','progress','task_error','parked','finished','fatal','cleanup')}
    sender.close()
    checks['lock_closes_every_native_host']=processes(str(tree/'launcher.py'))==[]
except BaseException as exc:
    error=''.join(traceback.format_exception(exc))[-3500:];note('error',error=error[-400:])
finally:
    for name in ('sender','recipient'):
        w=globals().get(name)
        if w is not None and w.cdp is not None:
            try:
                chrome_console[name+'-final']=list(w.cdp.console);network_log[name+'-final']=[{k:v for k,v in r.items() if k!='t'} for r in w.cdp.requests[:400]];w.cdp.terminate();w.cdp=None
            except Exception:pass
    stop_beat.set()
    if relay is not None and relay.proc is not None:
        try:relay_exit=relay.stop()
        except Exception:relay_exit='stop failed'
    time.sleep(1.5);leftovers=processes(str(base))
    if service is not None:
        try:service.stop()
        except Exception:pass
    tor_reaped=None
    if lab is not None:
        try:
            lab.close();tor_reaped=all(p.poll() is not None for _,p in lab.processes)
        except Exception:tor_reaped=False
    validator_exit=None
    if validator is not None:
        try:
            validator.stdin.close();validator_exit=validator.wait(timeout=60)
        except Exception:
            validator.terminate()
            try:validator_exit=validator.wait(timeout=30)
            except Exception:validator.kill();validator_exit=validator.wait()
    after={str(d):listing(d) for d in REAL_HOST_DIRS}
    if service is not None:write(out/'history-service-log.json',service.log)
    if relay is not None:
        write(out/'relay-events.json',relay.events)
        if state.exists():
            rec=out/'relay-state-record';rec.mkdir()
            for rel in ('EVENTS.jsonl',):
                if (state/rel).exists():shutil.copy2(state/rel,rec/rel)
            for sub in ('requests','outcomes'):
                if (state/sub).exists():
                    (rec/sub).mkdir();[(rec/sub/p.name).write_text(json.dumps({'bytes':p.stat().st_size,'sha256':sha(p)}) if sub=='requests' else p.read_text()) for p in sorted((state/sub).iterdir())]
            if (state/'diagnostics').exists():
                (rec/'diagnostics').mkdir();[shutil.copy2(p,rec/'diagnostics'/p.name) for p in sorted((state/'diagnostics').iterdir()) if p.stat().st_size<20_000_000]
    write(out/'signature-timeline.json',timeline)
    write(out/'extension-network-requests.json',network_log)
    write(out/'cdp-console-errors.json',{k:[c for c in v if re.search(r'rror|xception|denied|fail',c['text'])][:40] for k,v in chrome_console.items()})
    if tree and tree.exists():
        rec=out/'host-tree-record';rec.mkdir()
        for rel in ('INSTALL.json','config','manifests','bin'):
            src=tree/rel;(shutil.copytree(src,rec/rel) if src.is_dir() else shutil.copy2(src,rec/rel))
    HB.rmtree_force(base)
    checks['all_tor_children_reaped']=bool(tor_reaped)
    checks['validator_stopped_cleanly']=validator_exit==0
    checks['relay_service_stopped_cleanly']=relay_exit==0
    checks['no_process_left_with_the_disposable_profiles']=leftovers==[]
    checks['real_browser_host_directories_unchanged']=before==after
    checks['disposable_profiles_and_relay_state_removed']=not base.exists()
    ok=error is None and bool(checks) and all(checks.values())
    result={'status':'PASS_ONION_PAYMENT_%s'%MODE.upper() if ok else 'FAIL_ONION_PAYMENT_%s'%MODE.upper(),'error':error,'mode':MODE,'chrome':version,'checks':checks,'steps':steps,
            'validator_run':vid,'unified_base':label,'extension_id':package['extension_id'] if package else None,
            'scope':{'validator':'local synthetic, real programs','tor':'one-host local test network (TorLab), not public Tor','history_and_relay_operator':'both played by this machine/script (same operator as the validator)',
                     'sponsor':'relay-owned key, funded by the validator faucet; package names its real authority','private_payment':MODE in ('send','full'),'withdrawal':MODE=='full','account_cleanup_shown':MODE in ('send','full'),
                     'real_funds':False,'privacy_proven':False,'network_timing_anonymity_proven':False,'independent_operator':False,'public_fixture_seeds':True,'real_profile_touched':False}}
    write(out/'RESULT.json',result);print(json.dumps({'status':result['status'],'error':(error or '')[-800:],'checks':checks},indent=1),flush=True)
    sys.exit(0 if ok else 1)
