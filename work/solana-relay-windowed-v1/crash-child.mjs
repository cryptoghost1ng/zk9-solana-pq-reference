// Child process of the windowed checks: signs one chunk window through the REAL sender, journal and SQLite and dies by SIGKILL at a
// chosen point of the durable commit. The parent then reopens the same database and looks at what survived.
// usage: crash-child.mjs DIR before-commit|after-commit
import {makeEnv} from './harness.mjs';
const [dir,mode]=process.argv.slice(2);
if(!['before-commit','after-commit'].includes(mode))throw Error('unknown mode');
const window=e=>Array.isArray(e.value.pending)&&e.value.pending.length>1;
const wrap=base=>({...base,compareAndSwapFunded:async a=>{
  if(mode==='before-commit'&&window(a))process.kill(process.pid,'SIGKILL');
  const result=await base.compareAndSwapFunded(a);
  if(mode==='after-commit'&&window(a))process.kill(process.pid,'SIGKILL');
  return result;
}});
const env=await makeEnv({kind:'send',window:16,dir,wrap});
await env.step();
throw Error('the child was expected to die inside the window commit');
