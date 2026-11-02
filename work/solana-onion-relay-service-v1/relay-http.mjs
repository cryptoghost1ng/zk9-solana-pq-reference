// Loopback-only HTTP front of the relay. It is meant to sit behind a v3 onion service and never learns who a caller is:
// it keeps no per-caller state and its replies carry no progress. Errors are fixed codes; internal messages never leave.
import http from 'node:http';
import {requireState as require} from '../solana-chrome-wallet-v1/recovery/checkpoint.mjs';

export const MAX_BODY=Math.ceil((4*1024*1024+3945)/3)*4+128;   // the same bound the native relay host enforces
export const SCOPE='local-onion-relay-service';
const ONION=/^[a-z2-7]{56}\.onion$/;

export function createRelayHttp({offer,submit,maximum=MAX_BODY,hostPattern=ONION,requestTimeout=120000}) {
  require(typeof offer==='function'&&typeof submit==='function'&&hostPattern instanceof RegExp,'Relay handlers required.');
  let expectedHost=null;
  const reply=(res,status,value)=>{
    const body=Buffer.from(JSON.stringify(value));
    res.writeHead(status,{'Content-Type':'application/json','Content-Length':body.length,'Connection':'close'});res.end(body);
  };
  const server=http.createServer({maxHeaderSize:16384,requestTimeout,headersTimeout:15000},async(req,res)=>{
    try{
      // Until the operator binds the onion name, and for any other Host, the service answers nothing useful.
      if(expectedHost===null||req.headers.host!==expectedHost)return reply(res,421,{error:'host'});
      if(req.method==='GET'&&req.url==='/health')return reply(res,200,{scope:SCOPE});
      if(req.method!=='POST'||!['/v1/offer','/v1/submit'].includes(req.url))return reply(res,404,{error:'route'});
      const length=req.headers['content-length'];
      if(req.headers['transfer-encoding']||!/^[1-9][0-9]*$/.test(length??'')||Number(length)>maximum||req.headers['content-type']!=='application/json')
        return reply(res,413,{error:'framing'});
      const chunks=[];let size=0;
      for await(const part of req){size+=part.length;require(size<=Number(length),'Body longer than declared.');chunks.push(part);}
      require(size===Number(length),'Body shorter than declared.');
      const raw=new Uint8Array(Buffer.concat(chunks));
      if(req.url==='/v1/offer') {
        const text=new TextDecoder('utf-8',{fatal:true}).decode(raw),value=JSON.parse(text);
        require(JSON.stringify(value)===text,'Noncanonical offer.');
        return reply(res,200,await offer(value));
      }
      const result=await submit(raw);
      require(Number.isInteger(result?.status)&&result.status>=200&&result.status<=599,'Invalid relay result.');
      return reply(res,result.status,result.body);
    }catch{
      if(!res.headersSent)reply(res,400,{error:'rejected'});else res.destroy();
    }
  });
  return Object.freeze({
    listen:(port=0)=>new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',()=>resolve(server.address().port));}),
    // Bound exactly once, by the operator, after the onion name is known.
    setHost(host) {
      require(expectedHost===null&&typeof host==='string'&&hostPattern.test(host),'The relay host can be bound once, to an onion name.');
      expectedHost=host;
    },
    close:()=>new Promise(resolve=>{server.closeAllConnections();server.close(()=>resolve());}),
  });
}
