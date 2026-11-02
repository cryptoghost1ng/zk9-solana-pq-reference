// Local relay operational state only: public request hashes, transport IDs and
// signed attempts. No wallet secrets, network address or proof witness storage.
// WINDOWED revision: derived from ../solana-private-relay-v1/relay-repository.mjs (frozen, untouched). Same SQLite
// schema and file format. Differences, all in the funded path: (1) the v2 publication journal holds a LIST of
// pending attempts, so its record may be larger; (2) the list may only shrink (resolution) or go from empty to a
// whole new window, never grow or have an attempt replaced while others are unresolved; (3) a new window is
// debited atomically with its commit, like a single attempt was.
import fs from 'node:fs';
import path from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {createHash} from 'node:crypto';
import {un58} from '../solana-chrome-wallet-v1/recovery/solana-transaction.mjs';
import {requireState as require,hexValue,integer} from '../solana-chrome-wallet-v1/recovery/checkpoint.mjs';
const APP=0x5a4b3952;
const PUBLICATION='zk9-sponsored-publication-journal-v2',SETTLEMENT='zk9-sponsored-settlement-v1';
// 128 signed chunk transactions are about 240 KB of JSON; every other record keeps the original 32 KiB bound.
const WINDOW_RECORD_LIMIT=524288,RECORD_LIMIT=32768;
const units=value=>{require(typeof value==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(value),'Invalid sponsor amount.');const n=BigInt(value);require(n<2n**64n);return n;};
const FUNDING_SCHEMA=`CREATE TABLE IF NOT EXISTS funding_budgets(id TEXT PRIMARY KEY NOT NULL,body TEXT NOT NULL) STRICT;
 CREATE TABLE IF NOT EXISTS funding_reservations(budget TEXT NOT NULL,id TEXT NOT NULL,cap TEXT NOT NULL,used TEXT NOT NULL,PRIMARY KEY(budget,id)) STRICT;
 CREATE TABLE IF NOT EXISTS funded_operations(id TEXT PRIMARY KEY NOT NULL,budget TEXT NOT NULL,request_id TEXT NOT NULL) STRICT;`;
function payload(id,revision,value){
  hexValue(id,32);integer(revision);require(revision>0&&value?.id===id&&value.revision===revision);
  const text=JSON.stringify(value);require(Buffer.byteLength(text)<=(value.version===PUBLICATION?WINDOW_RECORD_LIMIT:RECORD_LIMIT),'Relay record too large.');return text;
}
export class RelayRepository {
  #db;
  constructor(filename){
    require(typeof filename==='string'&&path.isAbsolute(filename),'Absolute local relay database path required.');
    const parent=fs.lstatSync(path.dirname(filename));
    require(parent.isDirectory()&&!parent.isSymbolicLink()&&(parent.mode&0o077)===0&&parent.uid===process.getuid(),
      'Relay database needs an owner-only directory.');
    let created=false;
    try{const fd=fs.openSync(filename,fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_WRONLY|fs.constants.O_NOFOLLOW,0o600);fs.closeSync(fd);created=true;}
    catch(error){if(error.code!=='EEXIST')throw error;}
    const stat=fs.lstatSync(filename);
    require(stat.isFile()&&!stat.isSymbolicLink()&&(stat.mode&0o077)===0&&stat.uid===process.getuid(),'Unsafe relay database file.');
    this.#db=new DatabaseSync(filename,{allowExtension:false,enableDoubleQuotedStringLiterals:false});
    try{
      this.#db.exec('PRAGMA busy_timeout=1000; PRAGMA synchronous=FULL;');
      if(created){
        this.#db.exec(`BEGIN IMMEDIATE; PRAGMA application_id=${APP}; PRAGMA user_version=1;
          CREATE TABLE operations(id TEXT PRIMARY KEY NOT NULL,revision INTEGER NOT NULL CHECK(revision>0),body TEXT NOT NULL) STRICT;
          COMMIT;`);
        // Persist directory entry as well as the SQLite transaction.
        const fd=fs.openSync(path.dirname(filename),fs.constants.O_RDONLY);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
      }
      require(this.#db.prepare('PRAGMA application_id').get().application_id===APP
        &&this.#db.prepare('PRAGMA user_version').get().user_version===1,'Unknown relay database schema.');
      // Additive tables in the same v1 database. Existing signed journals are
      // unchanged. Funding policy is configured explicitly by the local owner.
      this.#db.exec(FUNDING_SCHEMA);
      require(this.#db.prepare('PRAGMA journal_mode=WAL').get().journal_mode==='wal','WAL unavailable.');
      require(this.#db.prepare('PRAGMA synchronous').get().synchronous===2,'Full durability unavailable.');
    }catch(error){this.#db.close();this.#db=null;throw error;}
  }
  async read(id){
    hexValue(id,32);require(this.#db,'Relay database is closed.');
    const row=this.#db.prepare('SELECT revision,body FROM operations WHERE id=?').get(id);if(!row)return null;
    const value=JSON.parse(row.body);payload(id,row.revision,value);return value;
  }
  async compareAndSwap(id,expectedRevision,value){
    require(this.#db,'Relay database is closed.');if(expectedRevision!==null){integer(expectedRevision);require(expectedRevision>0);}
    const revision=(expectedRevision??0)+1,body=payload(id,revision,value);
    this.#db.exec('BEGIN IMMEDIATE');
    try{
      require(!this.#db.prepare('SELECT id FROM funded_operations WHERE id=?').get(id)
        &&!this.#db.prepare('SELECT id FROM funding_reservations WHERE id=?').get(id),
        'Funded operation requires an atomic funding debit.');
      const result=expectedRevision===null
        ?this.#db.prepare('INSERT INTO operations(id,revision,body) VALUES(?,?,?) ON CONFLICT(id) DO NOTHING').run(id,revision,body)
        :this.#db.prepare('UPDATE operations SET revision=?,body=? WHERE id=? AND revision=?').run(revision,body,id,expectedRevision);
      require(result.changes===1,'Concurrent relay journal update; reopen and reconcile.');
      this.#db.exec('COMMIT');
    }catch(error){this.#db.exec('ROLLBACK');throw error;}
    return revision;
  }
  async configureFunding({sponsor,genesis,totalLamports}){
    un58(sponsor,32);un58(genesis,32);
    require(units(totalLamports)>0n&&this.#db);
    const id=createHash('sha256').update(`ZK9/RELAY/FUNDING/v1\0${genesis}\0${sponsor}`).digest('hex');
    const body=JSON.stringify({sponsor,genesis,total_lamports:totalLamports});
    this.#db.exec('BEGIN IMMEDIATE');
    try{
      const row=this.#db.prepare('SELECT body FROM funding_budgets WHERE id=?').get(id);
      if(row)require(row.body===body,'Stored sponsor budget differs; restart cannot reset or enlarge it.');
      else this.#db.prepare('INSERT INTO funding_budgets(id,body) VALUES(?,?)').run(id,body);
      this.#db.exec('COMMIT');return id;
    }catch(error){this.#db.exec('ROLLBACK');throw error;}
  }
  async reserveFunding(budget,id,cap){
    hexValue(budget,32);hexValue(id,32);const maximum=units(cap);require(maximum>0n&&this.#db);
    this.#db.exec('BEGIN IMMEDIATE');
    try{
      const configured=this.#db.prepare('SELECT body FROM funding_budgets WHERE id=?').get(budget);require(configured,'Sponsor budget not configured.');
      const existing=this.#db.prepare('SELECT cap,used FROM funding_reservations WHERE budget=? AND id=?').get(budget,id);
      if(existing)require(existing.cap===cap,'Existing request budget cannot change.');
      else{
        const all=this.#db.prepare('SELECT cap FROM funding_reservations WHERE budget=?').all(budget);require(all.length<10000,'Reservation bound reached.');
        const total=all.reduce((sum,row)=>sum+units(row.cap),0n);
        require(total+maximum<=units(JSON.parse(configured.body).total_lamports),'Sponsor reserve exhausted.');
        this.#db.prepare('INSERT INTO funding_reservations(budget,id,cap,used) VALUES(?,?,?,?)').run(budget,id,cap,'0');
      }
      this.#db.exec('COMMIT');return this.funding(budget,id);
    }catch(error){this.#db.exec('ROLLBACK');throw error;}
  }
  async funding(budget,id){
    hexValue(budget,32);hexValue(id,32);require(this.#db);
    const row=this.#db.prepare('SELECT cap,used FROM funding_reservations WHERE budget=? AND id=?').get(budget,id);require(row,'Missing request reserve.');
    require(units(row.used)<=units(row.cap));return {cap_lamports:row.cap,charged_lamports:row.used};
  }
  async compareAndSwapFunded({id,expectedRevision,value,budget,requestId,debitLamports}){
    require(this.#db);hexValue(budget,32);hexValue(requestId,32);const debit=units(debitLamports);
    if(expectedRevision!==null){integer(expectedRevision);require(expectedRevision>0);}
    const revision=(expectedRevision??0)+1,body=payload(id,revision,value);
    require(value.version===PUBLICATION?id===requestId
      :value.version===SETTLEMENT&&value.request_id===requestId,'Foreign funded journal.');
    this.#db.exec('BEGIN IMMEDIATE');
    try{
      const configured=this.#db.prepare('SELECT body FROM funding_budgets WHERE id=?').get(budget);require(configured,'Unknown sponsor budget.');
      require(JSON.parse(configured.body).sponsor===value.transport?.authority,'Wrong sponsor for funded operation.');
      const reservation=this.#db.prepare('SELECT cap,used FROM funding_reservations WHERE budget=? AND id=?').get(budget,requestId);require(reservation,'Request not reserved.');
      const old=this.#db.prepare('SELECT revision,body FROM operations WHERE id=?').get(id);
      require((old?.revision??null)===expectedRevision,'Concurrent funded journal update.');
      const binding=this.#db.prepare('SELECT budget,request_id FROM funded_operations WHERE id=?').get(id);
      if(binding)require(binding.budget===budget&&binding.request_id===requestId,'Funded journal cannot switch budgets.');
      // Existing unbudgeted journals cannot be adopted without a separate,
      // audited migration accounting for their already-released signed bytes.
      else require(!old,'Cannot adopt an existing unbudgeted journal.');
      if(old){const previous=JSON.parse(old.body);require(previous.version===value.version
        &&previous.wire_hash===value.wire_hash&&JSON.stringify(previous.transport)===JSON.stringify(value.transport),
        'Funded operation identity changed.');}
      // The publication journal holds a LIST of pending attempts, the settlement journal one attempt or null.
      const attemptsOf=(version,pending)=>version===PUBLICATION?(require(Array.isArray(pending),'Pending attempt list required.'),pending):pending?[pending]:[];
      const stored=old?JSON.parse(old.body):null;
      const before=stored?attemptsOf(stored.version,stored.pending):[],after=attemptsOf(value.version,value.pending);
      const kept=new Map(before.map(a=>[a.signature,a]));
      require(new Set(after.map(a=>a.signature)).size===after.length,'Duplicate pending attempt.');
      for(const a of after)if(kept.has(a.signature))require(kept.get(a.signature).raw===a.raw,'Cannot replace unresolved funded transaction.');
      const added=after.filter(a=>!kept.has(a.signature));
      // New attempts enter only an EMPTY list; an unresolved transaction is never joined or replaced.
      require(!before.length||!added.length,'Cannot replace unresolved funded transaction.');
      const newlySigned=added.length>0;
      require(newlySigned?debit>0n:debit===0n,'Funding debit must match a new signed attempt.');
      const used=units(reservation.used)+debit;require(used<=units(reservation.cap),'Request funding limit exceeded.');
      if(!binding)this.#db.prepare('INSERT INTO funded_operations(id,budget,request_id) VALUES(?,?,?)').run(id,budget,requestId);
      if(old)this.#db.prepare('UPDATE operations SET revision=?,body=? WHERE id=?').run(revision,body,id);
      else this.#db.prepare('INSERT INTO operations(id,revision,body) VALUES(?,?,?)').run(id,revision,body);
      this.#db.prepare('UPDATE funding_reservations SET used=? WHERE budget=? AND id=?').run(used.toString(),budget,requestId);
      this.#db.exec('COMMIT');return revision;
    }catch(error){this.#db.exec('ROLLBACK');throw error;}
  }
  close(){if(this.#db){this.#db.close();this.#db=null;}}
}
