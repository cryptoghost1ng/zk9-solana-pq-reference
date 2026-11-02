//! Authentication of all binary FRI rounds for the pinned ZK9 profile.
//! Does not verify AIR/quotient constraints or authorize a spend.
#![no_std]
#![forbid(unsafe_code)]
use arithmetic::{fold, field::P};
use mmcs::{Cursor, Digest, hash};
pub use mmcs::Error;
pub const STATE_BYTES: usize = 64 + 72 * 64;
pub const MAX_LEAVES: usize = 32;
pub const MAX_PARENTS: usize = 32;

/// Borrowed, verifier-derived reconstructed rows plus authenticated scan metadata.
/// The owning program must bind every argument to the SAME immutable proof and session.
pub struct View<'a, 's> {
    bytes: &'a [u8],
    salts: &'a [u8],
    siblings_start: usize,
    siblings_count: usize,
    folded: fold::Progress<'s>,
    root: Digest,
    round: usize,
}
impl<'a, 's> View<'a, 's> {
    #[inline(never)]
    pub fn from_trusted_scan(wire: &'a [u8], format: &[u8], index: &[u8], rounds: &[u8], folded: &'s mut [u8], round: usize) -> Result<Self, Error> {
        if round >= 13 || rounds.len() != 104 { return Err(Error::Shape); }
        let proof = wire.get(3904..).ok_or(Error::Encoding)?;
        let reader = fri::scan::Reader::resume_trusted(proof, format).map_err(|_| Error::Format)?;
        if !reader.done() { return Err(Error::Format); }
        let index = fri::Index::resume_trusted(index, &reader).map_err(|_| Error::State)?;
        let whole = index.spans[5];
        if proof.get(whole.start as usize) != Some(&13) { return Err(Error::Shape); }
        let mut previous = whole.start as usize + 1;
        let mut selected = (0, 0);
        for (r, span) in rounds.chunks_exact(8).enumerate() {
            let start = num(span, 0); let end = num(span, 4);
            if start != previous || start >= end || end > whole.end as usize { return Err(Error::State); }
            previous = end;
            if r == round { selected = (start, end); }
        }
        if previous != whole.end as usize { return Err(Error::State); }
        // Read every cap, enforcing the exact profile and canonical integer encodings.
        let span = index.spans[2];
        let mut caps = Cursor { bytes: proof.get(span.start as usize..span.end as usize).ok_or(Error::Encoding)?, at: 0 };
        caps.count(13)?;
        let mut root = [0; 8];
        for r in 0..13 { caps.count(1)?; let digest = caps.digest()?; if r == round { root = digest; } }
        caps.end()?;
        Self::from_round_bytes(proof.get(selected.0..selected.1).ok_or(Error::Encoding)?, folded, round, root)
    }

    /// Low-level entry point. Root, round and completed fold state must be verifier-derived.
    /// A caller-supplied root or arbitrary fold state does NOT establish proof validity.
    pub fn from_round_bytes(bytes: &'a [u8], folded: &'s mut [u8], round: usize, root: Digest) -> Result<Self, Error> {
        if round >= 13 { return Err(Error::Shape); }
        let folded = fold::Progress::resume_trusted(folded).map_err(|_| Error::State)?;
        if !folded.done() { return Err(Error::State); }
        let mut c = Cursor { bytes, at: 0 };
        c.count(64)?;
        for _ in 0..64 { c.count(1)?; for raw in c.take(32)?.chunks_exact(4) { if num(raw, 0) >= P as usize { return Err(Error::Encoding); } } }
        c.count(64)?;
        let start = c.at;
        for _ in 0..64 { c.count(1)?; c.count(16)?; c.take(64)?; }
        let salts = &bytes[start..c.at];
        let siblings_count = usize::try_from(c.uint()?).map_err(|_| Error::Encoding)?;
        if siblings_count > 64 * (15 - round) { return Err(Error::Shape); }
        let siblings_start = c.at;
        let len = bytes.len() - siblings_start;
        if len < siblings_count * 8 || len > siblings_count * 80 { return Err(Error::Encoding); }
        Ok(Self { bytes, salts, siblings_start, siblings_count, folded, root, round })
    }
    pub fn root(&self) -> Digest { self.root }
    pub fn round(&self) -> usize { self.round }
    pub fn depth(&self) -> usize { 15 - self.round }
    pub fn index(&self, q: usize) -> Result<usize, Error> {
        let index = self.folded.index(self.round, q).map_err(|_| Error::State)?;
        if index >= (1 << self.depth()) { return Err(Error::State); }
        Ok(index)
    }
    fn salt(&self, q: usize) -> Result<&[u8], Error> {
        self.salts.get(q * 66 + 2..q * 66 + 66).ok_or(Error::Encoding)
    }
    fn equal(&self, a: usize, b: usize) -> Result<bool, Error> {
        Ok(self.folded.row(self.round, a).map_err(|_| Error::State)? == self.folded.row(self.round, b).map_err(|_| Error::State)? && self.salt(a)? == self.salt(b)?)
    }
    fn leaf(&self, q: usize) -> Result<Digest, Error> {
        let pair = self.folded.row(self.round, q).map_err(|_| Error::State)?;
        let mut hash = hash::WordHash::default();
        // SerializingHasher packs two RAW Montgomery u32 values into each u64.
        for ext in pair { for fields in ext.0.chunks_exact(2) { hash.word(u64::from(fields[0].montgomery()) | (u64::from(fields[1].montgomery()) << 32)); } }
        for fields in self.salt(q)?.chunks_exact(8) {
            let a = num(fields, 0); let b = num(fields, 4);
            if a >= P as usize || b >= P as usize { return Err(Error::Encoding); }
            hash.word(a as u64 | ((b as u64) << 32));
        }
        Ok(hash.finish())
    }
}
fn num(b: &[u8], at: usize) -> usize { u32::from_le_bytes(b[at..at+4].try_into().unwrap()) as usize }
fn put(b: &mut [u8], at: usize, n: usize) { b[at..at+4].copy_from_slice(&(n as u32).to_le_bytes()); }
fn node(b: &[u8], slot: usize) -> (usize, usize, Digest) {
    let at = 64 + 72 * slot;
    let mut digest = [0; 8];
    for (x, raw) in digest.iter_mut().zip(b[at+8..at+72].chunks_exact(8)) { *x = u64::from_le_bytes(raw.try_into().unwrap()); }
    (num(b, at), num(b, at+4), digest)
}
fn setnode(b: &mut [u8], slot: usize, index: usize, q: usize, digest: Digest) {
    let at = 64 + 72 * slot; put(b, at, index); put(b, at+4, q);
    for (x, raw) in digest.iter().zip(b[at+8..at+72].chunks_exact_mut(8)) { raw.copy_from_slice(&x.to_le_bytes()); }
}
/// Caller-owned frontier; no heap allocation or 4 KiB stack array.
/// On Err, native callers must discard mutations; Solana rolls them back atomically.
pub struct Progress<'s> { saved: &'s mut [u8] }
impl<'s> Progress<'s> {
    pub fn start(saved: &'s mut [u8], view: &View) -> Result<Self, Error> {
        if saved.len() != STATE_BYTES || saved.iter().any(|x| *x != 0) { return Err(Error::State); }
        let mut order = core::array::from_fn::<_,64,_>(|i| i as u8);
        // Check bounds before sorting; comparator cannot propagate a malformed-state error.
        for q in 0..64 { view.index(q)?; }
        order.sort_unstable_by_key(|q| (view.index(*q as usize).unwrap(), *q));
        let mut count = 0; let mut previous = None;
        for q in order { let q = q as usize; let index = view.index(q)?;
            if let Some((i, p)) = previous { if index == i { if !view.equal(p, q)? { return Err(Error::Duplicate); } continue; } }
            setnode(saved, count, index, q, [0; 8]); count += 1; previous = Some((index, q));
        }
        saved[..8].copy_from_slice(b"ZK9RMM01"); saved[8] = view.round as u8; saved[9] = 1;
        put(saved, 12, count); put(saved, 32, view.siblings_start);
        Ok(Self { saved })
    }
    /// Shape checking only: the owning program authenticates state and immutable-source binding.
    pub fn resume_trusted(saved: &'s mut [u8]) -> Result<Self, Error> {
        if saved.len() != STATE_BYTES || &saved[..8] != b"ZK9RMM01" || saved[8] >= 13 || !(1..=3).contains(&saved[9]) || saved[10..12] != [0; 2] || saved[20..24] != [0; 4] || saved[44..64] != [0;20] { return Err(Error::State); }
        let count = num(saved, 12); let depth = 15 - saved[8] as usize;
        if !(1..=64).contains(&count) || num(saved,16) > count || num(saved,24) > depth || num(saved,28) > count || num(saved,40) > count || num(saved,36) > 64 * depth { return Err(Error::State); }
        if saved[9] == 3 && (count != 1 || num(saved,24) != depth || node(saved,0).0 != 0) { return Err(Error::State); }
        Ok(Self { saved })
    }
    pub fn done(&self) -> bool { self.saved[9] == 3 }
    pub fn result(&self) -> Option<Digest> { self.done().then(|| node(self.saved, 0).2) }
    pub fn advance(&mut self, view: &View, leaves: usize, parents: usize) -> Result<bool, Error> {
        if leaves == 0 || leaves > MAX_LEAVES || parents == 0 || parents > MAX_PARENTS { return Err(Error::Limit); }
        if self.done() { return Err(Error::Done); }
        let s = &mut *self.saved;
        if s[8] as usize != view.round { return Err(Error::State); }
        let count = num(s,12);
        if s[9] == 1 {
            let start = num(s,16); if start >= count { return Err(Error::State); }
            let end = (start + leaves).min(count);
            for slot in start..end { let (index,q,_) = node(s,slot); if q >= 64 || index != view.index(q)? { return Err(Error::State); } setnode(s,slot,index,q,view.leaf(q)?); }
            put(s,16,end); if end == count { s[9] = 2; }
            return Ok(false);
        }
        let level = num(s,24); if level >= view.depth() { return Err(Error::State); }
        let mut input = num(s,28); let mut output = num(s,40);
        let mut c = Cursor { bytes: view.bytes, at: num(s,32) }; let mut used = num(s,36);
        if c.at < view.siblings_start || c.at > view.bytes.len() || used > view.siblings_count { return Err(Error::State); }
        for _ in 0..parents {
            if input == count { break; }
            let (index,q,digest) = node(s,input); let mut next = input+1;
            let (left,right) = if index & 1 == 0 && next < count && node(s,next).0 == index+1 { let right = node(s,next).2; next += 1; (digest,right) }
            else { if used >= view.siblings_count { return Err(Error::Siblings); } let sibling = c.digest()?; used += 1; if index & 1 == 0 { (digest,sibling) } else { (sibling,digest) } };
            setnode(s,output,index>>1,q,hash::compress(left,right)); output += 1; input = next;
        }
        put(s,28,input); put(s,40,output); put(s,32,c.at); put(s,36,used);
        if input == count {
            put(s,12,output); put(s,28,0); put(s,40,0); put(s,24,level+1); put(s,16,0);
            if level+1 == view.depth() {
                if output != 1 || node(s,0).0 != 0 { return Err(Error::State); }
                if used != view.siblings_count || c.at != view.bytes.len() { return Err(Error::Siblings); }
                if node(s,0).2 != view.root { return Err(Error::Root); }
                s[9] = 3;
            }
        }
        Ok(self.done())
    }
}
