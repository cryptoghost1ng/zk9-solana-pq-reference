// PUBLIC SYNTHETIC fixture helper, not a wallet interface. No user key inputs.
package main

import (
 "encoding/hex"
 "encoding/json"
 "fmt"
 "os"
 nd "zk9.local/notedelivery"
)
type request struct { Amounts []uint64; Rhos []string }
func main() {
 var req request
 if err:=json.NewDecoder(os.Stdin).Decode(&req);err!=nil {panic(err)}
 var c nd.Context;var seed [32]byte
 for i:=0;i<32;i++ {c.Network[i]=1;c.Genesis[i]=2;c.Asset[i]=3;seed[i]=211}
 k,err:=nd.Derive(seed,c);if err!=nil {panic(err)}
 owner:=nd.Owner(k.Spend)
 packets:=[]string{};cms:=[]string{}
 if len(req.Amounts)!=len(req.Rhos) || (len(req.Amounts)!=0 && len(req.Amounts)!=2) {panic("fixture shape")}
 for i,amount:=range req.Amounts {
  rho,err:=hex.DecodeString(req.Rhos[i]);if err!=nil || len(rho)!=32 {panic("rho")}
  n:=nd.Note{Owner:owner,Amount:amount};copy(n.Rho[:],rho)
  cm:=n.Commitment(c)
  packet,err:=nd.Seal(k.Receive.EncapsulationKey().Bytes(),c,uint8(i),n);if err!=nil {panic(err)}
  opened,err:=nd.Open(k,c,cm,uint8(i),packet);if err!=nil || opened!=n {panic("decryption mismatch")}
  tampered:=append([]byte{},packet...);tampered[len(tampered)-1]^=1
  if _,err=nd.Open(k,c,cm,uint8(i),tampered);err==nil {panic("tampered ciphertext accepted")}
  if _,err=nd.Open(k,c,cm,uint8(1-i),packet);err==nil {panic("wrong slot accepted")}
  packets=append(packets,hex.EncodeToString(packet));cms=append(cms,hex.EncodeToString(cm[:]))
 }
 out:=map[string]any{"synthetic":true,"seed_byte":211,"spend":hex.EncodeToString(k.Spend[:]),"owner":hex.EncodeToString(owner[:]),"packets":packets,"commitments":cms,"decrypt_roundtrip":true}
 if err=json.NewEncoder(os.Stdout).Encode(out);err!=nil {panic(fmt.Sprint(err))}
}
