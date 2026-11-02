// Package notedelivery implements a versioned EXPERIMENTAL note format.
// It does not authenticate a blockchain, prove ML-KEM recipient anonymity,
// provide forward secrecy, or replace the consensus proof and nullifier checks.
package notedelivery

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/binary"
	"errors"
)

const PaddedBytes = 128
const PacketBytes = 8 + mlkem.CiphertextSize1024 + 12 + PaddedBytes + 16

var magic = [8]byte{'Z', 'K', '9', 'N', 'D', 'L', 1, 1}
var errNote = errors.New("invalid encrypted note")

type Context struct{ Network, Genesis, Asset [32]byte }
type Note struct {
	Owner  [64]byte
	Rho    [32]byte
	Amount uint64
}
type Keys struct {
	Spend   [32]byte
	Receive *mlkem.DecapsulationKey1024
}

func (c Context) valid() bool {
	return c.Network != [32]byte{} && c.Genesis != [32]byte{} && c.Asset != [32]byte{}
}
func (c Context) bytes() []byte {
	b := append([]byte{}, c.Network[:]...)
	b = append(b, c.Genesis[:]...)
	return append(b, c.Asset[:]...)
}

// Derive is deterministic and network/genesis/asset separated. Callers provide
// a high-entropy wallet seed, never a password. Imported all-zero seeds fail.
// Seeds are NOT serialized in addresses or payment envelopes.
func Derive(seed [32]byte, c Context) (*Keys, error) {
	if seed == [32]byte{} || !c.valid() {
		return nil, errors.New("invalid wallet seed or context")
	}
	salt := sha512.Sum512(append([]byte("ZK9/NOTE-DELIVERY/SEED/v1\x00"), c.bytes()...))
	spend, e := hkdf.Key(sha512.New, seed[:], salt[:], "spend-secret", 32)
	if e != nil {
		return nil, e
	}
	defer clear(spend)
	receive, e := hkdf.Key(sha512.New, seed[:], salt[:], "ML-KEM-1024-receive", 64)
	if e != nil {
		return nil, e
	}
	defer clear(receive)
	key, e := mlkem.NewDecapsulationKey1024(receive)
	if e != nil {
		return nil, e
	}
	k := &Keys{Receive: key}
	copy(k.Spend[:], spend)
	return k, nil
}
func Generate(c Context) (*Keys, [32]byte, error) {
	var seed [32]byte
	if _, e := rand.Read(seed[:]); e != nil {
		return nil, [32]byte{}, e
	}
	k, e := Derive(seed, c)
	if e != nil {
		clear(seed[:])
	}
	return k, seed, e
}
func Owner(secret [32]byte) [64]byte { return sha3.Sum512(append([]byte("ZK9ADR01"), secret[:]...)) }
func (n Note) Commitment(c Context) [64]byte {
	b := append([]byte("ZK9NOT01"), c.bytes()...)
	b = append(b, n.Owner[:]...)
	b = append(b, n.Rho[:]...)
	b = binary.LittleEndian.AppendUint64(b, n.Amount)
	return sha3.Sum512(b)
}
func (n Note) Nullifier(c Context, secret [32]byte) [64]byte {
	b := append([]byte("ZK9NUL01"), c.Network[:]...)
	b = append(b, c.Genesis[:]...)
	b = append(b, secret[:]...)
	cm := n.Commitment(c)
	return sha3.Sum512(append(b, cm[:]...))
}
func associated(c Context, cm [64]byte, slot uint8) ([]byte, error) {
	if !c.valid() || cm == [64]byte{} || slot > 1 {
		return nil, errNote
	}
	b := append([]byte("ZK9/NOTE-DELIVERY/ENCRYPTION/v1\x00"), c.bytes()...)
	b = append(b, cm[:]...)
	return append(b, slot), nil
}
func makeAEAD(shared, pub, ct, context []byte) (cipher.AEAD, error) {
	h := sha512.New()
	h.Write([]byte("ZK9/NOTE-DELIVERY/KDF/v1\x00"))
	h.Write(pub)
	h.Write(ct)
	h.Write(context)
	key, e := hkdf.Key(sha512.New, shared, h.Sum(nil), "AES-256-GCM", 32)
	if e != nil {
		return nil, e
	}
	defer clear(key)
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(block)
}

// Seal authenticates the expected commitment and output slot. The address
// containing owner + encapsulation key must itself be authenticated by the user.
func Seal(pub []byte, c Context, slot uint8, n Note) ([]byte, error) {
	if n.Owner == [64]byte{} {
		return nil, errNote
	}
	context, e := associated(c, n.Commitment(c), slot)
	if e != nil {
		return nil, e
	}
	pk, e := mlkem.NewEncapsulationKey1024(pub)
	if e != nil {
		return nil, e
	}
	shared, ct := pk.Encapsulate()
	defer clear(shared)
	a, e := makeAEAD(shared, pub, ct, context)
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, a.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	plain := make([]byte, PaddedBytes)
	defer clear(plain)
	copy(plain, n.Owner[:])
	copy(plain[64:], n.Rho[:])
	binary.LittleEndian.PutUint64(plain[96:], n.Amount)
	header := append(append(append([]byte{}, magic[:]...), ct...), nonce...)
	aad := append(append([]byte{}, context...), header...)
	return a.Seal(header, nonce, plain, aad), nil
}

// Open returns a note only after AEAD, canonical padding, ownership and output
// commitment checks. Caller must first verify the proof and accepted chain state.
func Open(k *Keys, c Context, cm [64]byte, slot uint8, packet []byte) (Note, error) {
	fail := func() (Note, error) { return Note{}, errNote }
	if k == nil || k.Receive == nil || len(packet) != PacketBytes || !bytes.Equal(packet[:8], magic[:]) {
		return fail()
	}
	context, e := associated(c, cm, slot)
	if e != nil {
		return fail()
	}
	end := 8 + mlkem.CiphertextSize1024
	ct := packet[8:end]
	nonce := packet[end : end+12]
	shared, e := k.Receive.Decapsulate(ct)
	if e != nil {
		return fail()
	}
	defer clear(shared)
	a, e := makeAEAD(shared, k.Receive.EncapsulationKey().Bytes(), ct, context)
	if e != nil {
		return fail()
	}
	aad := append(append([]byte{}, context...), packet[:end+12]...)
	plain, e := a.Open(nil, nonce, packet[end+12:], aad)
	if e != nil {
		return fail()
	}
	defer clear(plain)
	if len(plain) != PaddedBytes {
		return fail()
	}
	for _, b := range plain[104:] {
		if b != 0 {
			return fail()
		}
	}
	var n Note
	copy(n.Owner[:], plain[:64])
	copy(n.Rho[:], plain[64:96])
	n.Amount = binary.LittleEndian.Uint64(plain[96:104])
	if n.Owner != Owner(k.Spend) || n.Commitment(c) != cm {
		return fail()
	}
	return n, nil
}

// DeliveryDigest is public and slot/context separated; Rust recomputes it from
// mandatory fixed-size packets before checking the bound STARK proof.
func DeliveryDigest(c Context, cm [64]byte, slot uint8, packet []byte) ([64]byte, error) {
	if !c.valid() || cm == [64]byte{} || slot > 1 || len(packet) != PacketBytes {
		return [64]byte{}, errNote
	}
	b := append([]byte("ZK9/NOTE-DELIVERY/DIGEST/v1\x00"), c.bytes()...)
	b = append(b, cm[:]...)
	b = append(b, slot)
	b = append(b, packet...)
	return sha3.Sum512(b), nil
}
