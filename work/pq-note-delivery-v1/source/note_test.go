package notedelivery

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func repeated[T ~[32]byte](b byte) (r T) {
	for i := range r {
		r[i] = b
	}
	return
}
func testContext() Context {
	return Context{repeated[[32]byte](1), repeated[[32]byte](2), repeated[[32]byte](3)}
}
func testNote(k *Keys) Note {
	return Note{Owner: Owner(k.Spend), Rho: repeated[[32]byte](112), Amount: 900000}
}

func TestSeedRecoveryAndRandomizedEncryption(t *testing.T) {
	c := testContext()
	seed := repeated[[32]byte](201)
	k, e := Derive(seed, c)
	if e != nil {
		t.Fatal(e)
	}
	n := testNote(k)
	packet, e := Seal(k.Receive.EncapsulationKey().Bytes(), c, 0, n)
	if e != nil {
		t.Fatal(e)
	}
	if len(packet) != 1732 {
		t.Fatal(len(packet))
	}
	restored, e := Derive(seed, c)
	if e != nil {
		t.Fatal(e)
	}
	got, e := Open(restored, c, n.Commitment(c), 0, packet)
	if e != nil || got != n {
		t.Fatal(got, e)
	}
	other, e := Seal(k.Receive.EncapsulationKey().Bytes(), c, 0, n)
	if e != nil || bytes.Equal(packet, other) {
		t.Fatal("encryption must use fresh randomness", e)
	}
	if _, e = Derive([32]byte{}, c); e == nil {
		t.Fatal("zero seed")
	}
	if _, e = Derive(seed, Context{}); e == nil {
		t.Fatal("zero context")
	}
	for i := 0; i < 3; i++ {
		cc := c
		switch i {
		case 0:
			cc.Network[0] ^= 1
		case 1:
			cc.Genesis[0] ^= 1
		case 2:
			cc.Asset[0] ^= 1
		}
		kk, e := Derive(seed, cc)
		if e != nil {
			t.Fatal(e)
		}
		if kk.Spend == k.Spend || bytes.Equal(kk.Receive.EncapsulationKey().Bytes(), k.Receive.EncapsulationKey().Bytes()) {
			t.Fatal("key separation")
		}
	}
	generated, s, e := Generate(c)
	if e != nil || s == [32]byte{} || generated == nil {
		t.Fatal("OS entropy", e)
	}
}
func TestRejectWrongRecipientContextSlotAndEveryPacketByte(t *testing.T) {
	c := testContext()
	k, _ := Derive(repeated[[32]byte](201), c)
	n := testNote(k)
	cm := n.Commitment(c)
	p, e := Seal(k.Receive.EncapsulationKey().Bytes(), c, 0, n)
	if e != nil {
		t.Fatal(e)
	}
	// Both header/encapsulation bytes and every AEAD byte must be authenticated.
	for i := range p {
		bad := bytes.Clone(p)
		bad[i] ^= 1
		got, e := Open(k, c, cm, 0, bad)
		if e == nil || got != (Note{}) {
			t.Fatalf("accepted mutation %d", i)
		}
	}
	for size := 0; size < len(p); size++ {
		if _, e := Open(k, c, cm, 0, p[:size]); e == nil {
			t.Fatalf("truncation %d", size)
		}
	}
	for _, bad := range [][]byte{append(bytes.Clone(p), 0), nil} {
		if _, e := Open(k, c, cm, 0, bad); e == nil {
			t.Fatal("framing")
		}
	}
	wrong, _ := Derive(repeated[[32]byte](202), c)
	if _, e := Open(wrong, c, cm, 0, p); e == nil {
		t.Fatal("wrong recipient")
	}
	wrongSpend := *k
	wrongSpend.Spend[0] ^= 1
	if _, e := Open(&wrongSpend, c, cm, 0, p); e == nil {
		t.Fatal("spend owner mismatch")
	}
	badcm := cm
	badcm[0] ^= 1
	if _, e := Open(k, c, badcm, 0, p); e == nil {
		t.Fatal("commitment")
	}
	for _, slot := range []uint8{1, 2, 255} {
		if _, e := Open(k, c, cm, slot, p); e == nil {
			t.Fatal("slot")
		}
	}
	for i := 0; i < 3; i++ {
		cc := c
		switch i {
		case 0:
			cc.Network[0] ^= 1
		case 1:
			cc.Genesis[0] ^= 1
		case 2:
			cc.Asset[0] ^= 1
		}
		if _, e := Open(k, cc, cm, 0, p); e == nil {
			t.Fatal("context")
		}
	}
	if _, e := Seal([]byte{1}, c, 0, n); e == nil {
		t.Fatal("bad public key")
	}
}
func TestAuthenticatedWrongPlaintextStillRejected(t *testing.T) {
	c := testContext()
	k, _ := Derive(repeated[[32]byte](201), c)
	n := testNote(k)
	cm := n.Commitment(c)
	context, _ := associated(c, cm, 0)
	// A malicious sender can encrypt arbitrary bytes. The receiver independently
	// recomputes the note commitment instead of trusting AEAD success alone.
	for _, field := range []int{0, 64, 96, 104, 127} {
		shared, ct := k.Receive.EncapsulationKey().Encapsulate()
		a, e := makeAEAD(shared, k.Receive.EncapsulationKey().Bytes(), ct, context)
		clear(shared)
		if e != nil {
			t.Fatal(e)
		}
		plain := make([]byte, PaddedBytes)
		copy(plain, n.Owner[:])
		copy(plain[64:], n.Rho[:])
		binary.LittleEndian.PutUint64(plain[96:], n.Amount)
		plain[field] ^= 1
		nonce := make([]byte, 12)
		header := append(append(append([]byte{}, magic[:]...), ct...), nonce...)
		packet := a.Seal(header, nonce, plain, append(bytes.Clone(context), header...))
		if got, e := Open(k, c, cm, 0, packet); e == nil || got != (Note{}) {
			t.Fatalf("accepted authenticated bad plaintext at %d", field)
		}
	}
}

type Fixture struct {
	Warning     string
	Context     Context
	Seeds       [2][32]byte
	Notes       [2]Note
	Commitments [2][64]byte
	Digests     [2][64]byte
}

func TestExportSyntheticFixture(t *testing.T) {
	dir := os.Getenv("ZK9_NOTE_FIXTURE")
	if dir == "" {
		t.Skip("explicit synthetic fixture export only")
	}
	if !filepath.IsAbs(dir) {
		t.Fatal("absolute fresh destination required")
	}
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	f := Fixture{Warning: "PUBLIC SYNTHETIC SEEDS - NEVER FUND", Context: testContext(), Seeds: [2][32]byte{repeated[[32]byte](201), repeated[[32]byte](202)}}
	for i := 0; i < 2; i++ {
		k, e := Derive(f.Seeds[i], f.Context)
		if e != nil {
			t.Fatal(e)
		}
		f.Notes[i] = Note{Owner: Owner(k.Spend), Rho: repeated[[32]byte](byte(112 + 2*i)), Amount: []uint64{900000, 599999}[i]}
		f.Commitments[i] = f.Notes[i].Commitment(f.Context)
		p, e := Seal(k.Receive.EncapsulationKey().Bytes(), f.Context, uint8(i), f.Notes[i])
		if e != nil {
			t.Fatal(e)
		}
		f.Digests[i], e = DeliveryDigest(f.Context, f.Commitments[i], uint8(i), p)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, []string{"packet-0.bin", "packet-1.bin"}[i]), p, 0600); e != nil {
			t.Fatal(e)
		}
	}
	b, e := json.MarshalIndent(f, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "fixture.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
}
func TestRecoverAfterRustProofVerification(t *testing.T) {
	dir := os.Getenv("ZK9_NOTE_RECOVER")
	if dir == "" {
		t.Skip("cross-language driver must first verify the bound proof")
	}
	// This is a test harness, not an API for trusting unverified transaction files.
	b, e := os.ReadFile(filepath.Join(dir, "fixture.json"))
	if e != nil {
		t.Fatal(e)
	}
	var f Fixture
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	b, e = os.ReadFile(filepath.Join(dir, "envelope.bin"))
	if e != nil {
		t.Fatal(e)
	}
	if len(b) <= 440+2*PacketBytes || string(b[:8]) != "ZK9PQD1\x00" {
		t.Fatal("framing")
	}
	var total uint64
	for i := 0; i < 2; i++ {
		var cm [64]byte
		copy(cm[:], b[308+i*64:372+i*64])
		if cm != f.Commitments[i] {
			t.Fatal("commitment changed")
		}
		k, e := Derive(f.Seeds[i], f.Context)
		if e != nil {
			t.Fatal(e)
		}
		note, e := Open(k, f.Context, cm, uint8(i), b[440+i*PacketBytes:440+(i+1)*PacketBytes])
		if e != nil || note != f.Notes[i] {
			t.Fatal("seed restoration failed", e)
		}
		total += note.Amount
		foreign, _ := Derive(f.Seeds[1-i], f.Context)
		if _, e = Open(foreign, f.Context, cm, uint8(i), b[440+i*PacketBytes:440+(i+1)*PacketBytes]); e == nil {
			t.Fatal("foreign note discovered")
		}
	}
	if total != 1499999 {
		t.Fatal(total)
	}
	t.Logf("restored two wallets from seeds: total=%d", total)
}
