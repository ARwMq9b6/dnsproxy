package kcp

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"io"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

const cryptKey = "testkey"
const cryptSalt = "kcptest"

func TestAES(t *testing.T) {
	pass := pbkdf2.Key(key, []byte(portSink), 4096, 32, sha1.New)
	bc, err := NewAESBlockCrypt(pass)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)
	bc.Encrypt(enc, data)
	bc.Decrypt(dec, enc)
	if !bytes.Equal(data, dec) {
		t.Fail()
	}
}

func BenchmarkAES128(b *testing.B) {
	pass := make([]byte, 16)
	io.ReadFull(rand.Reader, pass)
	bc, err := NewAESBlockCrypt(pass)
	if err != nil {
		b.Fatal(err)
	}

	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)

	for i := 0; i < b.N; i++ {
		bc.Encrypt(enc, data)
		bc.Decrypt(dec, enc)
	}
	b.SetBytes(int64(len(enc) * 2))
}

func BenchmarkAES192(b *testing.B) {
	pass := make([]byte, 24)
	io.ReadFull(rand.Reader, pass)
	bc, err := NewAESBlockCrypt(pass)
	if err != nil {
		b.Fatal(err)
	}

	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)

	for i := 0; i < b.N; i++ {
		bc.Encrypt(enc, data)
		bc.Decrypt(dec, enc)
	}
	b.SetBytes(int64(len(enc) * 2))
}

func BenchmarkAES256(b *testing.B) {
	pass := make([]byte, 32)
	io.ReadFull(rand.Reader, pass)
	bc, err := NewAESBlockCrypt(pass)
	if err != nil {
		b.Fatal(err)
	}

	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)

	for i := 0; i < b.N; i++ {
		bc.Encrypt(enc, data)
		bc.Decrypt(dec, enc)
	}
	b.SetBytes(int64(len(enc) * 2))
}

func TestTEA(t *testing.T) {
	pass := pbkdf2.Key(key, []byte(portSink), 4096, 16, sha1.New)
	bc, err := NewTEABlockCrypt(pass)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)
	bc.Encrypt(enc, data)
	bc.Decrypt(dec, enc)
	if !bytes.Equal(data, dec) {
		t.Fail()
	}

}

func BenchmarkTEA(b *testing.B) {
	pass := make([]byte, 16)
	io.ReadFull(rand.Reader, pass)
	bc, err := NewTEABlockCrypt(pass)
	if err != nil {
		b.Fatal(err)
	}

	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)

	for i := 0; i < b.N; i++ {
		bc.Encrypt(enc, data)
		bc.Decrypt(dec, enc)
	}
	b.SetBytes(int64(len(enc) * 2))
}

func TestXOR(t *testing.T) {
	pass := pbkdf2.Key(key, []byte(portSink), 4096, 32, sha1.New)
	bc, err := NewSimpleXORBlockCrypt(pass)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)
	bc.Encrypt(enc, data)
	bc.Decrypt(dec, enc)
	if !bytes.Equal(data, dec) {
		t.Fail()
	}
}

func BenchmarkXOR(b *testing.B) {
	pass := make([]byte, 32)
	io.ReadFull(rand.Reader, pass)
	bc, err := NewSimpleXORBlockCrypt(pass)
	if err != nil {
		b.Fatal(err)
	}

	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)

	for i := 0; i < b.N; i++ {
		bc.Encrypt(enc, data)
		bc.Decrypt(dec, enc)
	}
	b.SetBytes(int64(len(enc) * 2))
}

func TestBlowfish(t *testing.T) {
	pass := pbkdf2.Key(key, []byte(portSink), 4096, 32, sha1.New)
	bc, err := NewBlowfishBlockCrypt(pass)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)
	bc.Encrypt(enc, data)
	bc.Decrypt(dec, enc)
	if !bytes.Equal(data, dec) {
		t.Fail()
	}
}

func BenchmarkBlowfish(b *testing.B) {
	pass := make([]byte, 32)
	io.ReadFull(rand.Reader, pass)
	bc, err := NewBlowfishBlockCrypt(pass)
	if err != nil {
		b.Fatal(err)
	}

	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)

	for i := 0; i < b.N; i++ {
		bc.Encrypt(enc, data)
		bc.Decrypt(dec, enc)
	}
	b.SetBytes(int64(len(enc) * 2))
}

func TestNone(t *testing.T) {
	pass := pbkdf2.Key(key, []byte(portSink), 4096, 32, sha1.New)
	bc, err := NewNoneBlockCrypt(pass)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)
	bc.Encrypt(enc, data)
	bc.Decrypt(dec, enc)
	if !bytes.Equal(data, dec) {
		t.Fail()
	}
}

func BenchmarkNone(b *testing.B) {
	pass := make([]byte, 32)
	io.ReadFull(rand.Reader, pass)
	bc, err := NewNoneBlockCrypt(pass)
	if err != nil {
		b.Fatal(err)
	}

	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)

	for i := 0; i < b.N; i++ {
		bc.Encrypt(enc, data)
		bc.Decrypt(dec, enc)
	}
	b.SetBytes(int64(len(enc) * 2))
}

func TestCast5(t *testing.T) {
	pass := pbkdf2.Key(key, []byte(portSink), 4096, 16, sha1.New)
	bc, err := NewCast5BlockCrypt(pass)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)
	bc.Encrypt(enc, data)
	bc.Decrypt(dec, enc)
	if !bytes.Equal(data, dec) {
		t.Fail()
	}
}

func BenchmarkCast5(b *testing.B) {
	pass := make([]byte, 16)
	io.ReadFull(rand.Reader, pass)
	bc, err := NewCast5BlockCrypt(pass)
	if err != nil {
		b.Fatal(err)
	}

	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)

	for i := 0; i < b.N; i++ {
		bc.Encrypt(enc, data)
		bc.Decrypt(dec, enc)
	}
	b.SetBytes(int64(len(enc) * 2))
}

func Test3DES(t *testing.T) {
	pass := pbkdf2.Key(key, []byte(portSink), 4096, 24, sha1.New)
	bc, err := NewTripleDESBlockCrypt(pass)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)
	bc.Encrypt(enc, data)
	bc.Decrypt(dec, enc)
	if !bytes.Equal(data, dec) {
		t.Fail()
	}
}

func Benchmark3DES(b *testing.B) {
	pass := make([]byte, 24)
	io.ReadFull(rand.Reader, pass)
	bc, err := NewTripleDESBlockCrypt(pass)
	if err != nil {
		b.Fatal(err)
	}

	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)

	for i := 0; i < b.N; i++ {
		bc.Encrypt(enc, data)
		bc.Decrypt(dec, enc)
	}
	b.SetBytes(int64(len(enc) * 2))
}

func TestTwofish(t *testing.T) {
	pass := pbkdf2.Key(key, []byte(portSink), 4096, 32, sha1.New)
	bc, err := NewTwofishBlockCrypt(pass)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)
	bc.Encrypt(enc, data)
	bc.Decrypt(dec, enc)
	if !bytes.Equal(data, dec) {
		t.Fail()
	}
}

func BenchmarkTwofish(b *testing.B) {
	pass := make([]byte, 32)
	io.ReadFull(rand.Reader, pass)
	bc, err := NewTwofishBlockCrypt(pass)
	if err != nil {
		b.Fatal(err)
	}

	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)

	for i := 0; i < b.N; i++ {
		bc.Encrypt(enc, data)
		bc.Decrypt(dec, enc)
	}
	b.SetBytes(int64(len(enc) * 2))
}

func TestXTEA(t *testing.T) {
	pass := pbkdf2.Key(key, []byte(portSink), 4096, 16, sha1.New)
	bc, err := NewXTEABlockCrypt(pass)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)
	bc.Encrypt(enc, data)
	bc.Decrypt(dec, enc)
	if !bytes.Equal(data, dec) {
		t.Fail()
	}

}

func BenchmarkXTEA(b *testing.B) {
	pass := make([]byte, 16)
	io.ReadFull(rand.Reader, pass)
	bc, err := NewXTEABlockCrypt(pass)
	if err != nil {
		b.Fatal(err)
	}

	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)

	for i := 0; i < b.N; i++ {
		bc.Encrypt(enc, data)
		bc.Decrypt(dec, enc)
	}
	b.SetBytes(int64(len(enc) * 2))
}

func TestSalsa20(t *testing.T) {
	pass := pbkdf2.Key(key, []byte(portSink), 4096, 32, sha1.New)
	bc, err := NewSalsa20BlockCrypt(pass)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)
	bc.Encrypt(enc, data)
	bc.Decrypt(dec, enc)
	if !bytes.Equal(data, dec) {
		t.Fail()
	}
}

func BenchmarkSalsa20(b *testing.B) {
	pass := make([]byte, 32)
	io.ReadFull(rand.Reader, pass)
	bc, err := NewSalsa20BlockCrypt(pass)
	if err != nil {
		b.Fatal(err)
	}

	data := make([]byte, mtuLimit)
	io.ReadFull(rand.Reader, data)
	dec := make([]byte, mtuLimit)
	enc := make([]byte, mtuLimit)

	for i := 0; i < b.N; i++ {
		bc.Encrypt(enc, data)
		bc.Decrypt(dec, enc)
	}
	b.SetBytes(int64(len(enc) * 2))
}
