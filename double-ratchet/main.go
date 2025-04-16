package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type RatchetState struct {
	RootKey    []byte
	DHsPriv    [32]byte
	DHsPub     [32]byte
	DHr        [32]byte
	CKs        []byte
	CKr        []byte
	Ns, Nr, PN int
	Skipped    map[string][]byte // map[DHr || Nr] → message key
}

type Header struct {
	DHPub [32]byte // Your new DH public key
	PN    int      // Number of messages sent in the previous sending chain
	Ns    int      // Message number in this sending chain
}

func (s *RatchetState) InitPeer(pubKey []byte) {
	s.DHr = [32]byte(pubKey)
	s.RunInitialRatchet()
}

func (s *RatchetState) RunInitialRatchet() {
	sharedA, _ := curve25519.X25519(s.DHsPriv[:], s.DHr[:])
	s.RootKey, s.CKs = DeriveKeys(s.RootKey, sharedA)
}

func (s *RatchetState) HandleSkippedMessages(peerNs int) {
	maxSkip := 50 // Protect memory: only keep N skipped keys
	for s.Nr < peerNs && len(s.Skipped) < maxSkip {
		var mk []byte
		s.CKr, mk = RatchetCK(s.CKr)
		keyID := fmt.Sprintf("%x|%d", s.DHr, s.Nr)
		s.Skipped[keyID] = mk
		s.Nr++
	}
}

func (s *RatchetState) TryDecryptSkipped(header Header, ciphertext []byte) ([]byte, bool) {
	keyID := fmt.Sprintf("%x|%d", header.DHPub, header.Ns)
	mk, exists := s.Skipped[keyID]
	if !exists {
		return nil, false
	}
	delete(s.Skipped, keyID)
	plaintext := Decrypt(mk, ciphertext)
	return plaintext, true
}

func (s *RatchetState) ShouldRatchet() bool {
	// You ratchet if you've received a new DHr and haven't responded with a new DHs yet.
	return s.Ns == 0
}

func GenerateDHKeyPair() (priv [32]byte, pub [32]byte, err error) {
	if _, err = rand.Read(priv[:]); err != nil {
		return
	}

	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	curve25519.ScalarBaseMult(&pub, &priv)
	return
}

func DH(priv [32]byte, pub [32]byte) ([]byte, error) {
	return curve25519.X25519(priv[:], pub[:])
}

func DeriveKeys(rootKey, inputSecret []byte) (newRootKey, chainKey []byte) {
	hkdf := hkdf.New(sha256.New, inputSecret, rootKey, nil)
	newRootKey = make([]byte, 32)
	chainKey = make([]byte, 32)
	io.ReadFull(hkdf, newRootKey)
	io.ReadFull(hkdf, chainKey)
	return
}

func RatchetCK(ck []byte) (nextCK, messageKey []byte) {
	hmacFn := hmac.New(sha256.New, ck)
	hmacFn.Write([]byte{0x01})
	nextCK = hmacFn.Sum(nil)

	hmacFn.Reset()
	hmacFn.Write([]byte{0x02})
	messageKey = hmacFn.Sum(nil)
	return
}

func Encrypt(key, plaintext []byte) []byte {
	aead, _ := chacha20poly1305.New(key)
	nonce := make([]byte, chacha20poly1305.NonceSize)
	rand.Read(nonce)
	return append(nonce, aead.Seal(nil, nonce, plaintext, nil)...)
}

func Decrypt(key, ciphertext []byte) []byte {
	aead, _ := chacha20poly1305.New(key)
	nonce := ciphertext[:12]
	ct := ciphertext[12:]
	plaintext, _ := aead.Open(nil, nonce, ct, nil)
	return plaintext
}

func (s *RatchetState) SendMessage(plaintext []byte) (Header, []byte) {
	if s.ShouldRatchet() {
		s.PN = s.Ns
		s.DHsPriv, s.DHsPub, _ = GenerateDHKeyPair()
		sharedSecret, _ := curve25519.X25519(s.DHsPriv[:], s.DHr[:])
		s.RootKey, s.CKs = DeriveKeys(s.RootKey, sharedSecret)
		s.Ns = 0
	}

	var mk []byte
	s.CKs, mk = RatchetCK(s.CKs)
	ciphertext := Encrypt(mk, plaintext)
	header := Header{DHPub: s.DHsPub, PN: s.PN, Ns: s.Ns}
	s.Ns++
	return header, ciphertext
}

func (s *RatchetState) ReceiveMessage(header Header, ciphertext []byte) ([]byte, error) {
	// Try to decrypt using a skipped message key first
	if plaintext, ok := s.TryDecryptSkipped(header, ciphertext); ok {
		return plaintext, nil
	}

	// New DH key from sender triggers a DH ratchet
	if header.DHPub != s.DHr {
		s.HandleSkippedMessages(header.Ns)
		s.DHr = header.DHPub
		sharedSecret, _ := curve25519.X25519(s.DHsPriv[:], s.DHr[:])
		s.RootKey, s.CKr = DeriveKeys(s.RootKey, sharedSecret)
		s.Nr = 0
	}

	// Advance CKr to expected message number
	var mk []byte
	for s.Nr < header.Ns {
		s.CKr, mk = RatchetCK(s.CKr)
		keyID := fmt.Sprintf("%x|%d", s.DHr, s.Nr)
		s.Skipped[keyID] = mk
		s.Nr++
	}

	s.CKr, mk = RatchetCK(s.CKr)
	plaintext := Decrypt(mk, ciphertext)
	s.Nr++
	return plaintext, nil
}

// NewRatchet generates a new ratchet state for a user based on the provided root key,
// this key should be generated using an X3DH. Important, the caller is expected to initialize the
// peer using InitPeer
func NewRatchet(rootKey []byte) (*RatchetState, error) {
	priv, pub, err := GenerateDHKeyPair()
	if err != nil {
		return nil, err
	}

	return &RatchetState{
		RootKey: rootKey[:],
		DHsPriv: priv,
		DHsPub:  pub,
		DHr:     [32]byte{}, // To be filled by the caller
		CKs:     make([]byte, 32),
		CKr:     nil,
		Skipped: make(map[string][]byte),
	}, nil
}

func main() {
	// Simulate shared root key (e.g. from X3DH)
	rk := make([]byte, 32)
	rand.Read(rk)

	alice, err := NewRatchet(rk)
	if err != nil {
		log.Fatal("Failed to create alice", "err", err)
	}

	bob, err := NewRatchet(rk)
	if err != nil {
		log.Fatal("Failed to create bob", "err", err)
	}

	alice.InitPeer(bob.DHsPub[:])
	bob.InitPeer(alice.DHsPub[:])

	fmt.Println(">>> Alice sends 'Hello Bob'")
	header, ciphertext := alice.SendMessage([]byte("Hello Bob"))

	fmt.Println(">>> Bob receives")
	plaintext, _ := bob.ReceiveMessage(header, ciphertext)
	fmt.Printf("Bob decrypted: %s\n", string(plaintext))

	fmt.Println(">>> Bob replies 'Hi Alice'")
	replyHeader, replyCipher := bob.SendMessage([]byte("Hi Alice"))

	fmt.Println(">>> Alice receives")
	plaintext2, _ := alice.ReceiveMessage(replyHeader, replyCipher)
	fmt.Printf("Alice decrypted: %s\n", string(plaintext2))
}
