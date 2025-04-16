package main

import (
	"crypto/rand"
	"time"

	dr "github.com/TypicalAM/signal-toy/double-ratchet"
	"github.com/charmbracelet/log"
)

func main() {
	log.SetLevel(log.DebugLevel)

	// Simulate shared root key (e.g. from X3DH)
	rk := make([]byte, 32)
	rand.Read(rk)

	alice, err := dr.NewRatchet(rk)
	if err != nil {
		log.Fatal("Failed to create alice", "err", err)
	}

	bob, err := dr.NewRatchet(rk)
	if err != nil {
		log.Fatal("Failed to create bob", "err", err)
	}

	alice.InitPeer(bob.DHsPub[:])
	bob.InitPeer(alice.DHsPub[:])

	aliceToBob := make(Queue, 10)
	bobToAlice := make(Queue, 10)
	aliceUser := &User{"Alice", alice, bobToAlice, aliceToBob}
	bobUser := &User{"Bob", bob, aliceToBob, bobToAlice}
	aliceUser.Start()
	bobUser.Start()

	// Chat
	log.Info("Starting secure conversation")
	aliceUser.Send("Hello Bob!")
	time.Sleep(100 * time.Millisecond)

	bobUser.Send("Hey Alice!")
	time.Sleep(100 * time.Millisecond)

	aliceUser.Send("How are you?")
	time.Sleep(100 * time.Millisecond)

	bobUser.Send("Good, and you?")
	time.Sleep(100 * time.Millisecond)
	bobUser.Send("Hello? Are you there?")
	time.Sleep(100 * time.Millisecond)
	bobUser.Send("Did you skip any messages?")
	time.Sleep(100 * time.Millisecond)

	aliceUser.Send("I don't think so but if I did I would have handled them gracefully!")
	time.Sleep(50 * time.Millisecond)

	bobUser.Send("Bread")
	time.Sleep(50 * time.Millisecond)
	log.Info("Secure conversation ended!")
}
