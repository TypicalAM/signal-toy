package main

import (
	"github.com/charmbracelet/log"

	dr "github.com/TypicalAM/signal-toy/double-ratchet"
)

// Message represents what gets sent over the wire
type Message struct {
	Header     dr.Header
	Ciphertext []byte
}

// Queue simulates a message queue
type Queue chan Message

// User represents a party in the conversation
type User struct {
	Name   string
	State  *dr.RatchetState
	Inbox  Queue
	Outbox Queue
}

// Start begins listening and decrypting messages
func (u *User) Start() {
	go func() {
		for msg := range u.Inbox {
			plaintext, err := u.State.ReceiveMessage(msg.Header, msg.Ciphertext)
			if err != nil {
				log.Error("Error decrypting", "name", u.Name, "err", err)
				continue
			}

			log.Debug("Received", "name", u.Name, "text", string(plaintext))
		}
	}()
}

// Send a message to the other user
func (u *User) Send(text string) {
	header, ciphertext := u.State.SendMessage([]byte(text))
	u.Outbox <- Message{Header: header, Ciphertext: ciphertext}
	log.Debug("Sent", "name", u.Name, "text", text)
}
