package server

import (
	"encoding/json"
	"sync"
)

type Event struct {
	Topic  string      `json:"topic"`
	Action string      `json:"action"`
	Data   interface{} `json:"data"`
}

func (e Event) JSON() []byte {
	b, _ := json.Marshal(e)
	return b
}

type Hub struct {
	mu   sync.RWMutex
	subs map[chan Event]struct{}
}

func NewHub() *Hub {
	return &Hub{subs: make(map[chan Event]struct{})}
}

func (h *Hub) Subscribe() chan Event {
	ch := make(chan Event, 256)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub) Unsubscribe(ch chan Event) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
	close(ch)
}

func (h *Hub) Publish(topic, action string, data interface{}) {
	evt := Event{Topic: topic, Action: action, Data: data}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.subs {
		select {
		case ch <- evt:
		default:
		}
	}
}
