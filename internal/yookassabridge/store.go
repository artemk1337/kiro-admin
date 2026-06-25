package yookassabridge

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Store struct {
	path   string
	mu     sync.Mutex
	Orders map[string]Order `json:"orders"`
}

func NewStore(path string) (*Store, error) {
	store := &Store{path: path, Orders: map[string]Order{}}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) Create(order Order) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.Orders[order.ID]; ok {
		return errors.New("order already exists")
	}
	now := time.Now().UTC()
	order.CreatedAt = now
	order.UpdatedAt = now
	s.Orders[order.ID] = order
	return s.saveLocked()
}

func (s *Store) Get(id string) (Order, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	order, ok := s.Orders[id]
	return order, ok
}

func (s *Store) FindByPaymentID(paymentID string) (Order, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, order := range s.Orders {
		if order.YooPaymentID == paymentID {
			return order, true
		}
	}
	return Order{}, false
}

func (s *Store) PendingPaymentIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0)
	for _, order := range s.Orders {
		if order.Status == OrderPending && order.YooPaymentID != "" {
			ids = append(ids, order.YooPaymentID)
		}
	}
	return ids
}

func (s *Store) Update(id string, fn func(Order) Order) (Order, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	order, ok := s.Orders[id]
	if !ok {
		return Order{}, errors.New("order not found")
	}
	order = fn(order)
	order.UpdatedAt = time.Now().UTC()
	s.Orders[id] = order
	return order, s.saveLocked()
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, s)
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil && filepath.Dir(s.path) != "." {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}
