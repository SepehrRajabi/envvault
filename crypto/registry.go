package crypto

import (
	"fmt"
	"sync"
)

var (
	registry        = make(map[string]Provider)
	defaultProvider Provider
	mu              sync.RWMutex
)

// Adds a custom provider
func Register(p Provider) error {
	if p == nil {
		return ErrInvalidProvider
	}

	id := p.AlgorithmID()
	if !validID(id) {
		return fmt.Errorf("%w: %q", ErrInvalidProvider, id)
	}

	mu.Lock()
	defer mu.Unlock()

	if _, exists := registry[id]; exists {
		return fmt.Errorf("provider %q already registered", id)
	}

	registry[id] = p
	if defaultProvider == nil {
		defaultProvider = p
	}
	return nil
}

// Sets the provider used for encryption when none is specified.
func SetDefault(id string) error {
	mu.Lock()
	defer mu.Unlock()

	p, ok := registry[id]
	if !ok {
		return ErrProviderNotFound
	}
	defaultProvider = p
	return nil
}

func Default() Provider {
	mu.RLock()
	defer mu.RUnlock()
	return defaultProvider
}

func GetProvider(id string) (Provider, error) {
	mu.RLock()
	defer mu.RUnlock()

	if p, ok := registry[id]; ok {
		return p, nil
	}
	return nil, ErrProviderNotFound
}

func ListProviders() []ProviderInfo {
	mu.Lock()
	defer mu.Unlock()

	var providers []ProviderInfo
	for _, p := range registry {
		providers = append(providers, p.Description())
	}
	return providers
}

func validID(id string) bool {
	if len(id) == 0 || len(id) > 32 {
		return false
	}
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
			return false
		}
	}
	return true
}
