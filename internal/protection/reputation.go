package protection

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type reputationClient struct {
	endpoint string
	apiKey   string
	ttl      time.Duration
	http     *http.Client
	mu       sync.Mutex
	cache    map[string]reputationCache
}

type reputationCache struct {
	signal  *Signal
	expires time.Time
}

func newReputationClient(endpoint, apiKeyEnv string, timeout, ttl time.Duration, apiKey string) (*reputationClient, error) {
	if !strings.HasPrefix(strings.ToLower(endpoint), "https://") {
		return nil, errors.New("reputation endpoint must use HTTPS")
	}
	if timeout <= 0 || ttl <= 0 {
		return nil, errors.New("reputation timeout and cache TTL must be positive")
	}
	return &reputationClient{
		endpoint: endpoint,
		apiKey:   apiKey,
		ttl:      ttl,
		cache:    map[string]reputationCache{},
		http: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("reputation redirects are disabled")
			},
		},
	}, nil
}

func (c *reputationClient) lookup(ctx context.Context, sha256 string) (*Signal, error) {
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(sha256) {
		return nil, errors.New("invalid SHA-256 for reputation lookup")
	}
	c.mu.Lock()
	if cached, ok := c.cache[sha256]; ok && time.Now().Before(cached.expires) {
		c.mu.Unlock()
		return cached.signal, nil
	}
	c.mu.Unlock()

	// Privacy contract: the request contains the hash only. File names, paths,
	// host identity, process data, and file bytes never leave the endpoint.
	body, _ := json.Marshal(map[string]string{"sha256": sha256})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		request.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil {
		return nil, err
	}
	if len(content) > 64*1024 {
		return nil, errors.New("reputation response exceeds 64 KiB")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("reputation service returned HTTP %d", response.StatusCode)
	}
	var result struct {
		Verdict    string `json:"verdict"`
		Confidence int    `json:"confidence"`
		Threat     string `json:"threat,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("decode reputation response: %w", err)
	}
	var signal *Signal
	if strings.EqualFold(result.Verdict, "malicious") {
		if result.Confidence < 1 || result.Confidence > 100 {
			return nil, errors.New("reputation confidence must be between 1 and 100")
		}
		value := Signal{Source: "hash_reputation", ID: strings.TrimSpace(result.Threat), Confidence: result.Confidence}
		if value.ID == "" {
			value.ID = "known_malicious_hash"
		}
		value.Authoritative = result.Confidence >= 95
		signal = &value
	}
	c.mu.Lock()
	if len(c.cache) >= 10000 {
		c.cache = map[string]reputationCache{}
	}
	c.cache[sha256] = reputationCache{signal: signal, expires: time.Now().Add(c.ttl)}
	c.mu.Unlock()
	return signal, nil
}
