package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestNewRateLimiter(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)

	if rl == nil {
		t.Fatal("RateLimiter is nil")
	}

	if rl.limit != 10 {
		t.Errorf("Expected limit 10, got %d", rl.limit)
	}

	if rl.window != time.Minute {
		t.Errorf("Expected window time.Minute, got %v", rl.window)
	}

	if rl.requests == nil {
		t.Error("Requests map is nil")
	}
}

func TestRateLimiterLimitWithinThreshold(t *testing.T) {
	rl := NewRateLimiter(5, time.Minute)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	limitedHandler := rl.Limit(handler)

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()

		limitedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected status 200, got %d", i+1, w.Code)
		}
	}
}

func TestRateLimiterLimitExceeded(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	limitedHandler := rl.Limit(handler)

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()

		limitedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected status 200, got %d", i+1, w.Code)
		}
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()

	limitedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", w.Code)
	}
}

func TestRateLimiterDifferentIPs(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	limitedHandler := rl.Limit(handler)

	ips := []string{"127.0.0.1:12345", "127.0.0.2:12345", "127.0.0.3:12345"}

	for _, ip := range ips {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = ip
		w := httptest.NewRecorder()

		limitedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("IP %s: Expected status 200, got %d", ip, w.Code)
		}
	}
}

func TestRateLimiterWindowExpiration(t *testing.T) {
	rl := NewRateLimiter(2, 100*time.Millisecond)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	limitedHandler := rl.Limit(handler)

	ip := "127.0.0.1:12345"

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = ip
	w := httptest.NewRecorder()
	limitedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("First request: Expected status 200, got %d", w.Code)
	}

	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = ip
	w = httptest.NewRecorder()
	limitedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Second request: Expected status 200, got %d", w.Code)
	}

	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = ip
	w = httptest.NewRecorder()
	limitedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Third request: Expected status 429, got %d", w.Code)
	}

	time.Sleep(150 * time.Millisecond)

	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = ip
	w = httptest.NewRecorder()
	limitedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Request after expiration: Expected status 200, got %d", w.Code)
	}
}

func TestRateLimiterConcurrentAccess(t *testing.T) {
	rl := NewRateLimiter(100, time.Minute)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	limitedHandler := rl.Limit(handler)

	var wg sync.WaitGroup
	numRequests := 200
	numClients := 10

	for c := 0; c < numClients; c++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()
			ip := "127.0.0." + string(rune(clientID%10)+'0') + ":12345"

			for i := 0; i < numRequests/numClients; i++ {
				req := httptest.NewRequest("GET", "/", nil)
				req.RemoteAddr = ip
				w := httptest.NewRecorder()
				limitedHandler.ServeHTTP(w, req)

				if w.Code == http.StatusInternalServerError {
					t.Errorf("Client %d: Got internal server error", clientID)
				}
			}
		}(c)
	}

	wg.Wait()
}

func TestRateLimiterRequestCleanup(t *testing.T) {
	rl := NewRateLimiter(5, 100*time.Millisecond)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	limitedHandler := rl.Limit(handler)

	ip := "127.0.0.1:12345"

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = ip
		w := httptest.NewRecorder()
		limitedHandler.ServeHTTP(w, req)
	}

	time.Sleep(150 * time.Millisecond)

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = ip
		w := httptest.NewRecorder()
		limitedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d after cleanup: Expected status 200, got %d", i+1, w.Code)
		}
	}
}

func TestRateLimiterZeroLimit(t *testing.T) {
	rl := NewRateLimiter(0, time.Minute)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	limitedHandler := rl.Limit(handler)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()

	limitedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429 for zero limit, got %d", w.Code)
	}
}

func TestRateLimiterVerySmallWindow(t *testing.T) {
	rl := NewRateLimiter(5, 10*time.Millisecond)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	limitedHandler := rl.Limit(handler)

	ip := "127.0.0.1:12345"

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = ip
		w := httptest.NewRecorder()
		limitedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected status 200, got %d", i+1, w.Code)
		}
	}

	time.Sleep(20 * time.Millisecond)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = ip
	w := httptest.NewRecorder()
	limitedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Request after small window: Expected status 200, got %d", w.Code)
	}
}
