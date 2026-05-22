package metrics

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// healthResponse is returned by the /healthz endpoint.
type healthResponse struct {
	Status  string `json:"status"`
	Uptime  string `json:"uptime"`
	Service string `json:"service"`
}

// NewHTTPHandler returns an http.Handler with /healthz and /metrics endpoints.
func NewHTTPHandler(serviceName string, startTime time.Time) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(healthResponse{
			Status:  "ok",
			Uptime:  time.Since(startTime).Round(time.Second).String(),
			Service: serviceName,
		})
	})

	mux.Handle("GET /metrics", promhttp.Handler())

	return mux
}
