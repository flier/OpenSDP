package api

import (
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server provides gRPC and HTTP API
type Server struct {
	mux *runtime.ServeMux
}

func (s *Server) Serve() {
	http.Handle("/metrics", promhttp.Handler())
}
