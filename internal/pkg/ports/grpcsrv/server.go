// Package grpcsrv provides a gRPC server implementation.
package grpcsrv

import (
	"context"
	"fmt"
	"net"
	"runtime/debug"

	"github.com/alukart32/yandex/practicum/passkee/internal/pkg/ports/grpcauth"
	"github.com/alukart32/yandex/practicum/passkee/internal/pkg/zerologx"
	"github.com/caarlos0/env/v7"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/selector"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	otelstdout "go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	otelpropagation "go.opentelemetry.io/otel/propagation"
	otelsdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server defines the gRPC Server wrapper.
type Server struct {
	Srv    *grpc.Server
	notify chan error
	addr   string
}

// NewServer creates a new grpc server.
func NewServer(cfg Config, authOpts grpcauth.AuthOpts) (*Server, error) {
	if len(cfg.ADDR) == 0 {
		opts := env.Options{RequiredIfNoDef: true}
		if err := env.Parse(&cfg, opts); err != nil {
			return nil, fmt.Errorf("failed to read config: %v", err)
		}
	}

	// Define interceptors.
	// Set up OTLP tracing (stdout for debug).
	exporter, err := otelstdout.New(otelstdout.WithPrettyPrint())
	if err != nil {
		panic(err)
	}
	tp := otelsdktrace.NewTracerProvider(
		otelsdktrace.WithSampler(otelsdktrace.AlwaysSample()),
		otelsdktrace.WithBatcher(exporter),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(otelpropagation.NewCompositeTextMapPropagator(
		otelpropagation.TraceContext{}, otelpropagation.Baggage{}))
	defer func() { _ = exporter.Shutdown(context.Background()) }()

	// Set up Logger.
	rpcLogger := zerologx.Get().With().Str("server", "grpc").Logger()
	logTraceID := func(ctx context.Context) logging.Fields {
		if span := trace.SpanContextFromContext(ctx); span.IsSampled() {
			return logging.Fields{"traceID", span.TraceID().String()}
		}
		return nil
	}
	logOpts := []logging.Option{
		logging.WithFieldsFromContext(logTraceID),
		logging.WithLogOnEvents(
			logging.StartCall,
			logging.FinishCall,
		),
		logging.WithDurationField(logWithDuration()),
	}

	// Set up Recovery.
	recoveryHandler := func(p any) (err error) {
		rpcLogger.Error().Bytes("panic", debug.Stack()).Msg("recorverd")
		return status.Errorf(codes.Internal, "%s", p)
	}

	// Set up ServerOptions.
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(
			otelgrpc.UnaryServerInterceptor(),
			logging.UnaryServerInterceptor(
				logger(rpcLogger),
				logOpts...,
			),
			selector.UnaryServerInterceptor(
				auth.UnaryServerInterceptor(authOpts.Fn),
				authOpts.Skip,
			),
			recovery.UnaryServerInterceptor(
				recovery.WithRecoveryHandler(recoveryHandler),
			),
		),
	}
	// Set up server.
	s := Server{
		Srv:    grpc.NewServer(opts...),
		notify: make(chan error, 1),
		addr:   cfg.ADDR,
	}

	return &s, nil
}

// Run runs grpc Server.
func (s *Server) Run() {
	go func() {
		listener, err := net.Listen("tcp", s.addr)
		if err != nil {
			panic(err)
		}

		s.notify <- s.Srv.Serve(listener)
		close(s.notify)
	}()
}

// Notify throws a server error.
func (s *Server) Notify() <-chan error {
	return s.notify
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown() {
	s.Srv.GracefulStop()
	s.Srv.Stop()
}

// Config represents the grpc server configuration.
type Config struct {
	//Port specifies the listening port of the server.
	ADDR string `env:"GRPC_SRV_ADDRESS" envDefault:"localhost:9090"`
}

// Empty checks on being empty.
func (c Config) Empty() bool {
	return len(c.ADDR) == 0
}
