package grpc

import (
	//"crypto/tls"
	"errors"
	"net"

	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	bcreds "github.com/letsencrypt/boulder/grpc/creds"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	tls "github.com/tjfoc/gmtls"
)

// CodedError is a alias required to appease go vet
var CodedError = grpc.Errorf

var errNilTLS = errors.New("boulder/grpc: received nil tls.Config")

// NewServer creates a gRPC server that uses the provided *tls.Config, and
// verifies that clients present a certificate that (a) is signed by one of
// the configured ClientCAs, and (b) contains at least one
// subjectAlternativeName matching the accepted list from GRPCServerConfig.
func NewServer(c *cmd.GRPCServerConfig, tlsConfig *tls.Config, metrics serverMetrics, clk clock.Clock) (*grpc.Server, net.Listener, error) {
	if tlsConfig == nil {
		return nil, nil, errNilTLS
	}
	acceptedSANs := make(map[string]struct{})
	for _, name := range c.ClientNames {
		acceptedSANs[name] = struct{}{}
	}

	// Set the only acceptable TLS version to 1.2 and the only acceptable cipher suite
	// to ECDHE-RSA-CHACHA20-POLY1305.
	//tlsConfig.MinVersion, tlsConfig.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	tlsConfig.MinVersion, tlsConfig.MaxVersion = tls.VersionGMTLS, tls.VersionGMTLS

	tlsConfig.CipherSuites = []uint16{tls.TLS_ECC_SM2_WITH_SM4_256_SM3}    //update

	creds, err := bcreds.NewServerCredentials(tlsConfig, acceptedSANs)
	if err != nil {
		return nil, nil, err
	}

	l, err := net.Listen("tcp", c.Address)
	if err != nil {
		return nil, nil, err
	}

	si := newServerInterceptor(metrics, clk)
	return grpc.NewServer(
		grpc.Creds(creds),
		grpc.UnaryInterceptor(si.intercept),
	), l, nil
}

// serverMetrics is a struct type used to return a few registered metrics from
// `NewServerMetrics`
type serverMetrics struct {
	grpcMetrics *grpc_prometheus.ServerMetrics
	rpcLag      prometheus.Histogram
}

// NewServerMetrics registers metrics with a registry. It must be called a
// maximum of once per registry, or there will be conflicting names.
// It constructs and registers a *grpc_prometheus.ServerMetrics with timing
// histogram enabled as well as a prometheus Histogram for RPC latency.
func NewServerMetrics(stats registry) serverMetrics {
	// Create the grpc prometheus server metrics instance and register it
	grpcMetrics := grpc_prometheus.NewServerMetrics()
	grpcMetrics.EnableHandlingTimeHistogram()
	stats.MustRegister(grpcMetrics)

	// rpcLag is a prometheus histogram tracking the difference between the time
	// the client sent an RPC and the time the server received it. Create and
	// register it.
	rpcLag := prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name: "grpc_lag",
			Help: "Delta between client RPC send time and server RPC receipt time",
		})
	stats.MustRegister(rpcLag)

	return serverMetrics{
		grpcMetrics: grpcMetrics,
		rpcLag:      rpcLag,
	}
}
