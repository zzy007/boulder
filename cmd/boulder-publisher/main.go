package main

import (
	"flag"
	"os"
	"runtime"

	ct "github.com/google/certificate-transparency-go"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/publisher"
	pubpb "github.com/letsencrypt/boulder/publisher/proto"
)

type config struct {
	Publisher struct {
		cmd.ServiceConfig
		Features map[string]bool
		// If this is non-zero, profile blocking events such that one even is
		// sampled every N nanoseconds.
		// https://golang.org/pkg/runtime/#SetBlockProfileRate
		BlockProfileRate int
		UserAgent        string
	}

	Syslog cmd.SyslogConfig

	Common struct {
		CT struct {
			IntermediateBundleFilename string
		}
	}
}

func main() {
	grpcAddr := flag.String("addr", "", "gRPC listen address override")
	debugAddr := flag.String("debug-addr", "", "Debug server address override")
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")
	err = features.Set(c.Publisher.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	runtime.SetBlockProfileRate(c.Publisher.BlockProfileRate)

	if *grpcAddr != "" {
		c.Publisher.GRPC.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.Publisher.DebugAddr = *debugAddr
	}
	if c.Publisher.UserAgent == "" {
		c.Publisher.UserAgent = "certificate-transparency-go/1.0"
	}

	scope, logger := cmd.StatsAndLogging(c.Syslog, c.Publisher.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	if c.Common.CT.IntermediateBundleFilename == "" {
		logger.AuditErr("No CT submission bundle provided")
		os.Exit(1)
	}
	pemBundle, err := core.LoadCertBundle(c.Common.CT.IntermediateBundleFilename)
	cmd.FailOnError(err, "Failed to load CT submission bundle")
	bundle := []ct.ASN1Cert{}
	for _, cert := range pemBundle {
		bundle = append(bundle, ct.ASN1Cert{Data: cert.Raw})
	}

	tlsConfig, err := c.Publisher.TLS.Load()
	cmd.FailOnError(err, "TLS config")

	clk := cmd.Clock()

	pubi := publisher.New(
		bundle,
		c.Publisher.UserAgent,
		logger,
		scope)

	serverMetrics := bgrpc.NewServerMetrics(scope)
	grpcSrv, l, err := bgrpc.NewServer(c.Publisher.GRPC, tlsConfig, serverMetrics, clk)
	cmd.FailOnError(err, "Unable to setup Publisher gRPC server")
	gw := bgrpc.NewPublisherServerWrapper(pubi)
	pubpb.RegisterPublisherServer(grpcSrv, gw)

	go cmd.CatchSignals(logger, grpcSrv.GracefulStop)

	err = cmd.FilterShutdownErrors(grpcSrv.Serve(l))
	cmd.FailOnError(err, "Publisher gRPC service failed")
}
