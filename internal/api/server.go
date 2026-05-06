package api

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	"github.com/open-crypto-broker/crypto-broker-server/internal/interceptors"
	"github.com/open-crypto-broker/crypto-broker-server/internal/otel"
	"github.com/open-crypto-broker/crypto-broker-server/internal/procedure"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// CryptoBrokerServer defines crypto broker's server
type CryptoBrokerServer struct {
	protobuf.CryptoGrpcServer
	procedureHash  *procedure.Hash
	procedureSign  *procedure.Sign
	meter          metric.Meter
	metricsEnabled bool
}

func NewCryptoBrokerServer(c10yNative *c10y.LibraryNative, procedureHash *procedure.Hash, procedureSign *procedure.Sign, metricsEnabled bool) *CryptoBrokerServer {
	server := &CryptoBrokerServer{
		procedureHash:  procedureHash,
		procedureSign:  procedureSign,
		metricsEnabled: metricsEnabled,
	}

	if metricsEnabled {
		server.meter = otel.GetGlobalMeter()
		if err := otel.InitializeInstruments(server.meter); err != nil {
			panic(fmt.Sprintf("failed to initialize metric instruments: %v", err))
		}
		go server.collectSystemMetrics()
	}

	return server
}

// Hash contains data hashing logic
func (server *CryptoBrokerServer) Hash(ctx context.Context, req *protobuf.HashRequest) (*protobuf.HashResponse, error) {
	var start time.Time
	if server.metricsEnabled {
		start = time.Now()
	}

	tracer := otel.GetGlobalTracer()
	ctx, span := tracer.Start(ctx, "CryptoBrokerServer.Hash",
		trace.WithAttributes(
			otel.AttributeRpcMethod.String(otel.RPCMethodHash),
			otel.AttributeCryptoProfile.String(req.GetProfile()),
			otel.AttributeCryptoInputSize.Int(len(req.GetInput())),
			otel.AttributeCorrelationId.String(interceptors.CorrelationIDFromProtoRequest(req)),
		))
	defer span.End()

	response, err := server.procedureHash.Execute(req)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())

		if server.metricsEnabled {
			duration := time.Since(start).Seconds()
			// Record error metrics
			otel.OperationsErrorsTotal.Add(ctx, 1, metric.WithAttributes(
				attribute.String("rpc_method", otel.RPCMethodHash),
				attribute.String("error_type", "hash_error"),
			))

			otel.RequestDuration.Record(ctx, duration, metric.WithAttributes(
				attribute.String("rpc_method", otel.RPCMethodHash),
				attribute.String("profile", req.GetProfile()),
				attribute.String("status", otel.StatusError),
			))
		}

		return nil, fmt.Errorf("something went wrong while hashing data: %w", err)
	}

	span.SetAttributes(
		otel.AttributeCryptoHashAlgorithm.String(response.GetHashAlgorithm()),
		otel.AttributeCryptoHashOutputSize.Int(len(response.GetHashValue())),
	)
	span.SetStatus(codes.Ok, "Hash operation completed successfully")

	if server.metricsEnabled {
		duration := time.Since(start).Seconds()
		otel.RequestsTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodHash),
			attribute.String("profile", req.GetProfile()),
			attribute.String("status", otel.StatusSuccess),
		))

		otel.RequestDuration.Record(ctx, duration, metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodHash),
			attribute.String("profile", req.GetProfile()),
			attribute.String("status", otel.StatusSuccess),
		))

		otel.HashOperationsTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("algorithm", response.GetHashAlgorithm()),
		))

		otel.OperationBytesProcessed.Add(ctx, int64(len(req.GetInput())), metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodHash),
		))
	}

	return response, nil
}

// Sign contains certificate signing logic
func (server *CryptoBrokerServer) Sign(ctx context.Context, req *protobuf.SignRequest) (*protobuf.SignResponse, error) {
	var start time.Time
	if server.metricsEnabled {
		start = time.Now()
	}

	tracer := otel.GetGlobalTracer()
	ctx, span := tracer.Start(ctx, "CryptoBrokerServer.Sign",
		trace.WithAttributes(
			otel.AttributeRpcMethod.String(otel.RPCMethodSign),
			otel.AttributeCryptoProfile.String(req.GetProfile()),
			otel.AttributeCryptoCsrSize.Int(len(req.GetCsr())),
			otel.AttributeCryptoCaCertSize.Int(len(req.GetCaCert())),
			otel.AttributeCryptoCaKeySize.Int(len(req.GetCaPrivateKey())),
			otel.AttributeCorrelationId.String(interceptors.CorrelationIDFromProtoRequest(req)),
		))
	defer span.End()

	response, err := server.procedureSign.Execute(req)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())

		if server.metricsEnabled {
			duration := time.Since(start).Seconds()
			// Record error metrics
			otel.OperationsErrorsTotal.Add(ctx, 1, metric.WithAttributes(
				attribute.String("rpc_method", otel.RPCMethodSign),
				attribute.String("error_type", "sign_error"),
			))

			otel.RequestDuration.Record(ctx, duration, metric.WithAttributes(
				attribute.String("rpc_method", otel.RPCMethodSign),
				attribute.String("profile", req.GetProfile()),
				attribute.String("status", otel.StatusError),
			))
		}

		return nil, fmt.Errorf("something went wrong while signing certificate: %w", err)
	}

	span.SetAttributes(otel.AttributeCryptoSignedCertSize.Int(len(response.GetSignedCertificate())))
	span.SetStatus(codes.Ok, "Certificate signing completed successfully")

	if server.metricsEnabled {
		duration := time.Since(start).Seconds()
		// Record success metrics
		otel.RequestsTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodSign),
			attribute.String("profile", req.GetProfile()),
			attribute.String("status", otel.StatusSuccess),
		))

		otel.RequestDuration.Record(ctx, duration, metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodSign),
			attribute.String("profile", req.GetProfile()),
			attribute.String("status", otel.StatusSuccess),
		))

		otel.SignOperationsTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("profile", req.GetProfile()),
		))

		otel.OperationBytesProcessed.Add(ctx, int64(len(req.GetCsr())+len(req.GetCaCert())+len(req.GetCaPrivateKey())), metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodSign),
		))
	}

	return response, nil
}

// collectSystemMetrics sets up asynchronous metric callbacks for system metrics
func (server *CryptoBrokerServer) collectSystemMetrics() {
	if !server.metricsEnabled {
		return
	}

	// Set up asynchronous gauge for memory usage
	_, err := server.meter.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		o.ObserveInt64(otel.MemoryUsage, int64(m.Alloc))
		return nil
	}, otel.MemoryUsage)
	if err != nil {
		panic(fmt.Sprintf("failed to register memory usage callback: %v", err))
	}
}
