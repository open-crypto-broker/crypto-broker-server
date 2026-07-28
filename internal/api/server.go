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
	procedureHashData        *procedure.HashData
	procedureSignCertificate *procedure.SignCertificate
	meter                    metric.Meter
	metricsEnabled           bool
}

func NewCryptoBrokerServer(
	c10yNative *c10y.LibraryNative,
	procedureHashData *procedure.HashData,
	procedureSignCertificate *procedure.SignCertificate,
	metricsEnabled bool,
) *CryptoBrokerServer {
	server := &CryptoBrokerServer{
		procedureHashData:        procedureHashData,
		procedureSignCertificate: procedureSignCertificate,
		metricsEnabled:           metricsEnabled,
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

// HashData contains data hashing logic
func (server *CryptoBrokerServer) HashData(ctx context.Context, req *protobuf.HashDataRequest) (*protobuf.HashDataResponse, error) {
	var start time.Time
	if server.metricsEnabled {
		start = time.Now()
	}

	if err := validateHashDataRequest(req); err != nil {
		return nil, fmt.Errorf("something went wrong while hashing data: %w", err)
	}

	tracer := otel.GetGlobalTracer()
	ctx, span := tracer.Start(ctx, "CryptoBrokerServer.HashDataProcedure",
		trace.WithAttributes(
			otel.AttributeRpcMethod.String(otel.RPCMethodHashData),
			otel.AttributeCryptoProfile.String(req.GetProfile()),
			otel.AttributeCryptoInputSize.Int(len(req.GetInput())),
			otel.AttributeCorrelationId.String(interceptors.CorrelationIDFromProtoRequest(req)),
		), trace.WithSpanKind(trace.SpanKindServer))
	defer span.End()

	response, err := server.procedureHashData.Execute(req)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())

		if server.metricsEnabled {
			duration := time.Since(start).Seconds()
			// Record error metrics
			otel.OperationsErrorsTotal.Add(ctx, 1, metric.WithAttributes(
				attribute.String("rpc_method", otel.RPCMethodHashData),
				attribute.String("error_type", "hash_error"),
			))

			otel.RequestDuration.Record(ctx, duration, metric.WithAttributes(
				attribute.String("rpc_method", otel.RPCMethodHashData),
				attribute.String("profile", req.GetProfile()),
				attribute.String("status", otel.StatusError),
			))
		}

		return nil, fmt.Errorf("something went wrong while hashing data: %w", err)
	}

	span.SetAttributes(
		otel.AttributeCryptoHashAlgorithm.String(response.GetHashAlgorithm()),
		otel.AttributeCryptoHashOutputSize.Int(len(response.GetHashValueHex())/2+len(response.GetHashValueRaw())),
	)
	span.SetStatus(codes.Ok, "HashData operation completed successfully")

	if server.metricsEnabled {
		duration := time.Since(start).Seconds()
		otel.RequestsTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodHashData),
			attribute.String("profile", req.GetProfile()),
			attribute.String("status", otel.StatusSuccess),
		))

		otel.RequestDuration.Record(ctx, duration, metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodHashData),
			attribute.String("profile", req.GetProfile()),
			attribute.String("status", otel.StatusSuccess),
		))

		otel.HashDataOperationsTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("algorithm", response.GetHashAlgorithm()),
		))

		otel.OperationBytesProcessed.Add(ctx, int64(len(req.GetInput())), metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodHashData),
		))
	}

	return response, nil
}

// SignCertificate contains certificate signing logic
func (server *CryptoBrokerServer) SignCertificate(ctx context.Context, req *protobuf.SignCertificateRequest) (*protobuf.SignCertificateResponse, error) {
	var start time.Time
	if server.metricsEnabled {
		start = time.Now()
	}

	if err := validateSignCertificateRequest(req); err != nil {
		return nil, fmt.Errorf("something went wrong while signing certificate: %w", err)
	}

	tracer := otel.GetGlobalTracer()
	ctx, span := tracer.Start(ctx, "CryptoBrokerServer.SignCertificateProcedure",
		trace.WithAttributes(
			otel.AttributeRpcMethod.String(otel.RPCMethodSignCertificate),
			otel.AttributeCryptoProfile.String(req.GetProfile()),
			otel.AttributeCryptoCsrSize.Int(len(req.GetCsr())),
			otel.AttributeCryptoCaCertSize.Int(len(req.GetCaCert())),
			otel.AttributeCryptoCaKeySize.Int(len(req.GetCaPrivateKey())),
			otel.AttributeCorrelationId.String(interceptors.CorrelationIDFromProtoRequest(req)),
		), trace.WithSpanKind(trace.SpanKindServer))
	defer span.End()

	response, err := server.procedureSignCertificate.Execute(req)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())

		if server.metricsEnabled {
			duration := time.Since(start).Seconds()
			// Record error metrics
			otel.OperationsErrorsTotal.Add(ctx, 1, metric.WithAttributes(
				attribute.String("rpc_method", otel.RPCMethodSignCertificate),
				attribute.String("error_type", "sign_error"),
			))

			otel.RequestDuration.Record(ctx, duration, metric.WithAttributes(
				attribute.String("rpc_method", otel.RPCMethodSignCertificate),
				attribute.String("profile", req.GetProfile()),
				attribute.String("status", otel.StatusError),
			))
		}

		return nil, fmt.Errorf("something went wrong while signing certificate: %w", err)
	}

	span.SetAttributes(otel.AttributeCryptoSignedCertSize.Int(len(response.GetDer()) + len(response.GetPem())))
	span.SetStatus(codes.Ok, "Certificate signing completed successfully")

	if server.metricsEnabled {
		duration := time.Since(start).Seconds()
		// Record success metrics
		otel.RequestsTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodSignCertificate),
			attribute.String("profile", req.GetProfile()),
			attribute.String("status", otel.StatusSuccess),
		))

		otel.RequestDuration.Record(ctx, duration, metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodSignCertificate),
			attribute.String("profile", req.GetProfile()),
			attribute.String("status", otel.StatusSuccess),
		))

		otel.SignCertificateOperationsTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("profile", req.GetProfile()),
		))

		otel.OperationBytesProcessed.Add(ctx, int64(len(req.GetCsr())+len(req.GetCaCert())+len(req.GetCaPrivateKey())), metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodSignCertificate),
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
