package api

import (
	"context"
	"fmt"
	"runtime"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	"github.com/open-crypto-broker/crypto-broker-server/internal/otel"
	"github.com/open-crypto-broker/crypto-broker-server/internal/procedure"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// CryptoBrokerServer defines crypto broker's server
type CryptoBrokerServer struct {
	protobuf.CryptoGrpcServer
	procedureHashData        *procedure.HashData
	procedureSignCertificate *procedure.SignCertificate
	procedureEncryptData     *procedure.EncryptData
	procedureDecryptData     *procedure.DecryptData
	meter                    metric.Meter
	metricsEnabled           bool
}

func NewCryptoBrokerServer(
	c10yNative *c10y.LibraryNative,
	procedureHashData *procedure.HashData,
	procedureSignCertificate *procedure.SignCertificate,
	procedureEncryptData *procedure.EncryptData,
	procedureDecryptData *procedure.DecryptData,
	metricsEnabled bool,
) *CryptoBrokerServer {
	server := &CryptoBrokerServer{
		procedureHashData:        procedureHashData,
		procedureSignCertificate: procedureSignCertificate,
		procedureEncryptData:     procedureEncryptData,
		procedureDecryptData:     procedureDecryptData,
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
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		otel.AttributeCryptoProfile.String(req.GetProfile()),
		otel.AttributeCryptoInputSize.Int(len(req.GetInput())),
	)
	if err := validateHashDataRequest(req); err != nil {
		return nil, fmt.Errorf("something went wrong while hashing data: %w", err)
	}

	response, err := server.procedureHashData.Execute(req)

	if err != nil {
		return nil, fmt.Errorf("something went wrong while hashing data: %w", err)
	}

	span.SetAttributes(
		otel.AttributeCryptoHashAlgorithm.String(response.GetHashAlgorithm()),
		otel.AttributeCryptoHashOutputSize.Int(len(response.GetHashValueHex())/2+len(response.GetHashValueRaw())),
	)

	if server.metricsEnabled {
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
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		otel.AttributeCryptoProfile.String(req.GetProfile()),
		otel.AttributeCryptoCsrSize.Int(len(req.GetCsr())),
		otel.AttributeCryptoCaCertSize.Int(len(req.GetCaCert())),
		otel.AttributeCryptoCaKeySize.Int(len(req.GetCaPrivateKey())),
	)
	if err := validateSignCertificateRequest(req); err != nil {
		return nil, fmt.Errorf("something went wrong while signing certificate: %w", err)
	}

	response, err := server.procedureSignCertificate.Execute(req)

	if err != nil {
		return nil, fmt.Errorf("something went wrong while signing certificate: %w", err)
	}

	span.SetAttributes(otel.AttributeCryptoSignedCertSize.Int(len(response.GetDer()) + len(response.GetPem())))

	if server.metricsEnabled {
		otel.SignCertificateOperationsTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("profile", req.GetProfile()),
		))

		otel.OperationBytesProcessed.Add(ctx, int64(len(req.GetCsr())+len(req.GetCaCert())+len(req.GetCaPrivateKey())), metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodSignCertificate),
		))
	}

	return response, nil
}

func (server *CryptoBrokerServer) EncryptData(ctx context.Context, req *protobuf.EncryptDataRequest) (*protobuf.EncryptDataResponse, error) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		otel.AttributeCryptoProfile.String(req.GetProfile()),
		otel.AttributeCryptoInputSize.Int(len(req.GetPlaintext())),
	)
	if err := validateEncryptDataRequest(req); err != nil {
		return nil, fmt.Errorf("something went wrong while encrypting data: %w", err)
	}

	response, err := server.procedureEncryptData.Execute(req)
	if err != nil {
		return nil, fmt.Errorf("something went wrong while encrypting data: %w", err)
	}

	span.SetAttributes(otel.AttributeCryptoCiphertextSize.Int(len(response.GetCiphertext())))
	if server.metricsEnabled {
		otel.EncryptDataOperationsTotal.Add(ctx, 1)
		otel.OperationBytesProcessed.Add(ctx, int64(len(req.GetPlaintext())), metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodEncryptData),
		))
	}
	return response, nil
}

func (server *CryptoBrokerServer) DecryptData(ctx context.Context, req *protobuf.DecryptDataRequest) (*protobuf.DecryptDataResponse, error) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		otel.AttributeCryptoProfile.String(req.GetProfile()),
		otel.AttributeCryptoCiphertextSize.Int(len(req.GetCiphertext())),
	)
	if err := validateDecryptDataRequest(req); err != nil {
		return nil, fmt.Errorf("something went wrong while decrypting data: %w", err)
	}

	response, err := server.procedureDecryptData.Execute(req)
	if err != nil {
		return nil, fmt.Errorf("something went wrong while decrypting data: %w", err)
	}

	span.SetAttributes(otel.AttributeCryptoInputSize.Int(len(response.GetPlaintext())))
	if server.metricsEnabled {
		otel.DecryptDataOperationsTotal.Add(ctx, 1)
		otel.OperationBytesProcessed.Add(ctx, int64(len(req.GetCiphertext())), metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodDecryptData),
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
