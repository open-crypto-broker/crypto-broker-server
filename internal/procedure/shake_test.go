package procedure

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	protobuf "github.com/open-crypto-broker/crypto-broker-server/internal/gen/cryptobroker/v1"
	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Known answers use Python hashlib independently of the Go hashing implementation:
// hashlib.shake_128(b"Welcome CryptoBroker").hexdigest(32), and likewise for SHAKE256 and other sizes.
func TestHashDataSHAKE(t *testing.T) {
	if err := profile.LoadProfiles("SHAKE.yaml"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { loadDefaultProfiles(t) })
	library := newTestLibraryNative()
	p := NewHashData(library)
	tests := []struct {
		name, profile, wantAlgorithm, wantHex string
		outputBytes                           *uint32
		format                                protobuf.HashOutputFormat
		wantErr                               string
		wantSize                              int
	}{
		{name: "SHAKE128 default", profile: "SHAKE128", outputBytes: nil, format: protobuf.HashOutputFormat_HASH_OUTPUT_FORMAT_HEX, wantAlgorithm: "shake-128/256", wantHex: "ab08064041f58213df6e655f53f946db0d1a841409b397893aed90fc99834a26", wantSize: 32},
		{name: "SHAKE128 explicit minimum", profile: "SHAKE128", outputBytes: proto.Uint32(32), format: protobuf.HashOutputFormat_HASH_OUTPUT_FORMAT_RAW, wantAlgorithm: "shake-128/256", wantHex: "ab08064041f58213df6e655f53f946db0d1a841409b397893aed90fc99834a26", wantSize: 32},
		{name: "SHAKE128 explicit size", profile: "SHAKE128", outputBytes: proto.Uint32(96), format: protobuf.HashOutputFormat_HASH_OUTPUT_FORMAT_HEX, wantAlgorithm: "shake-128/768", wantHex: "ab08064041f58213df6e655f53f946db0d1a841409b397893aed90fc99834a2610dfc4b4346f269e2b3996cf9d45d9dda2b97f0df0bec67a54707d914f6e1975df831e1c2e8aaf86a5e11c8810666c2e7e7cff1ec3d6bf486c7102b3622eeaf5", wantSize: 96},
		{name: "SHAKE128 upper bound", profile: "SHAKE128", outputBytes: proto.Uint32(128), format: protobuf.HashOutputFormat_HASH_OUTPUT_FORMAT_RAW, wantAlgorithm: "shake-128/1024", wantHex: "ab08064041f58213df6e655f53f946db0d1a841409b397893aed90fc99834a2610dfc4b4346f269e2b3996cf9d45d9dda2b97f0df0bec67a54707d914f6e1975df831e1c2e8aaf86a5e11c8810666c2e7e7cff1ec3d6bf486c7102b3622eeaf537e31e4f00266814a401697122c9d0931221a4e327b1edc79d234defe21550ba", wantSize: 128},
		{name: "SHAKE128 zero", profile: "SHAKE128", outputBytes: proto.Uint32(0), wantErr: "allowed range [32, 128]"},
		{name: "SHAKE128 below minimum", profile: "SHAKE128", outputBytes: proto.Uint32(31), wantErr: "allowed range [32, 128]"},
		{name: "SHAKE128 above maximum", profile: "SHAKE128", outputBytes: proto.Uint32(129), wantErr: "allowed range [32, 128]"},
		{name: "SHAKE128 uint32 maximum", profile: "SHAKE128", outputBytes: proto.Uint32(4294967295), wantErr: "allowed range [32, 128]"},
		{name: "SHAKE256 default", profile: "SHAKE256", outputBytes: nil, format: protobuf.HashOutputFormat_HASH_OUTPUT_FORMAT_HEX, wantAlgorithm: "shake-256/512", wantHex: "41633815cfbbe0867293163f049423184e3bbc38910510925533b83b7fa2ac56c48f32bd3455e57f513db77262b323e08962c878f33c04b2881587446103cd07", wantSize: 64},
		{name: "SHAKE256 explicit minimum", profile: "SHAKE256", outputBytes: proto.Uint32(64), format: protobuf.HashOutputFormat_HASH_OUTPUT_FORMAT_RAW, wantAlgorithm: "shake-256/512", wantHex: "41633815cfbbe0867293163f049423184e3bbc38910510925533b83b7fa2ac56c48f32bd3455e57f513db77262b323e08962c878f33c04b2881587446103cd07", wantSize: 64},
		{name: "SHAKE256 explicit size", profile: "SHAKE256", outputBytes: proto.Uint32(96), format: protobuf.HashOutputFormat_HASH_OUTPUT_FORMAT_HEX, wantAlgorithm: "shake-256/768", wantHex: "41633815cfbbe0867293163f049423184e3bbc38910510925533b83b7fa2ac56c48f32bd3455e57f513db77262b323e08962c878f33c04b2881587446103cd07684d5d10fba0af5b0165af5e1220c93f2562863e8dac21994c5fab2efbf23841", wantSize: 96},
		{name: "SHAKE256 upper bound", profile: "SHAKE256", outputBytes: proto.Uint32(128), format: protobuf.HashOutputFormat_HASH_OUTPUT_FORMAT_RAW, wantAlgorithm: "shake-256/1024", wantHex: "41633815cfbbe0867293163f049423184e3bbc38910510925533b83b7fa2ac56c48f32bd3455e57f513db77262b323e08962c878f33c04b2881587446103cd07684d5d10fba0af5b0165af5e1220c93f2562863e8dac21994c5fab2efbf23841b334101b7d65f9925119a525734e2449aa3089285095d7f2df79d13f938c6cf7", wantSize: 128},
		{name: "SHAKE256 zero", profile: "SHAKE256", outputBytes: proto.Uint32(0), wantErr: "allowed range [64, 128]"},
		{name: "SHAKE256 below minimum", profile: "SHAKE256", outputBytes: proto.Uint32(63), wantErr: "allowed range [64, 128]"},
		{name: "SHAKE256 above maximum", profile: "SHAKE256", outputBytes: proto.Uint32(129), wantErr: "allowed range [64, 128]"},
		{name: "SHAKE256 uint32 maximum", profile: "SHAKE256", outputBytes: proto.Uint32(4294967295), wantErr: "allowed range [64, 128]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := &protobuf.Metadata{Id: "shake-test"}
			executor := p
			if tt.wantErr != "" {
				executor = NewHashData(nil)
			}
			resp, err := executor.Execute(&protobuf.HashDataRequest{Profile: tt.profile, Input: []byte("Welcome CryptoBroker"), OutputBytes: tt.outputBytes, OutputFormat: tt.format, Metadata: metadata})
			if tt.wantErr != "" {
				if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Execute() = %v, want InvalidArgument containing %q", err, tt.wantErr)
				}
				if resp != nil {
					t.Fatal("invalid request returned a response")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			gotHex := resp.GetHashValueHex()
			if tt.format == protobuf.HashOutputFormat_HASH_OUTPUT_FORMAT_RAW {
				if len(resp.GetHashValueRaw()) != tt.wantSize {
					t.Fatalf("raw length = %d, want %d", len(resp.GetHashValueRaw()), tt.wantSize)
				}
				gotHex = hex.EncodeToString(resp.GetHashValueRaw())
			}
			if gotHex != tt.wantHex {
				t.Fatalf("hash = %s, want %s", gotHex, tt.wantHex)
			}
			if d := resp.GetDescriptor_(); d.GetAlgorithm() != tt.wantAlgorithm || d.GetProfile() != tt.profile || d.GetOperation() != "HashData" {
				t.Fatalf("unexpected descriptor: %v", d)
			}
			if !proto.Equal(resp.GetMetadata(), metadata) {
				t.Fatalf("metadata changed: %v", resp.GetMetadata())
			}
		})
	}
}

func TestHashDataFixedOutputRejectsSize(t *testing.T) {
	loadDefaultProfiles(t)
	// A nil engine proves rejection occurs before hashing.
	p := NewHashData(nil)
	for _, size := range []uint32{0, 64} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			_, err := p.Execute(&protobuf.HashDataRequest{Profile: "Default", Input: []byte("data"), OutputBytes: proto.Uint32(size)})
			if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "only allowed for SHAKE") {
				t.Fatalf("Execute() = %v, want InvalidArgument", err)
			}
		})
	}
}
