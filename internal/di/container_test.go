package di

import (
	"context"
	"testing"
)

func TestNewContainerWithTracing_Smoke_NoTracing(t *testing.T) {
	c := NewContainerWithTracing(context.Background(), "Profiles.yaml", false)
	if c == nil {
		t.Fatalf("expected non-nil container")
	}
	if c.Server == nil {
		t.Fatalf("expected non-nil server")
	}
	if c.TracerProvider != nil {
		t.Fatalf("expected nil tracer provider when tracingEnabled=false")
	}
}

func TestNewContainerWithTracing_Smoke_WithTracing(t *testing.T) {
	c := NewContainerWithTracing(context.Background(), "Profiles.yaml", true)
	if c == nil {
		t.Fatalf("expected non-nil container")
	}
	if c.Server == nil {
		t.Fatalf("expected non-nil server")
	}
	if c.TracerProvider == nil {
		t.Fatalf("expected non-nil tracer provider when tracingEnabled=true")
	}
}
