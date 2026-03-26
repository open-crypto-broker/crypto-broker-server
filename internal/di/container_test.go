package di

import (
	"context"
	"testing"
)

func TestNewContainer(t *testing.T) {
	c := NewContainer(context.Background(), "Profiles.yaml")
	if c == nil {
		t.Fatalf("expected non-nil container")
	}
	if c.Server == nil {
		t.Fatalf("expected non-nil server in container")
	}
}

func TestNewContainerWithTracing_Disabled(t *testing.T) {
	c := NewContainerWithTracing(context.Background(), "Profiles.yaml", false)
	if c == nil {
		t.Fatalf("expected non-nil container")
	}
	if c.Server == nil {
		t.Fatalf("expected non-nil server in container")
	}
	if c.TracerProvider != nil {
		t.Fatalf("expected TracerProvider to be nil when tracing is disabled")
	}
}
