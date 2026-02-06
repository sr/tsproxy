package main

import (
	"bytes"
	"testing"

	"k8s.io/client-go/kubernetes/fake"
	"tailscale.com/ipn"
)

func TestCK8sState(t *testing.T) {
	store := &k8sStateStore{
		clientset: fake.NewSimpleClientset(),
		namespace: "test",
		secret:    "map",
		name:      "hostname",
	}

	testData := []byte("blahblah")

	sk := ipn.StateKey("test")

	if _, err := store.ReadState(sk); err != ipn.ErrStateNotExist {
		t.Errorf("wanted ipn.ErrStateNotExist, got: %v", err)
	}

	if err := store.WriteState(sk, testData); err != nil {
		t.Errorf("putting state: %v", err)
	}

	got, err := store.ReadState(sk)
	if err != nil {
		t.Errorf("unexptected error getting cert: %v", err)
	}

	if !bytes.Equal(testData, got) {
		t.Errorf("wanted to get %s, but got: %v", string(testData), string(got))
	}

	if err := store.WriteState(sk, testData); err != nil {
		t.Errorf("updating state: %v", err)
	}
}
