package main

import (
	"context"
	"encoding/base32"
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"tailscale.com/ipn"
)

var _ ipn.StateStore = (*k8sStateStore)(nil)

// k8sStateStore is an implementation of the tailscale state store that uses
// a secret to persist the data. It is not safe to share a secret across proxy
// instances.
type k8sStateStore struct {
	clientset kubernetes.Interface
	// namespace to keep the secret in
	namespace string
	// secret will be used as the name for the secret. this can serve
	// multiple store instances, keys inside will be prefixed with name
	secret string
	// name of the service this state store is for.
	name string

	currentSecret *corev1.Secret
	storeMu       sync.RWMutex
}

func (k *k8sStateStore) ReadState(id ipn.StateKey) ([]byte, error) {
	k.storeMu.RLock()
	defer k.storeMu.RUnlock()

	ctx := context.Background()

	if k.currentSecret == nil {
		sec, err := k.clientset.CoreV1().Secrets(k.namespace).Get(ctx, k.secret, metav1.GetOptions{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				// unexpected
				return nil, fmt.Errorf("fetching %s/%s from destination: %v", k.namespace, k.secret, err)
			}
			return nil, ipn.ErrStateNotExist
		}
		k.currentSecret = sec
	}

	v, ok := k.currentSecret.Data[k.cmKeyForStateKey(id)]
	if !ok {
		return nil, ipn.ErrStateNotExist
	}

	return v, nil
}

// Put stores the data in the cache under the specified key.
// Underlying implementations may use any data storage format,
// as long as the reverse operation, Get, results in the original data.
func (k *k8sStateStore) WriteState(id ipn.StateKey, bs []byte) error {
	k.storeMu.Lock()
	defer k.storeMu.Unlock()

	ctx := context.Background()

	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var needsCreate bool
		sec, err := k.clientset.CoreV1().Secrets(k.namespace).Get(ctx, k.secret, metav1.GetOptions{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				// unexpected
				return fmt.Errorf("fetching %s/%s from destination: %v", k.namespace, k.secret, err)
			}
			// item wasn't found, start with a new one
			needsCreate = true
			sec = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: k.namespace,
					Name:      k.secret,
				},
				Data: map[string][]byte{},
			}
		}

		sec.Data[k.cmKeyForStateKey(id)] = bs

		if needsCreate {
			// need to return the raw error so the retry can detect a conflict and correctly retry.
			// TODO at some point I hope error wrapping is supported, if it is return more descriptive with %w
			if _, err := k.clientset.CoreV1().Secrets(k.namespace).Create(context.TODO(), sec, metav1.CreateOptions{}); err != nil {
				return err
			}
		} else {
			if _, err := k.clientset.CoreV1().Secrets(k.namespace).Update(context.TODO(), sec, metav1.UpdateOptions{}); err != nil {
				return err
			}
		}

		k.currentSecret = sec

		return nil
	})
	if err != nil {
		return fmt.Errorf("putting in secret %s/%s: %v", k.namespace, k.secret, err)
	}

	return nil
}

func (c *k8sStateStore) cmKeyForStateKey(id ipn.StateKey) string {
	return fmt.Sprintf("%s-%s", c.name, base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(id)))
}
