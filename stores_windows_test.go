//go:build windows

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"syscall"
	"testing"
	"time"
)

// Exercise the real CryptoAPI with an isolated in-memory store. No test installs
// or removes certificates in the user's or machine's actual certificate stores.
func TestNativeExactMatchRemoval(t *testing.T) {
	handle, err := syscall.CertOpenStore(syscall.CERT_STORE_PROV_MEMORY, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		// CERT_CLOSE_STORE_CHECK_FLAG catches leaked certificate contexts.
		if err := syscall.CertCloseStore(handle, 2); err != nil {
			t.Errorf("close memory store: %v", err)
		}
	}()
	targetCert, err := parseCertificate(bundledCertificate)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(123), Subject: targetCert.Subject,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	unrelated, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, der := range [][]byte{targetCert.Raw, unrelated, targetCert.Raw} {
		context, err := syscall.CertCreateCertificateContext(1, &der[0], uint32(len(der)))
		if err != nil {
			t.Fatal(err)
		}
		err = syscall.CertAddCertificateContextToStore(handle, context, 4, nil) // ADD_ALWAYS
		freeErr := syscall.CertFreeCertificateContext(context)
		if err != nil || freeErr != nil {
			t.Fatalf("add: %v; free: %v", err, freeErr)
		}
	}
	target := sha256.Sum256(targetCert.Raw)
	for _, step := range []struct {
		target fingerprint
		remove bool
		want   int
	}{
		{target, false, 2},
		{sha256.Sum256(unrelated), false, 1},
		{target, true, 2},
		{target, false, 0},
		{sha256.Sum256(unrelated), false, 1},
		{target, true, 0},
	} {
		count, err := visitCertificates(handle, step.target, step.remove)
		if err != nil || count != step.want {
			t.Fatalf("remove=%v: count=%d, want %d; error=%v", step.remove, count, step.want, err)
		}
	}
}
