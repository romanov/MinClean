package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

type fakeStores struct {
	scans       int
	removes     int
	installed   bool
	scanErrors  []error
	removeError error
}

func (f *fakeStores) Scan(fingerprint) ([]match, []error) {
	f.scans++
	if f.installed {
		return []match{{Store: store{Location: "CurrentUser", Name: "Root"}, Count: 1}}, f.scanErrors
	}
	return nil, f.scanErrors
}

func (f *fakeStores) Remove(store, fingerprint) (int, error) {
	f.removes++
	if f.removeError != nil {
		return 0, f.removeError
	}
	f.installed = false
	return 1, nil
}

func TestCommands(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		input   string
		backend fakeStores
		code    int
		removes int
		scans   int
		message string
	}{
		{name: "absent", code: 0, scans: 1, message: "NOT INSTALLED"},
		{name: "present is read only", backend: fakeStores{installed: true}, code: 1, scans: 1, message: "INSTALLED:"},
		{name: "declined", args: []string{"-remove"}, input: "no\n", backend: fakeStores{installed: true}, code: 1, scans: 1, message: "cancelled"},
		{name: "EOF cancels", args: []string{"-remove"}, backend: fakeStores{installed: true}, code: 1, scans: 1, message: "cancelled"},
		{name: "confirmed", args: []string{"-remove"}, input: "yes\n", backend: fakeStores{installed: true}, code: 0, removes: 1, scans: 2, message: "Verified:"},
		{name: "automated", args: []string{"-remove", "-yes"}, backend: fakeStores{installed: true}, code: 0, removes: 1, scans: 2, message: "Verified:"},
		{name: "yes requires remove", args: []string{"-yes"}, code: 2},
		{name: "unexpected argument", args: []string{"typo"}, code: 2},
		{name: "scan error is not absence", backend: fakeStores{scanErrors: []error{errors.New("denied")}}, code: 2, scans: 1, message: "scan incomplete"},
		{name: "present with scan error", backend: fakeStores{installed: true, scanErrors: []error{errors.New("denied")}}, code: 2, scans: 1, message: "INSTALLED:"},
		{name: "deletion denied", args: []string{"-remove", "-yes"}, backend: fakeStores{installed: true, removeError: errors.New("denied")}, code: 2, removes: 1, scans: 2, message: "STILL INSTALLED"},
		{name: "verification incomplete", args: []string{"-remove", "-yes"}, backend: fakeStores{installed: true, scanErrors: []error{errors.New("denied")}}, code: 2, removes: 1, scans: 2, message: "could not be fully verified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output, errorOutput bytes.Buffer
			code := run(tc.args, strings.NewReader(tc.input), &output, &errorOutput, &tc.backend)
			if code != tc.code || tc.backend.removes != tc.removes || tc.backend.scans != tc.scans || !strings.Contains(output.String(), tc.message) {
				t.Fatalf("code=%d removes=%d scans=%d\n%s\n%s", code, tc.backend.removes, tc.backend.scans, &output, &errorOutput)
			}
		})
	}
}

func TestBundledCertificate(t *testing.T) {
	cert, err := parseCertificate(bundledCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "Russian Trusted Root CA" || !cert.IsCA {
		t.Fatalf("unexpected bundled certificate: %s", cert.Subject)
	}
	derCert, err := parseCertificate(cert.Raw)
	if err != nil || sha256.Sum256(derCert.Raw) != sha256.Sum256(cert.Raw) {
		t.Fatalf("DER parse failed: %v", err)
	}
	for _, invalid := range [][]byte{[]byte("not a certificate"), append(append([]byte{}, bundledCertificate...), bundledCertificate...)} {
		if _, err := parseCertificate(invalid); err == nil {
			t.Fatal("accepted invalid certificate data")
		}
	}
}
