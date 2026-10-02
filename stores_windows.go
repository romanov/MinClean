//go:build windows

package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"syscall"
	"unsafe"
)

const (
	storeProviderSystemW = 10
	storeOpenExisting    = 0x00004000
	storeReadOnly        = 0x00008000
	storeEnumArchived    = 0x00000200
	storeCurrentUser     = 0x00010000
	storeLocalMachine    = 0x00020000
	cryptNotFound        = syscall.Errno(0x80092004)
)

var (
	crypt32       = syscall.NewLazyDLL("crypt32.dll")
	enumStores    = crypt32.NewProc("CertEnumSystemStore")
	duplicateCert = crypt32.NewProc("CertDuplicateCertificateContext")
	deleteCert    = crypt32.NewProc("CertDeleteCertificateFromStore")
)

type windowsStores struct{}

func (windowsStores) Scan(target fingerprint) ([]match, []error) {
	var matches []match
	var scanErrors []error
	for _, location := range []store{
		{Location: "CurrentUser", Flags: storeCurrentUser},
		{Location: "LocalMachine", Flags: storeLocalMachine},
	} {
		stores, err := listStores(location)
		if err != nil {
			scanErrors = append(scanErrors, fmt.Errorf("enumerate %s: %w", location.Location, err))
		}
		for _, s := range stores {
			count, err := visitStore(s, target, false)
			if count > 0 {
				matches = append(matches, match{Store: s, Count: count})
			}
			if err != nil {
				scanErrors = append(scanErrors, fmt.Errorf("%s: %w", s, err))
			}
		}
	}
	return matches, scanErrors
}

func (windowsStores) Remove(s store, target fingerprint) (int, error) {
	return visitStore(s, target, true)
}

func listStores(location store) ([]store, error) {
	var stores []store
	// Windows calls this synchronously. Each CLI run allocates only a few callbacks.
	callback := syscall.NewCallback(func(name *uint16, flags uint32, info, reserved, arg unsafe.Pointer) uintptr {
		var units []uint16
		for p := unsafe.Pointer(name); ; p = unsafe.Add(p, 2) {
			unit := *(*uint16)(p)
			if unit == 0 {
				break
			}
			units = append(units, unit)
		}
		s := location
		s.Name = syscall.UTF16ToString(units)
		stores = append(stores, s)
		return 1
	})
	ok, _, err := enumStores.Call(uintptr(location.Flags), 0, 0, callback)
	sort.Slice(stores, func(i, j int) bool { return stores[i].Name < stores[j].Name })
	if ok == 0 {
		return stores, apiError("CertEnumSystemStore", err)
	}
	if len(stores) == 0 {
		return nil, fmt.Errorf("no Windows stores enumerated")
	}
	return stores, nil
}

func visitStore(s store, target fingerprint, remove bool) (count int, err error) {
	name, err := syscall.UTF16PtrFromString(s.Name)
	if err != nil {
		return 0, err
	}
	flags := s.Flags | storeOpenExisting | storeEnumArchived
	if !remove {
		flags |= storeReadOnly
	}
	handle, err := syscall.CertOpenStore(storeProviderSystemW, 0, 0, flags, uintptr(unsafe.Pointer(name)))
	runtime.KeepAlive(name)
	if err != nil {
		return 0, fmt.Errorf("open store: %w", err)
	}
	defer func() { err = errors.Join(err, syscall.CertCloseStore(handle, 0)) }()
	return visitCertificates(handle, target, remove)
}

// Enumerating consumes the previous context. Delete a duplicate so that the
// original remains valid as the next enumeration's previous-context argument.
func visitCertificates(handle syscall.Handle, target fingerprint, remove bool) (int, error) {
	var previous *syscall.CertContext
	count := 0
	var failures []error
	for {
		context, err := syscall.CertEnumCertificatesInStore(handle, previous)
		previous = context
		if context == nil {
			if err != cryptNotFound && err != syscall.ERROR_NO_MORE_FILES {
				failures = append(failures, fmt.Errorf("enumerate certificates: %w", err))
			}
			return count, errors.Join(failures...)
		}
		encoded := unsafe.Slice(context.EncodedCert, int(context.Length))
		if sha256.Sum256(encoded) != target {
			continue
		}
		if remove {
			duplicate, _, duplicateErr := duplicateCert.Call(uintptr(unsafe.Pointer(context)))
			if duplicate == 0 {
				failures = append(failures, apiError("duplicate certificate", duplicateErr))
				continue
			}
			// CertDeleteCertificateFromStore frees the duplicate even on failure.
			ok, _, deleteErr := deleteCert.Call(duplicate)
			if ok == 0 {
				failures = append(failures, apiError("delete certificate", deleteErr))
				continue
			}
		}
		count++
	}
}

func apiError(operation string, err error) error {
	if err == nil || err == syscall.Errno(0) {
		return fmt.Errorf("%s failed without a Windows error code", operation)
	}
	return fmt.Errorf("%s: %w", operation, err)
}
