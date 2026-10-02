//go:build !windows

package main

import "errors"

type windowsStores struct{}

func (windowsStores) Scan(fingerprint) ([]match, []error) {
	return nil, []error{errors.New("MinClean requires Windows")}
}

func (windowsStores) Remove(store, fingerprint) (int, error) {
	return 0, errors.New("MinClean requires Windows")
}
