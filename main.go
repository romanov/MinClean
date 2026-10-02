package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

//go:embed certs/Russian_Trusted_Root_CA.cer
var bundledCertificate []byte

type fingerprint = [sha256.Size]byte

type store struct {
	Location string
	Name     string
	Flags    uint32
}

func (s store) String() string { return s.Location + `\` + s.Name }

type match struct {
	Store store
	Count int
}

type certificateStores interface {
	Scan(fingerprint) ([]match, []error)
	Remove(store, fingerprint) (int, error)
}

func main() {
	input := bufio.NewReader(os.Stdin)
	pause := ownsInteractiveConsole()
	code := run(os.Args[1:], input, os.Stdout, os.Stderr, windowsStores{})
	if pause {
		fmt.Fprint(os.Stdout, "\nPress Enter to close this window...")
		_, _ = input.ReadString('\n')
	}
	os.Exit(code)
}

func parseCertificate(data []byte) (*x509.Certificate, error) {
	if block, rest := pem.Decode(data); block != nil {
		if block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
			return nil, fmt.Errorf("expected exactly one PEM certificate")
		}
		data = block.Bytes
	}
	return x509.ParseCertificate(data)
}

// Exit codes: 0 absent/removed, 1 present, 2 error or incomplete verification.
func run(args []string, input io.Reader, output, errorOutput io.Writer, backend certificateStores) int {
	flags := flag.NewFlagSet("minclean", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	remove := flags.Bool("remove", false, "remove exact matches after confirmation")
	yes := flags.Bool("yes", false, "skip confirmation (requires -remove)")
	flags.Usage = func() {
		fmt.Fprintln(errorOutput, "Usage: minclean [-remove [-yes]]")
		fmt.Fprintln(errorOutput, "Checks current-user and local-machine Windows certificate stores.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || (*yes && !*remove) {
		flags.Usage()
		return 2
	}

	cert, err := parseCertificate(bundledCertificate)
	if err != nil {
		fmt.Fprintf(errorOutput, "Cannot read bundled certificate: %v\n", err)
		return 2
	}
	target := sha256.Sum256(cert.Raw)
	fmt.Fprintf(output, "Certificate: %s\nSHA-256: %X\nSHA-1 thumbprint: %X\n\n", cert.Subject.CommonName, target, sha1.Sum(cert.Raw))

	matches, scanErrors := backend.Scan(target)
	printErrors(errorOutput, scanErrors)
	if len(matches) == 0 {
		if len(scanErrors) > 0 {
			fmt.Fprintln(output, "No matches in the stores that could be checked; scan incomplete.")
			return 2
		}
		fmt.Fprintln(output, "NOT INSTALLED in the current-user or local-machine Windows stores.")
		return 0
	}
	fmt.Fprintln(output, "INSTALLED: exact certificate found in these Windows store views:")
	for _, found := range matches {
		fmt.Fprintf(output, "  %s (%d match(es))\n", found.Store, found.Count)
	}
	fmt.Fprintln(output, "Machine certificates may also appear in the current-user view.")
	if !*remove {
		fmt.Fprintln(output, "To remove it, run: minclean.exe -remove")
		if len(scanErrors) > 0 {
			return 2
		}
		return 1
	}
	if !*yes {
		fmt.Fprintln(output, "Removing this root may stop sites signed by it from being trusted.")
		fmt.Fprint(output, "Remove every accessible exact match listed above? Type yes: ")
		answer, readErr := bufio.NewReader(input).ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			fmt.Fprintf(errorOutput, "Cannot read confirmation: %v\n", readErr)
			return 2
		}
		if !strings.EqualFold(strings.TrimSpace(answer), "yes") {
			fmt.Fprintln(output, "Removal cancelled.")
			if len(scanErrors) > 0 {
				return 2
			}
			return 1
		}
	}

	failed := false
	for _, found := range matches {
		count, err := backend.Remove(found.Store, target)
		if err != nil {
			failed = true
			fmt.Fprintf(errorOutput, "Could not fully remove from %s: %v\n", found.Store, err)
		}
		fmt.Fprintf(output, "Removed %d match(es) from %s.\n", count, found.Store)
	}
	remaining, verifyErrors := backend.Scan(target)
	printErrors(errorOutput, verifyErrors)
	if len(remaining) > 0 {
		fmt.Fprintln(output, "STILL INSTALLED:")
		for _, found := range remaining {
			fmt.Fprintf(output, "  %s (%d match(es))\n", found.Store, found.Count)
		}
		fmt.Fprintln(output, "For machine-store access errors, rerun from a terminal opened as Administrator.")
		fmt.Fprintln(output, "Policy-managed certificates may require a policy change and can be reinstalled.")
		return 2
	}
	if len(verifyErrors) > 0 {
		fmt.Fprintln(output, "Removal could not be fully verified: some stores were inaccessible.")
		return 2
	}
	fmt.Fprintln(output, "Verified: the certificate is absent from the checked Windows stores.")
	if failed {
		return 2
	}
	return 0
}

func printErrors(output io.Writer, errors []error) {
	for _, err := range errors {
		fmt.Fprintf(output, "Scan error: %v\n", err)
	}
}
