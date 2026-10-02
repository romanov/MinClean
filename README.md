# MinClean

A small Windows console app that checks whether the exact certificate in
`certs/Russian_Trusted_Root_CA.cer` is installed and can remove it on request.
The certificate is embedded at build time, so the executable works on its own.

## Build and use

Requires Go 1.22 or newer. No third-party dependencies or PowerShell subprocesses.

```powershell
go build -o minclean.exe .
```

You can also double-click `minclean.exe` in Explorer to check the certificate.
The window displays the result and waits for **Enter** before closing. When run
from an existing terminal or with redirected input/output, it exits normally.

Check only (the default):

```powershell
.\minclean.exe
```

Remove all accessible exact matches, with an interactive `yes` confirmation:

```powershell
.\minclean.exe -remove
```

For unattended use, explicitly skip the confirmation:

```powershell
.\minclean.exe -remove -yes
```

Run removal from a terminal opened **as Administrator** if a machine store
reports access denied. The app reports partial failures and rescans after
removal; it does not claim success when verification is incomplete.

## Matching and scope

Matching uses SHA-256 of the certificate's DER encoding, never just its name.
The SHA-1 thumbprint is printed only for comparison with Windows certificate
tools. Other certificates with the same subject are left alone.

The app enumerates all logical stores available to the current Windows user and
the local machine, including archived certificates. Logical stores can include
policy and enterprise certificates. A machine certificate can also appear in a
current-user store view, so the displayed matches are not necessarily distinct
installed copies. Removal acts on each matching certificate's backing store.
Removing a trusted root may cause sites signed by it to become untrusted.

Other user profiles, separate browser/application certificate databases, and
service-specific stores are outside the scan. Renewed or reissued certificates
with different contents are outside this exact-certificate match. A managed
policy may prevent removal or reinstall the certificate later; the policy must
then be changed by its administrator.

Exit codes (also available as `$LASTEXITCODE` in PowerShell):

| Code | Meaning |
| --- | --- |
| 0 | Certificate absent, or removal verified; also `-help` |
| 1 | Certificate present; also removal cancelled |
| 2 | Invalid arguments, scan/access error, removal failure, or incomplete verification |

## Verification

```powershell
go test ./...
go vet ./...
```

Tests cover confirmation, partial failures, and real CryptoAPI detection/removal
in a temporary in-memory store, including a different certificate with the same
subject and duplicate exact matches. Tests do not modify live system stores.

Windows API references: [certificate store locations](https://learn.microsoft.com/en-us/windows/win32/seccrypto/system-store-locations),
[opening stores](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore),
and [deleting certificates](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certdeletecertificatefromstore).
