## Docker image created locally
```
$ docker images
REPOSITORY                 TAG       IMAGE ID       CREATED         SIZE
solimage                   v1        d7c703235200   16 months ago   41MB
```

## Trivy scan on the docker image
```
$ trivy image solimage:v1
2024-07-25T21:16:36-07:00       INFO    Vulnerability scanning is enabled
2024-07-25T21:16:36-07:00       INFO    Secret scanning is enabled
2024-07-25T21:16:36-07:00       INFO    If your scanning is slow, please try '--scanners vuln' to disable secret scanning
2024-07-25T21:16:36-07:00       INFO    Please see also https://aquasecurity.github.io/trivy/dev/docs/scanner/secret#recommendation for faster secret detection
2024-07-25T21:16:36-07:00       INFO    Detected OS     family="alpine" version="3.17.3"
2024-07-25T21:16:36-07:00       INFO    [alpine] Detecting vulnerabilities...   os_version="3.17" repository="3.17" pkg_num=62
2024-07-25T21:16:36-07:00       INFO    Number of language-specific files       num=0
2024-07-25T21:16:36-07:00       WARN    Using severities from other vendors for some vulnerabilities. Read https://aquasecurity.github.io/trivy/dev/docs/scanner/vulnerability#severity-selection for details.

solimage:v1 (alpine 3.17.3)
===========================
Total: 88 (UNKNOWN: 0, LOW: 6, MEDIUM: 62, HIGH: 18, CRITICAL: 2)

┌───────────────────────┬────────────────┬──────────┬────────┬───────────────────┬──────────────────┬──────────────────────────────────────────────────────────────┐
│        Library        │ Vulnerability  │ Severity │ Status │ Installed Version │  Fixed Version   │                            Title                             │
├───────────────────────┼────────────────┼──────────┼────────┼───────────────────┼──────────────────┼──────────────────────────────────────────────────────────────┤
│ busybox               │ CVE-2023-42363 │ MEDIUM   │ fixed  │ 1.35.0-r29        │ 1.35.0-r31       │ busybox: use-after-free in awk                               │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-42363                   │
│                       ├────────────────┤          │        │                   │                  ├──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-42364 │          │        │                   │                  │ busybox: use-after-free                                      │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-42364                   │
│                       ├────────────────┤          │        │                   │                  ├──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-42365 │          │        │                   │                  │ busybox: use-after-free                                      │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-42365                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-42366 │          │        │                   │ 1.35.0-r30       │ busybox: A heap-buffer-overflow                              │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-42366                   │
├───────────────────────┼────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│ busybox-binsh         │ CVE-2023-42363 │          │        │                   │ 1.35.0-r31       │ busybox: use-after-free in awk                               │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-42363                   │
│                       ├────────────────┤          │        │                   │                  ├──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-42364 │          │        │                   │                  │ busybox: use-after-free                                      │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-42364                   │
│                       ├────────────────┤          │        │                   │                  ├──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-42365 │          │        │                   │                  │ busybox: use-after-free                                      │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-42365                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-42366 │          │        │                   │ 1.35.0-r30       │ busybox: A heap-buffer-overflow                              │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-42366                   │
├───────────────────────┼────────────────┼──────────┤        ├───────────────────┼──────────────────┼──────────────────────────────────────────────────────────────┤
│ curl                  │ CVE-2023-38545 │ CRITICAL │        │ 7.88.1-r1         │ 8.4.0-r0         │ curl: heap based buffer overflow in the SOCKS5 proxy         │
│                       │                │          │        │                   │                  │ handshake                                                    │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-38545                   │
│                       ├────────────────┼──────────┤        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-28319 │ HIGH     │        │                   │ 8.1.0-r0         │ curl: use after free in SSH sha256 fingerprint check         │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-28319                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-38039 │          │        │                   │ 8.3.0-r0         │ curl: out of heap memory issue due to missing limit on       │
│                       │                │          │        │                   │                  │ header...                                                    │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-38039                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-2398  │          │        │                   │ 8.7.1-r0         │ curl: HTTP/2 push headers memory-leak                        │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-2398                    │
│                       ├────────────────┼──────────┤        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-28320 │ MEDIUM   │        │                   │ 8.1.0-r0         │ curl: siglongjmp race condition may lead to crash            │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-28320                   │
│                       ├────────────────┤          │        │                   │                  ├──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-28321 │          │        │                   │                  │ curl: IDN wildcard match may lead to Improper Cerificate     │
│                       │                │          │        │                   │                  │ Validation                                                   │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-28321                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-46218 │          │        │                   │ 8.5.0-r0         │ curl: information disclosure by exploiting a mixed case flaw │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-46218                   │
│                       ├────────────────┤          │        │                   │                  ├──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-46219 │          │        │                   │                  │ curl: excessively long file name may lead to unknown HSTS    │
│                       │                │          │        │                   │                  │ status                                                       │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-46219                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-0853  │          │        │                   │ 8.6.0-r0         │ curl: OCSP verification bypass with TLS session reuse        │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-0853                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-2004  │          │        │                   │ 8.7.1-r0         │ curl: Usage of disabled protocol                             │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-2004                    │
│                       ├────────────────┤          │        │                   │                  ├──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-2379  │          │        │                   │                  │ curl: QUIC certificate check bypass with wolfSSL             │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-2379                    │
│                       ├────────────────┤          │        │                   │                  ├──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-2466  │          │        │                   │                  │ curl: TLS certificate check bypass with mbedTLS              │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-2466                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-6197  │          │        │                   │ 8.9.0-r0         │ curl: freeing stack buffer in utf8asn1str                    │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-6197                    │
│                       ├────────────────┤          │        │                   │                  ├──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-6874  │          │        │                   │                  │ curl: macidn punycode buffer overread                        │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-6874                    │
│                       ├────────────────┼──────────┤        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-28322 │ LOW      │        │                   │ 8.1.0-r0         │ curl: more POST-after-PUT confusion                          │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-28322                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-38546 │          │        │                   │ 8.4.0-r0         │ curl: cookie injection with none file                        │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-38546                   │
├───────────────────────┼────────────────┼──────────┤        ├───────────────────┼──────────────────┼──────────────────────────────────────────────────────────────┤
│ libcrypto3            │ CVE-2023-5363  │ HIGH     │        │ 3.0.8-r3          │ 3.0.12-r0        │ openssl: Incorrect cipher key and IV length processing       │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-5363                    │
│                       ├────────────────┼──────────┤        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-1255  │ MEDIUM   │        │                   │ 3.0.8-r4         │ openssl: Input buffer over-read in AES-XTS implementation on │
│                       │                │          │        │                   │                  │ 64 bit ARM                                                   │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-1255                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-2650  │          │        │                   │ 3.0.9-r0         │ openssl: Possible DoS translating ASN.1 object identifiers   │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-2650                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-2975  │          │        │                   │ 3.0.9-r2         │ openssl: AES-SIV cipher implementation contains a bug that   │
│                       │                │          │        │                   │                  │ causes it to ignore...                                       │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-2975                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-3446  │          │        │                   │ 3.0.9-r3         │ openssl: Excessive time spent checking DH keys and           │
│                       │                │          │        │                   │                  │ parameters                                                   │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-3446                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-3817  │          │        │                   │ 3.0.10-r0        │ OpenSSL: Excessive time spent checking DH q parameter value  │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-3817                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-5678  │          │        │                   │ 3.0.12-r1        │ openssl: Generating excessively long X9.42 DH keys or        │
│                       │                │          │        │                   │                  │ checking excessively long X9.42...                           │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-5678                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-6129  │          │        │                   │ 3.0.12-r2        │ mysql: openssl: POLY1305 MAC implementation corrupts vector  │
│                       │                │          │        │                   │                  │ registers on PowerPC                                         │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-6129                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-6237  │          │        │                   │ 3.0.12-r3        │ openssl: Excessive time spent checking invalid RSA public    │
│                       │                │          │        │                   │                  │ keys                                                         │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-6237                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-0727  │          │        │                   │ 3.0.12-r4        │ openssl: denial of service via null dereference              │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-0727                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-4603  │          │        │                   │ 3.0.13-r0        │ openssl: Excessive time spent checking DSA keys and          │
│                       │                │          │        │                   │                  │ parameters                                                   │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-4603                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-4741  │          │        │                   │ 3.0.14-r0        │ openssl: Use After Free with SSL_free_buffers                │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-4741                    │
│                       ├────────────────┤          │        │                   │                  ├──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-5535  │          │        │                   │                  │ openssl: SSL_select_next_proto buffer overread               │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-5535                    │
│                       ├────────────────┼──────────┤        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-2511  │ LOW      │        │                   │ 3.0.12-r5        │ openssl: Unbounded memory growth with session handling in    │
│                       │                │          │        │                   │                  │ TLSv1.3                                                      │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-2511                    │
├───────────────────────┼────────────────┼──────────┤        ├───────────────────┼──────────────────┼──────────────────────────────────────────────────────────────┤
│ libcurl               │ CVE-2023-38545 │ CRITICAL │        │ 7.88.1-r1         │ 8.4.0-r0         │ curl: heap based buffer overflow in the SOCKS5 proxy         │
│                       │                │          │        │                   │                  │ handshake                                                    │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-38545                   │
│                       ├────────────────┼──────────┤        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-28319 │ HIGH     │        │                   │ 8.1.0-r0         │ curl: use after free in SSH sha256 fingerprint check         │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-28319                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-38039 │          │        │                   │ 8.3.0-r0         │ curl: out of heap memory issue due to missing limit on       │
│                       │                │          │        │                   │                  │ header...                                                    │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-38039                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-2398  │          │        │                   │ 8.7.1-r0         │ curl: HTTP/2 push headers memory-leak                        │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-2398                    │
│                       ├────────────────┼──────────┤        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-28320 │ MEDIUM   │        │                   │ 8.1.0-r0         │ curl: siglongjmp race condition may lead to crash            │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-28320                   │
│                       ├────────────────┤          │        │                   │                  ├──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-28321 │          │        │                   │                  │ curl: IDN wildcard match may lead to Improper Cerificate     │
│                       │                │          │        │                   │                  │ Validation                                                   │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-28321                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-46218 │          │        │                   │ 8.5.0-r0         │ curl: information disclosure by exploiting a mixed case flaw │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-46218                   │
│                       ├────────────────┤          │        │                   │                  ├──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-46219 │          │        │                   │                  │ curl: excessively long file name may lead to unknown HSTS    │
│                       │                │          │        │                   │                  │ status                                                       │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-46219                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-0853  │          │        │                   │ 8.6.0-r0         │ curl: OCSP verification bypass with TLS session reuse        │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-0853                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-2004  │          │        │                   │ 8.7.1-r0         │ curl: Usage of disabled protocol                             │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-2004                    │
│                       ├────────────────┤          │        │                   │                  ├──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-2379  │          │        │                   │                  │ curl: QUIC certificate check bypass with wolfSSL             │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-2379                    │
│                       ├────────────────┤          │        │                   │                  ├──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-2466  │          │        │                   │                  │ curl: TLS certificate check bypass with mbedTLS              │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-2466                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-6197  │          │        │                   │ 8.9.0-r0         │ curl: freeing stack buffer in utf8asn1str                    │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-6197                    │
│                       ├────────────────┤          │        │                   │                  ├──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-6874  │          │        │                   │                  │ curl: macidn punycode buffer overread                        │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-6874                    │
│                       ├────────────────┼──────────┤        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-28322 │ LOW      │        │                   │ 8.1.0-r0         │ curl: more POST-after-PUT confusion                          │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-28322                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-38546 │          │        │                   │ 8.4.0-r0         │ curl: cookie injection with none file                        │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-38546                   │
├───────────────────────┼────────────────┼──────────┤        ├───────────────────┼──────────────────┼──────────────────────────────────────────────────────────────┤
│ libexpat              │ CVE-2023-52425 │ HIGH     │        │ 2.5.0-r0          │ 2.6.0-r0         │ expat: parsing large tokens can trigger a denial of service  │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-52425                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-28757 │          │        │                   │ 2.6.2-r0         │ expat: XML Entity Expansion                                  │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-28757                   │
│                       ├────────────────┼──────────┤        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-52426 │ MEDIUM   │        │                   │ 2.6.0-r0         │ expat: recursive XML entity expansion vulnerability          │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-52426                   │
├───────────────────────┼────────────────┼──────────┤        ├───────────────────┼──────────────────┼──────────────────────────────────────────────────────────────┤
│ libssl3               │ CVE-2023-5363  │ HIGH     │        │ 3.0.8-r3          │ 3.0.12-r0        │ openssl: Incorrect cipher key and IV length processing       │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-5363                    │
│                       ├────────────────┼──────────┤        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-1255  │ MEDIUM   │        │                   │ 3.0.8-r4         │ openssl: Input buffer over-read in AES-XTS implementation on │
│                       │                │          │        │                   │                  │ 64 bit ARM                                                   │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-1255                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-2650  │          │        │                   │ 3.0.9-r0         │ openssl: Possible DoS translating ASN.1 object identifiers   │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-2650                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-2975  │          │        │                   │ 3.0.9-r2         │ openssl: AES-SIV cipher implementation contains a bug that   │
│                       │                │          │        │                   │                  │ causes it to ignore...                                       │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-2975                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-3446  │          │        │                   │ 3.0.9-r3         │ openssl: Excessive time spent checking DH keys and           │
│                       │                │          │        │                   │                  │ parameters                                                   │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-3446                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-3817  │          │        │                   │ 3.0.10-r0        │ OpenSSL: Excessive time spent checking DH q parameter value  │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-3817                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-5678  │          │        │                   │ 3.0.12-r1        │ openssl: Generating excessively long X9.42 DH keys or        │
│                       │                │          │        │                   │                  │ checking excessively long X9.42...                           │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-5678                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-6129  │          │        │                   │ 3.0.12-r2        │ mysql: openssl: POLY1305 MAC implementation corrupts vector  │
│                       │                │          │        │                   │                  │ registers on PowerPC                                         │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-6129                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-6237  │          │        │                   │ 3.0.12-r3        │ openssl: Excessive time spent checking invalid RSA public    │
│                       │                │          │        │                   │                  │ keys                                                         │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-6237                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-0727  │          │        │                   │ 3.0.12-r4        │ openssl: denial of service via null dereference              │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-0727                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-4603  │          │        │                   │ 3.0.13-r0        │ openssl: Excessive time spent checking DSA keys and          │
│                       │                │          │        │                   │                  │ parameters                                                   │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-4603                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-4741  │          │        │                   │ 3.0.14-r0        │ openssl: Use After Free with SSL_free_buffers                │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-4741                    │
│                       ├────────────────┤          │        │                   │                  ├──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-5535  │          │        │                   │                  │ openssl: SSL_select_next_proto buffer overread               │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-5535                    │
│                       ├────────────────┼──────────┤        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2024-2511  │ LOW      │        │                   │ 3.0.12-r5        │ openssl: Unbounded memory growth with session handling in    │
│                       │                │          │        │                   │                  │ TLSv1.3                                                      │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2024-2511                    │
├───────────────────────┼────────────────┼──────────┤        ├───────────────────┼──────────────────┼──────────────────────────────────────────────────────────────┤
│ libwebp               │ CVE-2023-1999  │ HIGH     │        │ 1.2.4-r1          │ 1.2.4-r2         │ Mozilla: libwebp: Double-free in libwebp                     │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-1999                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-4863  │          │        │                   │ 1.2.4-r3         │ libwebp: Heap buffer overflow in WebP Codec                  │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-4863                    │
├───────────────────────┼────────────────┤          │        ├───────────────────┼──────────────────┼──────────────────────────────────────────────────────────────┤
│ libx11                │ CVE-2023-3138  │          │        │ 1.8.4-r0          │ 1.8.4-r1         │ libX11: InitExt.c can overwrite unintended portions of the   │
│                       │                │          │        │                   │                  │ Display structure if the...                                  │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-3138                    │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-43787 │          │        │                   │ 1.8.7-r0         │ libX11: integer overflow in XCreateImage() leading to a heap │
│                       │                │          │        │                   │                  │ overflow                                                     │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-43787                   │
│                       ├────────────────┼──────────┤        │                   │                  ├──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-43785 │ MEDIUM   │        │                   │                  │ libX11: out-of-bounds memory access in _XkbReadKeySyms()     │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-43785                   │
│                       ├────────────────┤          │        │                   │                  ├──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-43786 │          │        │                   │                  │ libX11: stack exhaustion from infinite recursion in          │
│                       │                │          │        │                   │                  │ PutSubImage()                                                │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-43786                   │
├───────────────────────┼────────────────┤          │        ├───────────────────┼──────────────────┼──────────────────────────────────────────────────────────────┤
│ libxml2               │ CVE-2023-28484 │          │        │ 2.10.3-r1         │ 2.10.4-r0        │ libxml2: NULL dereference in xmlSchemaFixupComplexType       │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-28484                   │
│                       ├────────────────┤          │        │                   │                  ├──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-29469 │          │        │                   │                  │ libxml2: Hashing of empty dict strings isn't deterministic   │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-29469                   │
├───────────────────────┼────────────────┼──────────┤        ├───────────────────┼──────────────────┼──────────────────────────────────────────────────────────────┤
│ ncurses-libs          │ CVE-2023-29491 │ HIGH     │        │ 6.3_p20221119-r0  │ 6.3_p20221119-r1 │ ncurses: Local users can trigger security-relevant memory    │
│                       │                │          │        │                   │                  │ corruption via malformed data                                │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-29491                   │
├───────────────────────┤                │          │        │                   │                  │                                                              │
│ ncurses-terminfo-base │                │          │        │                   │                  │                                                              │
│                       │                │          │        │                   │                  │                                                              │
│                       │                │          │        │                   │                  │                                                              │
├───────────────────────┼────────────────┤          │        ├───────────────────┼──────────────────┼──────────────────────────────────────────────────────────────┤
│ nghttp2-libs          │ CVE-2023-35945 │          │        │ 1.51.0-r0         │ 1.51.0-r1        │ envoy: HTTP/2 memory leak in nghttp2 codec                   │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-35945                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-44487 │          │        │                   │ 1.51.0-r2        │ HTTP/2: Multiple HTTP/2 enabled web servers are vulnerable   │
│                       │                │          │        │                   │                  │ to a DDoS attack...                                          │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-44487                   │
├───────────────────────┼────────────────┼──────────┤        ├───────────────────┼──────────────────┼──────────────────────────────────────────────────────────────┤
│ ssl_client            │ CVE-2023-42363 │ MEDIUM   │        │ 1.35.0-r29        │ 1.35.0-r31       │ busybox: use-after-free in awk                               │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-42363                   │
│                       ├────────────────┤          │        │                   │                  ├──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-42364 │          │        │                   │                  │ busybox: use-after-free                                      │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-42364                   │
│                       ├────────────────┤          │        │                   │                  ├──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-42365 │          │        │                   │                  │ busybox: use-after-free                                      │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-42365                   │
│                       ├────────────────┤          │        │                   ├──────────────────┼──────────────────────────────────────────────────────────────┤
│                       │ CVE-2023-42366 │          │        │                   │ 1.35.0-r30       │ busybox: A heap-buffer-overflow                              │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-42366                   │
├───────────────────────┼────────────────┤          │        ├───────────────────┼──────────────────┼──────────────────────────────────────────────────────────────┤
│ tiff                  │ CVE-2023-3316  │          │        │ 4.4.0-r3          │ 4.4.0-r4         │ libtiff: tiffcrop: null pointer dereference in TIFFClose()   │
│                       │                │          │        │                   │                  │ https://avd.aquasec.com/nvd/cve-2023-3316                    │
└───────────────────────┴────────────────┴──────────┴────────┴───────────────────┴──────────────────┴──────────────────────────────────────────────────────────────┘
```
## New docker image after updating the base image 
```
$ docker images
REPOSITORY                 TAG       IMAGE ID       CREATED         SIZE
solimage                   v3        489010e55324   6 minutes ago   46.6MB
solimage                   v1        d7c703235200   16 months ago   41MB
```
## Trivy scan on the updated docker image; Resolved all the vulnerabilities
```
$ trivy image solimage:v3
2024-07-28T19:56:27-07:00       INFO    Vulnerability scanning is enabled
2024-07-28T19:56:27-07:00       INFO    Secret scanning is enabled
2024-07-28T19:56:27-07:00       INFO    If your scanning is slow, please try '--scanners vuln' to disable secret scanning
2024-07-28T19:56:27-07:00       INFO    Please see also https://aquasecurity.github.io/trivy/dev/docs/scanner/secret#recommendation for faster secret detection
2024-07-28T19:56:28-07:00       INFO    Detected OS     family="alpine" version="3.19.3"
2024-07-28T19:56:28-07:00       INFO    [alpine] Detecting vulnerabilities...   os_version="3.19" repository="3.19" pkg_num=66
2024-07-28T19:56:28-07:00       INFO    Number of language-specific files       num=0

solimage:v3 (alpine 3.19.3)
===========================
Total: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)
```
