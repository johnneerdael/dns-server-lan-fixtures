# Public-only mail-security specimens

These values exercise OPENPGPKEY (type 61) and SMIMEA (type 53) DNS record
transport and decoding. They do not establish a working email identity, an
approved key, or a trusted certificate. Runtime values are in
`fault_proxy/security_records.py`; the separate additive Cloudflare import is
`external/cloudflare-security-records.zone`.

## OPENPGPKEY

The 683-byte payload is a real RSA-2048 transferable public key generated with
GnuPG for the synthetic UID `DNS QA Synthetic <dns-qa@example.invalid>`. It
contains a public-key packet, UID packet and self-certification signature. Its
fingerprint is **FA16EA1D9C1D75E67F1685B688321E58DF049EFF**. The temporary keyring
and private material were removed after public export; no private key is shipped.
Do not encrypt real messages to this test key: there is no retained decryption key.

The regression suite independently verifies packet types and, when GnuPG is
available, the self-signature. That establishes the specimen's format and internal
signature consistency, not trust in an email address. A self-signature alone
does not establish identity ownership.

[RFC 7929](https://www.rfc-editor.org/rfc/rfc7929.html) is Experimental. Real
mailbox discovery uses a hash-derived owner under `_openpgpkey` in the mailbox
domain and requires the specified DNSSEC treatment. Our `openpgpkey.<nonce>.fresh.example.test`
and public `<nonce>.openpgpkey.dns.quality-assurance.fyi` owners deliberately test
record handling rather than that mailbox-discovery workflow. The LAN is unsigned.

The key is larger than a complete 512-byte DNS response can hold. With no EDNS,
UDP returns TC and TCP can retrieve the whole key. The ordinary 1232-byte EDNS
test can carry it over UDP. Actual public DNSSEC signatures and path policies may
change response size; observe the received truncation flag and transport behavior.

## SMIMEA

The test value is:

```text
3 1 1 b24fd998ca466289386fd15e523a162f5ec09c1f9fa7fddffd7e7fc7c148fbd6
```

`3` identifies DANE-EE certificate usage, `1` selects SubjectPublicKeyInfo, and
the second `1` selects SHA-256. The final 32 bytes are the actual SHA-256 digest
of the DER SubjectPublicKeyInfo from [the public synthetic certificate](smimea-public-cert.pem).
The certificate's mailbox is `dns-qa@example.invalid`; it is self-signed test
material. Its private key was removed and is not shipped. A matching digest
does not turn it into a trusted real-world identity or test S/MIME message handling.

The regression suite recomputes that digest with OpenSSL when available.
[RFC 8162](https://www.rfc-editor.org/rfc/rfc8162.html) is Experimental and
describes real mailbox discovery under a hash-derived `_smimecert` owner.
These synthetic `smimea` probe owners do not implement that discovery process,
certificate validation, DNSSEC trust establishment, or mail encryption.

Keep these public values stable so captures remain comparable. Replacing a test
key or certificate is a test-data revision that needs new approved references.
