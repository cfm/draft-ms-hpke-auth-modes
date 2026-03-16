---
title: "Authenticated Modes for HPKE"
abbrev: "HPKE Authenticated Modes"
category: std

docname: draft-ms-hpke-auth-modes-latest
submissiontype: IETF # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
# area: AREA
# workgroup: HPKE
keyword:
  - AKEM
  - HPKE
  - authenticated KEM
  - implicit authentication
venue:
#  group: HPKE
#  type: Working Group
#  mail: hpke@ietf.org
  github: "cfm/draft-ms-hpke-auth-modes"

author:
  - fullname: Cory Myers
    role: editor
    organization: Freedom of the Press Foundation
    email: cfm@acm.org
  - fullname: Rowen S.
    role: editor
    organization: Freedom of the Press Foundation
    email: ro@freedom.press

normative:
  RFC2119:
  RFC8174:
  I-D.ietf-hpke-hpke:

informative:
  RFC5869:
  RFC9180:
  FIPS203:
    title: "Module-Lattice-Based Key-Encapsulation Mechanism Standard"
    author:
      org: "National Institute of Standards and Technology"
    date: August 2024
    seriesinfo:
      FIPS: "203"
    target: https://doi.org/10.6028/NIST.FIPS.203
  Alwen2021:
    title: "HPKE: Hybrid Public Key Encryption"
    rc: "Advances in Cryptology -- EUROCRYPT 2021, LNCS 12696, pp. 396-427"
    author:
      - name: Joël Alwen
      - name: Bruno Blanchet
      - name: Eduard Hauck
      - name: Eike Kiltz
      - name: Benjamin Lipp
      - name: Doreen Riepel
    date: 2021
    seriesinfo:
      DOI: "10.1007/978-3-030-77886-6_14"

--- abstract

{{I-D.ietf-hpke-hpke}} is a standards-track Internet-Draft that
supersedes the informational {{?RFC9180}} and omits `mode_auth` (0x02)
and `mode_auth_psk` (0x03). This document restores those two modes as a
strict extension, requiring only the addition of `AuthEncap`/`AuthDecap`
to the DHKEM, four Setup functions, and an update to `VerifyPSKInputs`.
The extension does not alter the externally observable behavior of
existing HPKE modes.

This document also illustrates, informatively, how the restored modes
may be applied. One such application uses `mode_auth_psk` with a
post-quantum KEM (PQ-KEM) shared secret as the PSK, providing hybrid
PQ/T confidentiality. This material is provided to motivate the
extension and may be developed as separate work.

--- middle

# Introduction

{{!I-D.ietf-hpke-hpke}} is the standards-track successor to the
informational {{?RFC9180}} and omits `mode_auth` and `mode_auth_psk` to
reduce the surface of the core specification. However, many protocol
designs require an authenticated key encapsulation mechanism (AKEM) — a
KEM whose shared secret is implicitly bound to the sender's static
private key — without requiring a full authenticated encryption context.
The DHKEM construction in {{!I-D.ietf-hpke-hpke}} already contains all
the primitives needed: `AuthEncap` computes a static-static DH value
`DH(skS, pkR)` alongside the ephemeral-static value and mixes both into
the key derivation, binding the output to the sender's key pair.

The normative core of this document is narrow: it restores `mode_auth`
and `mode_auth_psk` as a strict extension to {{!I-D.ietf-hpke-hpke}},
requiring only `AuthEncap`/`AuthDecap` on the DHKEM, four Setup
functions, and an updated `VerifyPSKInputs`. The externally observable
behavior of existing HPKE modes is unchanged.

{{sec-dh-akem}} and {{sec-suites}} describe, informatively, how the
restored modes might be applied, including a construction that layers
a post-quantum KEM shared secret as the PSK to achieve hybrid PQ/T
confidentiality. That material is provided to motivate the extension
and may be developed as separate work.

Implicit authentication does not provide non-repudiation, and the
authenticated modes inherit the Key Compromise Impersonation (KCI)
vulnerability common to all DH-based authentication schemes; both
limitations are discussed in {{sec-security}}.

# Conventions and Definitions
{::boilerplate bcp14-tagged}

Terms from {{I-D.ietf-hpke-hpke}} are used without redefinition. The
following additional term is used herein:

- **AKEM**: a KEM whose encapsulation additionally takes the sender's
  static private key and implicitly binds the shared secret to it.

# Authenticated Mode Extensions to {{I-D.ietf-hpke-hpke}} {#sec-ext}

This section specifies the additions to {{!I-D.ietf-hpke-hpke}} required
to restore `mode_auth` and `mode_auth_psk`. These extensions
are defined so that the externally observable behavior of existing HPKE
modes is unchanged, although this document updates the `VerifyPSKInputs`
procedure in {{I-D.ietf-hpke-hpke}}.

## Mode Identifiers

Two mode identifiers are added to the table in {{Section 5 of !I-D.ietf-hpke-hpke}}:

~~~
mode_auth     = 0x02
mode_auth_psk = 0x03
~~~

## DHKEM Extension: AuthEncap and AuthDecap {#sec-authencap}

The following two functions are added to the DHKEM, extending it to an
AKEM. All helper functions (`GenerateKeyPair`, `DH`, `SerializePublicKey`,
`DeserializePublicKey`, `ExtractAndExpand`) are as defined in
{{I-D.ietf-hpke-hpke}}.

~~~
def AuthEncap(pkR, skS):
  skE, pkE = GenerateKeyPair()
  dh = concat(DH(skE, pkR), DH(skS, pkR))
  enc = SerializePublicKey(pkE)
  pkRm = SerializePublicKey(pkR)
  pkSm = SerializePublicKey(pk(skS))
  kem_context = concat(enc, pkRm, pkSm)
  shared_secret = ExtractAndExpand(dh, kem_context)
  return shared_secret, enc

def AuthDecap(enc, skR, pkS):
  pkE = DeserializePublicKey(enc)
  dh = concat(DH(skR, pkE), DH(skR, pkS))
  pkRm = SerializePublicKey(pk(skR))
  pkSm = SerializePublicKey(pkS)
  kem_context = concat(enc, pkRm, pkSm)
  shared_secret = ExtractAndExpand(dh, kem_context)
  return shared_secret
~~~

## VerifyPSKInputs Update

The `VerifyPSKInputs` function defined in {{I-D.ietf-hpke-hpke}} is
extended to handle the two new modes. The updated function replaces the
original:

~~~
def VerifyPSKInputs(mode, psk, psk_id):
  got_psk = (psk != default_psk)
  got_psk_id = (psk_id != default_psk_id)
  if got_psk != got_psk_id:
    raise Exception("Inconsistent PSK inputs")
  if got_psk and mode in [mode_base, mode_auth]:
    raise Exception("PSK input provided when not needed")
  if (not got_psk) and mode in [mode_psk, mode_auth_psk]:
    raise Exception("Missing required PSK input")
~~~

The only change from the original is that `mode_base` is replaced by
`[mode_base, mode_auth]` and `mode_psk` is replaced by
`[mode_psk, mode_auth_psk]` in the final two guards.

## Setup Functions {#sec-setup}

The following four Setup functions are added alongside those defined in
{{I-D.ietf-hpke-hpke}}. `KeyScheduleS`/`KeyScheduleR` and
`AuthEncap`/`AuthDecap` are as defined in {{!I-D.ietf-hpke-hpke}} and
{{sec-authencap}} respectively.

~~~
def SetupAuthS(pkR, info, skS):
  shared_secret, enc = AuthEncap(pkR, skS)
  return enc, KeyScheduleS(mode_auth, shared_secret, info,
                           default_psk, default_psk_id)

def SetupAuthR(enc, skR, info, pkS):
  shared_secret = AuthDecap(enc, skR, pkS)
  return KeyScheduleR(mode_auth, shared_secret, info,
                      default_psk, default_psk_id)

def SetupAuthPSKS(pkR, info, psk, psk_id, skS):
  shared_secret, enc = AuthEncap(pkR, skS)
  return enc, KeyScheduleS(mode_auth_psk, shared_secret, info,
                           psk, psk_id)

def SetupAuthPSKR(enc, skR, info, psk, psk_id, pkS):
  shared_secret = AuthDecap(enc, skR, pkS)
  return KeyScheduleR(mode_auth_psk, shared_secret, info,
                      psk, psk_id)
~~~

# DH-AKEM Construction (Informative) {#sec-dh-akem}

This section is informative. It describes DH-AKEM, one intended
application of the authenticated mode extension defined in {{sec-ext}},
and may be developed as separate work.

DH-AKEM and DH-AKEM-Hybrid are usage profiles of the modes defined in
{{sec-ext}}. The AEAD is selected by the application; any AEAD
identifier from {{I-D.ietf-hpke-hpke}} may be used. The resulting
context supports `Seal`, `Open`, and `Export` per {{I-D.ietf-hpke-hpke}}.
Key generation is identical to `GenerateKeyPair` from
{{I-D.ietf-hpke-hpke}}.

## DH-AKEM (mode_auth)

For DH-AKEM the sender calls `SetupAuthS(pkR, info, skS)` and the
receiver calls `SetupAuthR(enc, skR, info, pkS)`, as defined in
{{sec-setup}}. The `enc` output is the serialized ephemeral public key
from `AuthEncap`, of length `Nenc` bytes for the chosen DHKEM.

## DH-AKEM-Hybrid (mode_auth_psk with PQ-KEM PSK) {#sec-hybrid}

The following terms are used in this section:

- **PQ-KEM**: a post-quantum KEM, e.g., ML-KEM {{FIPS203}}.
- `PQKEM.Encap(pkR_pq)`: PQ-KEM encapsulation; returns `(pq_ss, enc_pq)`.
- `PQKEM.Decap(enc_pq, skR_pq)`: PQ-KEM decapsulation; returns `pq_ss`.
- `Nenc_pq`: the fixed ciphertext length of the chosen PQ-KEM, in bytes.

The sender encapsulates a PQ-KEM to the receiver's PQ public key
`pkR_pq` and uses the resulting shared secret as the HPKE PSK, with the
PQ ciphertext as the PSK identifier. The combined encapsulation is
`concat(enc_dh, enc_pq)`; `Nenc` bytes are parsed as `enc_dh` and the
remaining `Nenc_pq` bytes as `enc_pq`.

~~~
def DH-AKEM-Hybrid.SetupS(pkR, pkR_pq, skS, info):
  pq_ss, enc_pq = PQKEM.Encap(pkR_pq)
  enc_dh, ctx = SetupAuthPSKS(pkR, info, pq_ss, enc_pq, skS)
  return concat(enc_dh, enc_pq), ctx

def DH-AKEM-Hybrid.SetupR(enc, skR, skR_pq, pkS, info):
  enc_dh, enc_pq = enc[:Nenc], enc[Nenc:]
  pq_ss = PQKEM.Decap(enc_pq, skR_pq)
  return SetupAuthPSKR(enc_dh, skR, info, pq_ss, enc_pq, pkS)
~~~

Implementations should verify `len(enc) == Nenc + Nenc_pq` and reject
encapsulations of any other length. A fresh `(pq_ss, enc_pq)` pair
should be generated for each encapsulation; reuse of a prior `enc_pq`
is prohibited. The `suite_id` in the HPKE key schedule reflects only the
classical ciphersuite `(KEM_ID, KDF_ID, AEAD_ID)`; the PQ-KEM identity
should be conveyed via application-layer framing or the `info` parameter
when multiple PQ-KEM algorithms are supported.

**Hybrid confidentiality.** `KeyScheduleS`/`KeyScheduleR` delegate to
`CombineSecrets`, for which {{!I-D.ietf-hpke-hpke}} defines two
variants. In `CombineSecrets_TwoStage`, the combination is
`secret = LabeledExtract(dhkem_shared_secret, "secret", psk)`,
equivalent to `HKDF-Extract(salt = dhkem_shared_secret, IKM = pq_ss)`
{{RFC5869}}. In `CombineSecrets_OneStage`, `dhkem_shared_secret` and
`psk` are length-prefixed and concatenated before a single
`LabeledDerive` call. In both cases, `dhkem_shared_secret` and `pq_ss`
enter the combination as independent inputs, so `secret` is pseudorandom
if either the Gap-DH assumption or the PQ-KEM IND-CCA2 security holds.
Authentication remains entirely classical; a quantum adversary that
breaks DH can also forge sender authentication, so post-quantum sender
authentication would require an additional PQ signature.

**PSK freshness.** The ML-KEM shared secret `pq_ss` satisfies the
entropy requirement in {{Section 9.7 of !I-D.ietf-hpke-hpke}} (32 bytes
of uniform randomness). The prohibition on `enc_pq` reuse above ensures
a fresh PSK per session.

# DH-AKEM Ciphersuites (Informative) {#sec-suites}

This section is informative. The ciphersuites below are suggested for
DH-AKEM usage profiles; they are not registered by this document.
`KEM_ID`, `KDF_ID`, and `AEAD_ID` are drawn from the registries in
{{I-D.ietf-hpke-hpke}}; `AEAD_ID` is selected by the application.

| Ciphersuite                            | KEM_ID | KDF_ID | PQKEM       | Nenc | Nenc_pq |
| -------------------------------------- | ------ | ------ | ----------- | ---- | ------- |
| DH-AKEM-X25519-SHA256                  | 0x0020 | 0x0001 | —           | 32   | —       |
| DH-AKEM-P256-SHA256                    | 0x0010 | 0x0001 | —           | 65   | —       |
| DH-AKEM-X448-SHA512                    | 0x0021 | 0x0003 | —           | 56   | —       |
| DH-AKEM-Hybrid-X25519-SHA256-MLKEM768  | 0x0020 | 0x0001 | ML-KEM-768  | 32   | 1088    |
| DH-AKEM-Hybrid-X25519-SHA256-MLKEM1024 | 0x0020 | 0x0001 | ML-KEM-1024 | 32   | 1568    |
| DH-AKEM-Hybrid-P256-SHA256-MLKEM768    | 0x0010 | 0x0001 | ML-KEM-768  | 65   | 1088    |

ML-KEM parameters are from {{FIPS203}}. DH-AKEM-Hybrid-X25519-SHA256-MLKEM768
is the suggested default hybrid ciphersuite, yielding a combined
encapsulation of 1120 bytes.

# Security Considerations {#sec-security}

**Implicit authentication and non-repudiation.** A receiver that
successfully derives `ss` may conclude the encapsulation was performed by
a holder of `skS`, since only such a party can compute `DH(skS, pkR)`.
No explicit signature or MAC is produced; a party holding `skR` can
simulate any sender by computing `DH(skR, pkS)` directly. Applications
requiring non-repudiation MUST add an explicit signature scheme.

**Key Compromise Impersonation (KCI).** Compromise of the receiver's key
`skR` enables an adversary to impersonate any sender to that receiver.
Applications requiring KCI resistance MUST add explicit sender
authentication.

**Binding.** The HPKE key schedule binds `(enc, pkR, pkS)` through
`kem_context`, the `mode` field (preventing cross-mode confusion), `info`
(application context), and `psk`/`psk_id` (in `mode_auth_psk`).
Applications SHOULD populate `info` with session-specific context.

**Forward secrecy.** Compromise of `skS` does not reveal past shared
secrets because the ephemeral key `skE` is independently necessary.
Compromise of `skR` enables decapsulation of all past sessions targeting
`pkR`; applications requiring receiver-key forward secrecy MUST use a
higher-level ratchet or key-update mechanism.

The formal security of the DHKEM authenticated modes under the Gap-DH
assumption is established in {{Alwen2021}}.

# IANA Considerations {#sec-iana}

This document requests no IANA actions; all identifiers are drawn from
registries defined in {{I-D.ietf-hpke-hpke}}.

--- back

# Acknowledgments
{:numbered="false"}

*TK*
