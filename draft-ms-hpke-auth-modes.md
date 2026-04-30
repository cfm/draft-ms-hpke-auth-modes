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
  - authenticated KEM
  - DHKEM
  - HPKE
  - KEM combiner
venue:
#  group: HPKE
#  type: Working Group
#  mail: hpke@ietf.org
  github: "cfm/draft-ms-hpke-auth-modes"

author:
  - fullname: Cory Francis Myers
    role: editor
    organization: Freedom of the Press Foundation
    email: cfm@acm.org
  - fullname: Rowen Shane
    role: editor
    organization: Freedom of the Press Foundation
    email: ro@freedom.press
  - fullname: Giulio Berra
    role: editor
    organization: Freedom of the Press Foundation
    email: giulio@freedom.press


normative:
  I-D.ietf-hpke-hpke:

informative:
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
  Alwen2023:
    title: "The Pre-Shared Key Modes of HPKE"
    author:
      - name: Joël Alwen
      - name: Jonas Janneck
      - name: Eike Kiltz
      - name: Benjamin Lipp
    date: 2023
    rc: "Advances in Cryptology -- ASIACRYPT 2023"
    target: https://eprint.iacr.org/2023/1480
  I-D.draft-connolly-cfrg-xwing-kem-10:
  PQCodePkgs:
    title: "PQ Code Package Repositories (accessed 2026-04-30)"
    author:
      org: "Post Quantum Cryptography Alliance"
    date: 2026
    target: https://github.com/orgs/pq-code-package/repositories
  Wireguard2020:
    title: "WireGuard: Next Generation Kernel Network Tunnel"
    author:
      - name: Jason A. Donenfeld
    date: 2020
    target: https://www.wireguard.com/papers/wireguard.pdf

--- abstract

The standards-track {{!I-D.ietf-hpke-hpke}} supersedes the informational
{{?RFC9180}}, omitting its authenticated modes `mode_auth` and `mode_auth_psk`.
This document restores `mode_auth_psk` mode as a strict extension, and illustrates
how the restored mode can be used with a post-quantum shared secret as the PSK
by application developers seeking to achieve hybrid PQ/T confidentiality while
transitioning to quantum-safe encryption, without deprecating the implicit
authentication properties of DHAKEM on which many applications still rely.

This extension requires only the
addition of `AuthEncap()`/`AuthDecap()` to the DHKEM, the definition of four
setup functions, and a change in `VerifyPSKInputs()`.  The extension does not
alter the externally observable behavior of the existing HPKE modes standardized
in {{!I-D.ietf-hpke-hpke}}.
Although `AuthEncap()`/`AuthDecap()` reintroduce the functionality of `mode_auth`,
the mode itself is not restored due to its inability to provide quantum safety.

The transitional nature of the AuthPSK construction and its security properties
are discussed.
Finally, the document illustrates how the restored mode can be used to provide
ready-made KEM combiner-like functionality ({{!I-D.ounsworth-cfrg-kem-combiners}})
without requiring downstream API users to manage their own encryption context.
The use of this construction as a transitional step towards quantum readiness
motivates this extension.

--- middle

# Introduction

{{!I-D.ietf-hpke-hpke}} is the standards-track successor to the informational
{{?RFC9180}} and omits the authenticated modes `mode_auth` and `mode_auth_psk`
to simplify the standard.
However, some applications make use of the type of implicit sender authentication
those modes provide.

The normative portion of this document is small.  It restores
`mode_auth_psk` as a strict extension to {{!I-D.ietf-hpke-hpke}}.
This requires `AuthEncap()`/`AuthDecap()` from the DHKEM construction in
{{?RFC9180}}, and a modified `VerifyPSKInputs()`. The externally observable
behavior of existing HPKE modes is unchanged.
`AuthEncap()` computes a static-static DH value `DH(skS, pkR)` alongside the
ephemeral-static value and mixes both into the key derivation, binding the
output to the sender's key pair.

Although the functionality of `mode_auth` is re-introduced, the mode identifer
itself, which relies solely on DHKEM, is not restored due to its inability to
provide quantum-safe encryption. Instead, it is instead treated as a building
block to `mode_auth_psk`, as seen in {{sec-dhakem}}.

{{sec-authencap}} describes how the restored
mode can be used to achieve hybrid PQ/T confidentiality as
defined in {{Section 5 of ?RFC9794}} during the transition to quantum-safe encryption.
{{sec-motivation}} discusses the transitional nature of this construction and reviews
the guidance available to application developers looking to begin the transition to
quantum-safe encryption with existing libraries and APIs.

To motivate the extension, {{sec-combiner}} discusses how the extension can be used
as a type of black-box KEM combiner ({{!I-D.ounsworth-cfrg-kem-combiners}}), similar to
the construction proposed in {{Alwen2023}}, to allow application developers to begin
the transition to quantum-safe encryption via usable libraries and APIs.

# Conventions and Definitions
{::boilerplate bcp14-tagged}

Terms from {{I-D.ietf-hpke-hpke}} are used without redefinition; particular reference is
made to the **DHKEM** construction {{Section 4.1 of ?RFC9180}}.
The following additional term is used herein:

- **AKEM:** a KEM whose encapsulation additionally takes the sender's static
  private key and implicitly binds the shared secret to it.

# Authenticated Pre-Shared Key Mode Extension to {{I-D.ietf-hpke-hpke}} {#sec-ext}

This section specifies the additions to {{!I-D.ietf-hpke-hpke}} required to
restore `mode_auth_psk`. These extensions are defined so that
the externally observable behavior of the existing HPKE modes is unchanged,
although this document modifies the `VerifyPSKInputs()` procedure in
{{I-D.ietf-hpke-hpke}}.

## Mode Identifiers

The reserved entry for value `0x03` in Table 1 of
{{!I-D.ietf-hpke-hpke}} is replaced with the following mode identifier, as
originally specified in Table 1 of {{?RFC9180}}:

~~~
mode_auth_psk = 0x03
~~~

The value `0x02` remains reserved.

## Exclusion of 0x02 `mode_auth` from Mode Identifiers

Although restoring  the `AuthEncap()` and `AuthDecap()` functions would also
allow for restoring `mode_auth`, this mode cannot offer quantum-safe encryption,
and its identifier is therefore not reintroduced.

## DHKEM Extension: `AuthEncap()` and `AuthDecap()` {#sec-authencap}

The following two functions are added to the DHKEM, extending it to an AKEM
(DHAKEM).
They are reproduced verbatim from {{Section 4.1 of ?RFC9180}}. All helper
functions (`GenerateKeyPair`, `DH`, `SerializePublicKey`,
`DeserializePublicKey`, `ExtractAndExpand`) are as defined in
{{!I-D.ietf-hpke-hpke}}.

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

Note that the `AuthEncap()` and `AuthDecap()` functions are vulnerable to
key-compromise impersonation (KCI): the assurance that the shared secret was
generated by the holder of the private key `skS` does not hold if the recipient
private key `skR` is compromised. See {{sec-security}} for further discussion;
see {{sec-setup}} for integration of a pre-shared key.

## `VerifyPSKInputs`

The `VerifyPSKInputs()` function defined in {{Section 5.1 of ?RFC9180}} and
{{!I-D.ietf-hpke-hpke}} is extended to handle the two new modes. The updated
function replaces the original:

~~~
def VerifyPSKInputs(mode, psk, psk_id):
  got_psk = (psk != default_psk)
  got_psk_id = (psk_id != default_psk_id)
  if got_psk != got_psk_id:
    raise Exception("Inconsistent PSK inputs")

  if got_psk and mode in [mode_base]:
    raise Exception("PSK input provided when not needed")
  if (not got_psk) and mode in [mode_psk, mode_auth_psk]:
    raise Exception("Missing required PSK input")
~~~

The only change from the original is that `mode_psk` is replaced by
`[mode_psk, mode_auth_psk]` in the final guard.

## Setup Functions {#sec-setup}

The following four setup functions are reproduced verbatim from {{Sections 5.1.3
and 5.1.4 of ?RFC9180}}.  `KeyScheduleS()`/`KeyScheduleR()` and
`AuthEncap()`/`AuthDecap()` are as defined in {{!I-D.ietf-hpke-hpke}} and
{{sec-authencap}} respectively.

~~~
def SetupAuthPSKS(pkR, info, psk, psk_id, skS):
  shared_secret, enc = AuthEncap(pkR, skS)
  return enc, KeyScheduleS(mode_auth_psk, shared_secret, info,
                           psk, psk_id)

def SetupAuthPSKR(enc, skR, info, psk, psk_id, pkS):
  shared_secret = AuthDecap(enc, skR, pkS)
  return KeyScheduleR(mode_auth_psk, shared_secret, info,
                      psk, psk_id)
~~~

## Input Validation and Error Handling

In addition to the validation requirements in {{Section 7.1.4 of
!I-D.ietf-hpke-hpke}}, the recipient MUST validate the sender's static public
key `pkS` before use in `AuthDecap()`, applying the same validation rules as for
other public key inputs. Validation failure MUST yield a `ValidationError`.

## DHAKEM with PSK {#sec-dhakem}

This section illustrates how the authenticated mode defined
in {{sec-ext}} can be used.  Any AEAD identifier from {{I-D.ietf-hpke-hpke}} may
be used; the resulting context supports `Seal()`, `Open()`, and `Export()`.
Key generation follows `GenerateKeyPair()` from {{I-D.ietf-hpke-hpke}}.

`mode_auth_psk` may be used via its setup function: the sender calls
`SetupAuthPSKS()` and the receiver calls `SetupAuthPSKR()`, with a pre-shared key
`psk` and a PSK identifier `psk_id`, as defined in {{sec-setup}}.
As in {{?RFC9180}}, both parties are assumped to have been provisioned with the
PSK value `psk` and another byte string `psk_id`.

This mode SHOULD be used with a quantum-safe PSK value as described below in
order to offer hybrid confidentiality properties.

### PQ/T Hybrid Construction {#sec-hybrid}

~~~
def HybridSetupS(pkR, skS, info, psk, psk_id):
  enc_dh, ctx = SetupAuthPSKS(pkR, info, psk, psk_id, skS)
  return enc_dh, ctx

def HybridSetupR(enc, skR, pkS, info, psk, psk):
  return SetupAuthPSKR(enc_dh, skR, info, psk, psk_id, pkS)
~~~

The `suite_id` in the HPKE key schedule reflects only the ciphersuite
`(KEM_ID, KDF_ID, AEAD_ID)`, where `KEM_ID` is a DHAKEM.
Generation and distribution of a quantum-safe PSK value is left to the
application.

**Hybrid confidentiality.** `KeyScheduleS()`/`KeyScheduleR()` delegate to
`CombineSecrets`, for which {{!I-D.ietf-hpke-hpke}} defines two variants. In
`CombineSecrets_TwoStage()`, the combination is `secret =
LabeledExtract(dhkem_shared_secret, "secret", psk)`, equivalent to
`HKDF-Extract(salt = dhkem_shared_secret, IKM = psk)` {{?RFC5869}}. In
`CombineSecrets_OneStage()`, `dhkem_shared_secret` and `psk` are length-prefixed
and concatenated before a single `LabeledDerive()` call. In both cases,
`dhkem_shared_secret` and `psk` enter the combination as independent inputs.
The intended design property is that `secret` remains pseudorandom as long as at
least one of the two inputs is---meaning an adversary would need to attack both
the classical DH-based component and the PQ-KEM to recover `secret`, as seen
in {{!I-D.ounsworth-cfrg-kem-combiners}} and subsequently,
{{?I-D.draft-connolly-cfrg-xwing-kem-10}}.

Whether
this property holds formally for a specific `CombineSecrets` variant depends on
that variant's security analysis, which is outside the scope of this document.

**Authentication.** This mode retains the implicit sender
authentication properties of DHAKEM described in {{?RFC9180}}.
A quantum adversary with access to the PSK can also forge authenticated messages.

**PSK freshness.** The PSK `psk` MUST satisfy the
entropy requirement in {{Section 9.5 of !I-D.ietf-hpke-hpke}} (32 bytes of
uniform randomness).

### AKEM/PQ KEM "Combiner" (Informative) {#sec-combiner}

Using `mode_auth_psk` with the shared secret from a PQ-KEM as the provided "psk"
value allows application developers to provide hybrid-transitional security properties
using ready-made libraries and APIs. Although not a true pre-shared key, the terminology
from similar work by {{Alwen2023}} ("pskAPKE") is retained.

The result is a KEM combiner-style construction {{!I-D.ounsworth-cfrg-kem-combiners}}
that provides hybrid PQ/T confidentiality and classical authentication, without requiring
developers to manage their own encryption context, a frequent source of developer error
and a motivating factor for the API design choices of {{?RFC9180}}.

In addition to the keypair specified in {{sec-setup}}, the receiver holds an additional
post-quantim keypair, (`skR_pq`, `pkR_pq`).
Prior to setting up an HPKE encryption context (either via `Setup` or via a single-shot
API), the sender encapsulates a PQ-KEM to the receiver's PQ public key `pkR_pq`, using
the resulting shared secret `ss_pq` as a "PSK", and a static identifier as the PSK
identifier.
The ciphertext encapsulation of `ss_pq`, `enc_pq`, is included in `info` to
bind it to the key schedule.

An example construction is provided below, with reference to the following terms:

- **PQ-KEM:** a post-quantum KEM, e.g., ML-KEM {{FIPS203}} or an
  algorithm from {{?I-D.ietf-hpke-pq}}.
- `PQKEM.Encap(pkR_pq)`: PQ-KEM encapsulation; returns `(enc_pq, ss_pq)`.
- `PQKEM.Decap(enc_pq, skR_pq)`: PQ-KEM decapsulation; returns `ss_pq`.
- `Nenc_pq`: the fixed ciphertext length of the chosen PQ-KEM, in bytes.

~~~
def HybridSetupS(pkR, pkR_pq, skS, info):
  enc_pq, ss_pq = PQKEM.Encap(pkR_pq)
  enc_dh, ctx = SetupAuthPSKS(pkR, concat(info, enc_pq), ss_pq, enc_pq, skS)
  return concat(enc_dh, enc_pq), ctx

def HybridSetupR(enc, skR, skR_pq, pkR_pq, pkS, info):
  enc_dh, enc_pq = enc[:Nenc], enc[Nenc:]
  ss_pq = PQKEM.Decap(enc_pq, skR_pq)
  return SetupAuthPSKR(enc_dh, skR, concat(info, enc_pq), ss_pq, enc_pq, pkS)
~~~

**Classical (implicit) sender authentication:** Only classical sender
authentication is provided; in contrast to {{sec-hybrid}}, the "psk" value
provides no sender authentication, as it is constructed rather than pre-shared.
This limitation is assessed in {{sec-motivation}}.

The `info` parameter will exceed 64 bytes. Implementors must ensure their choice of
algorithms and underlying implementation can support parameters of this length.

The shared secret `ss_pq` must satisfy the entropy requirement in
{{Section 9.5 of !I-D.ietf-hpke-hpke}}.

Implementations should verify `len(enc) == Nenc + Nenc_pq` and reject
encapsulations of any other length. A fresh `(ss_pq, enc_pq)` pair should be
generated for each encapsulation; reuse of a prior `enc_pq` is prohibited. The
`suite_id` in the HPKE key schedule reflects only the ciphersuite
`(AKEM_ID, KDF_ID, AEAD_ID)`; the PQ-KEM algorithm identity should be conveyed
via application-layer framing when multiple PQ-KEM algorithms are supported.

Note that {{Alwen2023}}
describes a related hybrid construction in which a PQ *AKEM* (rather than a
plain KEM) is used to generate the PSK, which would additionally provide
post-quantum sender authentication; that stronger construction is outside the
scope of this document.

## Motivation (Informative) {#sec-motivation}

Downstream application developers are in a bind: though they may be aware of advice to
implement quantum-safe encryption on an accelerated timeline, they may encounter rapidly-
evolving guidance on best practices, a lack of direct parity with classical constructions,
and a releative paucity of stable APIs suitable for non-cryptographers {{PQCodePkgs}}.

Non-cryptographers looking to offer classical/quantum-safe (hybrid) encryption in their
own applications can look to early-stage implementations of
{{?I-D.draft-connolly-cfrg-xwing-kem-10}}, or may refer to now-expired
{{!I-D.ounsworth-cfrg-kem-combiners}}, but will need to manage their own implementation.
Further, the guidance on post-quantum signature schemes is still under active development,
and if libraries are available, they come with strong caveats about changing APIs and general
maturity.

Although DH-based authentication is not future-forward, it remains in widespread use.
Further, although the property of hybrid encryption with classical authentication is not as
straightforward to communicate as an unauthenticated hybrid construct, protocols such as
Noise IK, as used in {{Wireguard2020}}, indicate their usage.
Simple APIs that allow application developers to deploy quantum-resistent encryption as
a transitional measure without deprecating the classical authentication properties of
their application provides a path towards quantum readiness.

# Security Considerations {#sec-security}

The sender-authentication and key-compromise impersonation (KCI) properties of
`mode_auth_psk` are as described in {{Sections 9.1 and 9.1.1 of
?RFC9180}}, which apply without change to the functions defined in {{sec-ext}}.
Security properties specific to the hybrid PQ/T construction are discussed
informatively in {{sec-hybrid}}.

The formal security of the DHKEM authenticated modes under the Gap-DH assumption
is established in {{Alwen2021}}. The security of `mode_auth_psk`---termed
`AuthPSK` in {{Alwen2023}}---is analyzed there as the `pskAPKE` scheme.

# IANA Considerations {#sec-iana}

This document requests no IANA actions; all identifiers are drawn from
registries defined in {{I-D.ietf-hpke-hpke}}.

--- back

# Acknowledgments
{:numbered="false"}

*TK*
