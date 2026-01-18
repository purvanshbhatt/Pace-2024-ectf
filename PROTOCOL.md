# eCTF Secure Channel Protocol

## Overview
This protocol defines the authenticated and encrypted AP↔Component messages used for LIST/BOOT/ATTEST/REPLACE flows. All messages use AEAD (AES-GCM) with a per-session key `Ks` and a monotonic counter.

## Frame Format
All multi-byte fields are big-endian.

```
Header:
  magic        uint16  (0xECF1)
  version      uint8   (1)
  msg_type     uint8
  component_id uint32
  counter      uint32  (monotonic per direction)
  payload_len  uint16
Payload: payload_len bytes
Tag: 16 bytes (AES-GCM tag)
```

**Validation rules**
- Reject bad magic/version.
- Reject unknown `msg_type`.
- Reject `payload_len` that exceeds max buffer.
- Reject `counter` rollback/replay (`counter` must be strictly increasing per direction).
- Reject bad AEAD tag.

## Message Types
| Type | Code | Direction | Payload |
|------|------|-----------|---------|
| HELLO | 0x01 | AP→Comp | `nonceA` (16 bytes) |
| HELLO_RESP | 0x02 | Comp→AP | `nonceC` (16 bytes) |
| BOOT_REQ | 0x10 | AP→Comp | empty |
| BOOT_RESP | 0x11 | Comp→AP | boot message bytes |
| ATTEST_REQ | 0x20 | AP→Comp | empty |
| ATTEST_RESP | 0x21 | Comp→AP | attestation string |

## Handshake + Session Key
Each component is provisioned with a long-term secret `Kc` derived in deployment.

Handshake:
1. AP → Comp: `HELLO(nonceA)` authenticated with `Kc`.
2. Comp → AP: `HELLO_RESP(nonceC)` authenticated with `Kc`.

Session key derivation:
```
Ks = HKDF-SHA256(
  ikm = Kc,
  salt = deployment_id,
  info = nonceA || nonceC || component_id || deployment_id,
  len = 16
)
```

## AEAD Nonce
12-byte nonce:
```
nonce = counter(4) || component_id(4) || direction(1) || 0x000000(3)
```
Direction byte is 0xA5 (AP→Comp) or 0x5A (Comp→AP).

## Error Handling
Messages failing validation are ignored. Host-visible failures are surfaced by AP as `%error` responses.
