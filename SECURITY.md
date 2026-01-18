# Security Rationale

## Threat Model
- Counterfeit components attempting to impersonate provisioned IDs.
- Replay of old AP↔Component messages.
- Sniffing or tampering of I2C traffic.
- Offline brute force against PIN/TOKEN.

## Controls → Goals Mapping

### Authenticity
- **Per-component long-term key `Kc`** (derived from deployment secret + component_id) authenticates components in the HELLO/HELLO_RESP exchange.
- **AEAD tags (AES-GCM)** authenticate every control message after session establishment.

### Integrity
- **AEAD** protects message integrity for BOOT/ATTEST commands and responses.
- **Monotonic counters** enforce freshness and block replay/rollback.

### Confidentiality
- **AES-GCM encryption** protects payload data on the wire (boot text, attestation data, control messages).
- **HKDF-derived session key `Ks`** isolates sessions per component and per boot handshake.

### Authorization / Privilege Gating
- **PIN/TOKEN are never stored in plaintext**; only salted SHA-256 hashes are stored.
- **Constant-time comparison** avoids timing leakage during PIN/TOKEN verification.
- **Rate-limited failures** add a time cost to repeated guesses without permanent lockout.

## Abuse Tests (Host-side)
- Replayed counters should be rejected.
- Invalid component_id should fail handshake.
- Wrong PIN/TOKEN should fail and backoff.
- Malformed length should be dropped safely.
- Attestation should be gated by valid PIN and secure session.
