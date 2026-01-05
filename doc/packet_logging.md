# QUIC Packet Logging Format

`PRINT_MODE=packet` enables a structured logger inside OpenSSL’s QUIC demo
client/server. Both endpoints emit the same format, which makes it possible to
merge the logs chronologically and inspect amplification behaviour, handshake
phases, and per-frame payloads. This document describes that format and the
meaning of each field.

## 1. Line template

```
[<timestamp_ms> ms] [<ROLE> <DIR>] [DATAGRAM-SIZE : <bytes>B] [DELTA-CREDIT : <±bytes>B] \
PACKET <packet_number> : <Initial|Handshake|0RTT|1RTT> { <FRAME_SPEC> | ... }  \
[CREDIT-BEFORE : <value_or_->] [AMPLIFICATION-FACTOR : <value>] [CREDIT AFTER : <value_or_->]
```

* **Timestamp** – the logger keeps a single monotonic clock for both client and
  server. To keep the line width manageable, only the last five digits of the
  integer part are displayed (`90231.12345678 ms`, `031.00000000 ms`, …) while
  the fractional precision (eight decimals) is preserved.
* **`[ROLE DIR]`** – reports which endpoint produced the log (`CLIENT` or
  `SERVER`) and whether the datagram was sent or received from the point of
  view of that endpoint (`SENT` / `RECEIVED`).
* **`DATAGRAM-SIZE`** – size, in bytes, of the QUIC datagram observed.
* **`DELTA-CREDIT`** – only present on server lines. A positive value means the
  server gained anti-amplification credit (it received bytes); a negative value
  means the server consumed credit while sending.
* **`PACKET <n> : <phase>`** – QUIC packet number and the encryption level
  (`Initial`, `Handshake`, `0RTT`, or `1RTT`).
* **`{ … }`** – list of frame specifications in the order they appear on the
  wire. Frames are separated by `" | "`. The notation for each frame is
  documented in Section 2.
* **Credit/amplification footer** – different for server and client:

  * Server: `[CREDIT-BEFORE : …] [AMPLIFICATION-FACTOR : 3x|UNLIMITED|-]
    [CREDIT AFTER : …]`
  * Client: `[CREDIT : UNLIMITED|UNKNOWN] [AMPLIFICATION-FACTOR :
    VALIDATED|UNKNOWN]`

## 2. Credit semantics

### 2.1 Server

The server enforces QUIC’s anti-amplification rule until the client address is
validated. Credit is tracked in bytes.

* **`[DELTA-CREDIT : …]`** – change applied by this datagram (positive on
  receive, negative on send). Omitted on client lines.
* **`[CREDIT-BEFORE : …]` / `[CREDIT AFTER : …]`** – credit window before/after
  applying the datagram. Values are expressed as `<bytes>B` or `UNLIMITED`.
* **`[AMPLIFICATION-FACTOR : …]`** – `3x` when the server is still limited,
  `UNLIMITED` when the address is validated, `-` when the concept does not
  apply (for example, after shutdown).

### 2.2 Client

The client does not enforce anti-amplification. Instead we expose the state of
the transmit packetiser:

* **`[CREDIT : UNLIMITED|UNKNOWN]`** – `UNLIMITED` when the client’s
  `unvalidated_credit` has been set to `SIZE_MAX`, otherwise `UNKNOWN`.
* **`[AMPLIFICATION-FACTOR : VALIDATED|UNKNOWN]`** – mirrors whether the QUIC
  stack considers the peer validated (`VALIDATED`) or still tentative
  (`UNKNOWN`).

## 3. Frame specifications

Every frame uses the pattern `NAME--(KEY1=<value> , KEY2=<value> , ... , SIZE=<bytes>B)`.
The most common frames are listed below.

### 3.1 CRYPTO

```
CRYPTO--( { <HandshakeFragment> | ... } , SIZE=<frame_size>B )
```

* `<HandshakeFragment>` may be `ClientHello`, `ServerHello`, `EncryptedExtensions`,
  `Certificate`, `CertificateVerify`, `Finished`, `NewSessionTicket`,
  `CertificateRequest`, `KeyUpdate`, or `MessageHash`.
* Multiple fragments appear when the TLS record aggregates several handshake
  messages.
* The logger annotates specific fragments when their metadata is known:
  * `ClientHello(KeyShare=mlkem512(800B) , Cipher[0]=TLS_AES_256_GCM_SHA384)`
  * `ServerHello(KeyShare=mlkem512(768B) , Cipher=TLS_AES_256_GCM_SHA384)`
  * `Certificate(LeafSig=p521_sphincssha2256ssimple , Leaf=30323B)`
  * `CertificateVerify(Algorithm=p521_sphincssha2256ssimple , Signature=29934B)`
* Large TLS messages are often split across several datagrams. Intermediate
  fragments still show the handshake name without annotations; the final
  fragment adds the metadata once the full message has been reassembled.

### 3.2 ACK

```
ACK--(RANGE=[<start-end>[,<start-end>...]] , SIZE=<frame_size>B)
```

The range list is compact (e.g. `RANGE=[0-2,5]`).

### 3.3 PADDING

```
PADDING--(SIZE=<frame_size>B)
```

### 3.4 STREAM

```
STREAM--(ID=<stream_id> , SIZE=<frame_size>B)
```

### 3.5 NEW_TOKEN

```
NEW_TOKEN--(SIZE=<frame_size>B)
```

### 3.6 NEW_CONNECTION_ID

```
NEW_CONNECTION_ID--(SEQ=<sequence> , SIZE=<frame_size>B)
```

### 3.7 CONNECTION_CLOSE

```
CONNECTION_CLOSE--(ERROR=<error_code> , SIZE=<frame_size>B)
```

### 3.8 Other frames

The logger uses the same `NAME--( … )` notation for
`PATH_CHALLENGE`, `PATH_RESPONSE`, `RETIRE_CONNECTION_ID`, `MAX_DATA`,
`MAX_STREAM_DATA`, `MAX_STREAMS_BIDI`, `MAX_STREAMS_UNI`, `DATA_BLOCKED`,
`STREAM_DATA_BLOCKED`, `STREAMS_BLOCKED_BIDI`, `STREAMS_BLOCKED_UNI`, and
`HANDSHAKE_DONE`.

## 4. Examples

### 4.1 Client sends the Initial datagram

```
[90382.58520508 ms] [CLIENT SENT] [DATAGRAM-SIZE : 1200B]
PACKET 0 : Initial { CRYPTO--( { ClientHello(KeyShare=mlkem512(800B) , Cipher[0]=TLS_AES_256_GCM_SHA384) } , SIZE=1096B) | PADDING--(SIZE=66B) }
 [CREDIT : UNKNOWN] [AMPLIFICATION-FACTOR : UNKNOWN]
```

### 4.2 Server receives the same packet (credit increases)

```
[90382.99707031 ms] [SERVER RECEIVED] [DATAGRAM-SIZE : 1200B] [DELTA-CREDIT : +3600B]
PACKET 0 : Initial { CRYPTO--( { ClientHello } , SIZE=1096B) | PADDING--(SIZE=66B) }
 [CREDIT-BEFORE : 0B] [AMPLIFICATION-FACTOR : 3x] [CREDIT AFTER : 3600B]
```

### 4.3 Server sends `ServerHello` + ACK while still limited

```
[90383.11401367 ms] [SERVER SENT] [DATAGRAM-SIZE : 873B] [DELTA-CREDIT : -835B]
PACKET 0 : Initial { ACK--(RANGE=[0-0] , SIZE=5B) | CRYPTO--( { ServerHello(KeyShare=mlkem512(768B) , Cipher=TLS_AES_256_GCM_SHA384) } , SIZE=830B) }
 [CREDIT-BEFORE : 3600B] [AMPLIFICATION-FACTOR : 3x] [CREDIT AFTER : 2765B]
```

### 4.4 Server sends handshake flight after validation

```
[90384.22192383 ms] [SERVER SENT] [DATAGRAM-SIZE : 1200B]
PACKET 4 : Handshake { CRYPTO--( { Certificate(LeafSig=id-ml-dsa-44 , Leaf=3931B) } , SIZE=1163B) }
 [CREDIT-BEFORE : UNLIMITED] [AMPLIFICATION-FACTOR : UNLIMITED] [CREDIT AFTER : UNLIMITED]
```

### 4.5 CertificateVerify + Finished in the same datagram

```
[90384.32788086 ms] [SERVER SENT] [DATAGRAM-SIZE : 839B]
PACKET 6 : Handshake { CRYPTO--( { CertificateVerify(Algorithm=p521_sphincssha2256ssimple , Signature=29934B) | Finished } , SIZE=802B) }
 [CREDIT-BEFORE : UNLIMITED] [AMPLIFICATION-FACTOR : UNLIMITED] [CREDIT AFTER : UNLIMITED]
```

These examples are identical on both endpoints except for the role/direction
and the credit annotations.

## 5. Internal timing lines

When `PRINT_MODE=packet` is active the QUIC stack also emits lightweight
“internal” lines that summarise the major handshake phases. They share the same
timestamp format but use the header `[ROLE INTERNAL] [LABEL]`. Values are
expressed in milliseconds and are derived from the instrumentation inside
OpenSSL’s TLS/QUIC glue.

### 5.1 Client logs

* **`[CLIENT HELLO BUILD] clientKeyshareGeneration | clientHelloBuild`** –
  measures the key-share/KEM generation and the total time spent assembling the
  ClientHello payload before the Initial datagram is sent.
* **`[CERTIFICATE PROCESSED] clientCertificateProcess`** – emitted as soon as
  the client finishes validating the server’s Certificate message (after the
  full TLS message has been reassembled from CRYPTO frames).
* **`[CERTIFICATE VERIFY CHECK] clientCertVerifyCheck`** – records how long the
  client spent verifying the server’s CertificateVerify signature immediately
  after the message completed.
* **`[SERVER HELLO PROCESSED] clientHelloRoundTrip | clientKeyExchangeLatency`**
  – emitted as soon as the client finishes processing `ServerHello`. The first
  value matches the client‑perceived RTT between sending the ClientHello and
  parsing the ServerHello. The second value measures the latency of the
  key-exchange/decapsulation step executed on the client.
* **`[HANDSHAKE DONE] handshakeLatency`** – emits the same value presented by
  `Handshake-RTT: <value> ms`, showing the total client-perceived TLS handshake
  duration measured from `ClientHello` transmission until `Finished`.

### 5.2 Server logs

* **`[CLIENT HELLO PROCESSED] clientHelloProcess | serverKeyExchangeLatency`**
  – fired immediately after the server has parsed the ClientHello and finished
  the server-side key-share/KEM computation needed for ServerHello.
* **`[SERVER HELLO BUILD] serverHelloPreparation`** – measures how long it took
  to assemble the ServerHello payload once ClientHello processing completed.
* **`[HANDSHAKE BUILD] serverHandshakePreparation`** – captures the aggregation
  of EncryptedExtensions/Certificate/CertificateVerify/Finished into CRYPTO
  frames after the ServerHello is ready.
* **`[CERTIFICATE BUILD] serverCertificateBuild`** – isolates the time spent
  assembling the Certificate message before it is inserted into CRYPTO frames.
* **`[CERTIFICATE VERIFY SIGN] serverCertVerifySign`** – isolates the signing
  latency for the CertificateVerify message as soon as the signature operation
  finishes.
* **`[CLIENT VALIDATED] clientValidationDelay | serverCreditState=UNLIMITED`**
  – indicates when the server has received the first handshake-protected packet
  from the client (i.e., the anti‑amplification limit is lifted). The metric
  reports the time elapsed since the ClientHello was processed.
* **`[HANDSHAKE DONE]`** – a marker that the server completed its side of the
  TLS handshake (no extra fields).

These internal lines are only emitted in `PRINT_MODE=packet` and are intended to
help correlate packet-level behaviour with TLS phase durations.
