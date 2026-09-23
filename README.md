# FRE - Fast Rotating Encoding

**FRE** is a new way of encoding, it permits multiple processes (or devices) to have the same pseudo-random encoding patterns, and a way to rotate from the last encoding pattern.

It is fairly similar to hashing, but you do not have the idea that an input has its own output, because **FRE** uses seeds to generate an encoding over an input, where those seeds generates other seeds by themselves.

> [!NOTE]
>
> A seed generates seeds that all resolves to the same output, even though the generated seeds may be different

## What does "fast and secure encoding" means here ?

> [!NOTE]
>
> If you are not interested in the *how*, skip to [the functional spec](#the-functional-spec), if you are not interested in the *why*, skip to [the security model](#security-model).

Let me be clear on the three words, so we do not lie to ourselves:

- **fast**: it must take **at most 100ms on 1kB of data**. This is the only performance requirement, everything else about speed is a bonus, not a promise.
- **secure**: given an output, it should be as hard as possible to find the input, or the seed that produced it. **FRE is reversible, but  only not in practice**: recovering the input costs `min(2^entropy(input), 2^λ)` work, and for a 1kB input that is `2^8192`, i.e. forever. The word of reference is *cost*: you go forward cheaply, and backward only if you can burn the universe.
- **encoding**: not a hash, not a cipher, more of something in-between. It is deterministic given a seed, but the seed is **secret**, so the output is not predictable by an observer that does not hold the first seed.

> So is it a hash ?

No, and importantly: it is not an [encryption](https://en.wikipedia.org/wiki/Encryption) either. An encryption gives the key holder a **cheap** way back: **FRE doesn't**. Even keeping the seed, the only way to recover an input is brute-force enumeration of the input space, at cost `min(2^entropy(input), 2^λ)`. The seed only lets you *regenerate* and *verify* the same pattern, exactly like a keyed hash (**PRF**). Reversal is theoretically possible, and practically a joke.

> Why not just use HMAC then ?

Because HMAC alone does not rotate. **FRE** 's whole point is that the seed **evolves**: every "generation" (`gen`) of the seed produces a slightly different pattern, and the only things you need to follow every evolution are the **first** seed and the **rotation key** `K_r` exchanged between the machines. Rotation *ratchets* the seed and the rotation key forward together, so the keys that authorize later generations are useless for earlier ones. This is the "rotating" in the name.

> And why this fingerprint ?

The **encoding** must bind to something that is (a) constant, so every device agrees on it, and (b) secret, so an observer cannot reconstruct the patterns. That something is the **fingerprint**. The spec proposes a simple answer: the fingerprint is **derived from the initial seed and the rotation key** (`FPR = HMAC(S_0 ‖ K_r, tag)`). It costs nothing new to store, it is secret as long as both secrets are, and it is constant by construction, and because both secrets feed it, **neither one alone can reconstruct `FPR`**, so a leaked `S_0` stays silent. It should not be confused with the *rotation* trigger, which is a separate concern addressed by `K_r` below.

> And the rotation: how is it locked down ?

Advancing the chain takes a **rotation key** exchanged between the machines out of band (an authenticated key exchange, or any out-of-band channel). This is the crucial bit: intercepting a seed `S_g` is **not enough** to rotate because the attacker also needs the current rotation key `K_g`. Rotation is always caller-driven (see the functional spec), so a machine that was never part of the exchange simply cannot follow the chain. The rotation key **ratchets**: each generation derives a fresh `K_{g+1}` from `K_g`, so a leak of the current `(S_g, K_g)` exposes only *later* generations, never earlier ones. The exchanged root key `K_r` only seeds `K_0` (and `FPR`); machines SHOULD erase it once the chain is up, so a future root leak cannot resurrect old captured seeds.

---

## Goals & non-goals

**Goals:**

- a keyed encoding over arbitrary input that is **practically** one-way: reversal exists in theory, never costs less than `2^λ` work, and the seed provides no shortcut
- a self-rotating seed chain: `S_0` and the exchanged rotation key `K_r` give you `S_1`, `S_2`, … without further external input
- all devices sharing `S_0` produce **byte-identical** outputs
- portable: it runs on embedded, desktop and server with the same code
- at most 100ms for 1kB of data, on any realistic hardware, **while keeping** λ ≥ 128 (the speed/security balance)

**Non-goals:**

- **not** an encryption: there is no trapdoor, no secret that unlocks a *cheap* reversal
- unkeyed "hash of this file" mode
- **not** a speed record: 100ms/1kB is the ceiling, not a target, so we are far from it. See the [performance model](#performance-model)

---

## Formal requirements

The following are normative. "MUST" is a hard promise, "SHOULD" is a strong intent.

| # | Requirement | Priority |
| --- | --- | --- |
| R1 | Given `(input, S_g, g, ctx)` the output is a **deterministic** function of these only | MUST |
| R2 | Recovering `input` from `output` costs **≥ 2^λ** work; brute-force enumeration of the input space is the only method, even holding `S_0` and `FPR` | MUST |
| R3 | Recovering any `S_g` from `output` also costs ≥ 2^λ (keyed PRF) | MUST |
| R4 | Holding `S_0` **and** `K_r` allows computing every `S_{g'}` for `g' ≥ 0` | MUST |
| R5 | Holding `S_g` does **not** reveal `S_{g'}` for `g' < g` (forward secrecy of the chain) | MUST |
| R6 | Two distinct inputs must not collide under the same `(S_g, g)` except with negligible probability | MUST |
| R6′ | The balance the other way: the extra security must not eat the budget. Forward encoding of 1kB still takes **≤ 100ms** while reversal stays ≥ 2^λ | MUST |
| R7 | Encoding 1kB of data takes **≤ 100ms** | MUST |
| R8 | The specification has a portable reference implementation | SHOULD |
| R9 | `S_0` MUST come from a CSPRNG at ≥ `k` bits of entropy, never a password, a guessable constant, or any low-entropy secret. FRE does not protect weak seeds | MUST |
| R9′ | `K_r` MUST have ≥ `k` bits of entropy and be established by an authenticated exchange between the machines, never derived from `S_0` or guessable | MUST |
| R10 | Advancing the chain (rotation) requires the current rotation key `K_g`: holding `S_g` but not `K_g` reveals no `S_{g'}` for `g' > g`. Intercepting a seed is not enough to rotate | MUST |
| R11 | Rotation-gate forward secrecy: holding `(S_j, K_j)` reveals no `S_{g'}` **or** `K_{g'}` for `g' < j`. A compromise at some generation exposes only later ones, never earlier ones (the ratchet). Over each generation `K_{g+1} = HMAC(K_g, …)` is a one-way image of `K_g`, so a leaked rotation key (nor its preimages, which are not recoverable from it) can be neither rolled back nor used to resurrect seeds captured before it became current | MUST |
| R12 | `K_r` may be erased once the chain is up. Only `K_0`, the per-generation `K_g`, `FPR` and `g` are used after bootstrap, so erasing the root closes the "root leak resurrects every capture" window | SHOULD |

---

## Notation & parameters

| Symbol | Meaning | Default |
| --- | --- | --- |
| `k` | security level, size of every seed (`\|S_g\| = k`) | 256 bits |
| `λ` | min work to reverse an output, `min(2^entropy(input), 2^λ)` | 128 bits |
| `B` | input block size | 64 bytes |
| `S_0` | initial secret seed, fixed once | - |
| `S_g` | seed at generation `g` (from the rotation, or `S_0` at `g=0`) | - |
| `K_r` | root rotation key, exchanged out of band between the machines; seeds `K_0` and `FPR`, then SHOULD be erased | - |
| `K_g` | rotation key at generation `g` (`K_0 = K_r`); ratchets forward each generation | - |
| `g` | generation counter, starts at `0`, never decreases | - |
| `ctx` | purpose tag: a per-use string separating protocols from one another (e.g. `"nsc:relay"`, `"nsc:msg"`), MUST be ≤ 64 bytes | `""` |
| `FPR` | fingerprint: constant + secret, size `k` | derived from `S_0 ‖ K_r` |
| `le64(x)` | little-endian 64-bit encoding of an integer `x` | - |
| `‖` | byte concatenation | - |

All sizes are in bytes unless stated otherwise. The encoding is **big-endian-neutral**: every multi-byte integer that enters the primitive goes through `le64`.

**`ctx` is bounded (MUST ≤ 64 bytes).** The per-block HMAC key is `S_g ‖ le64(g) ‖ le64(i) ‖ ctx`, i.e. `48 + |ctx|` bytes, and the reference implementations hold it on a fixed stack frame. The bound keeps that frame portable (no VLAs, optional in C11 and removed in C23) and identical across ports: the C port returns `0` for `ctx_len > 64` (`FRE_CTX_MAX`), the Rust port panics (`CTX_MAX`). 64 bytes is far beyond any realistic purpose tag.

**`g` MUST NOT wrap.** It is a `u64`; calling `rotate` at `g = 2^64 − 1` would recur into already-used generations. Real deployments are ~584 billion years away from this, but it is a hard contract: never rotate past `u64::MAX`.

`K_r` is the same size as a seed (`k` bits of entropy, 32 bytes like `S_0`). It MUST come from an authenticated exchange between the machines, a secure key-exchange protocol, or a pre-shared secret delivered out of band,  and never be re-derived from `S_0` (that would defeat the whole point: an observer who learns `S_0` must still not be able to rotate). It seeds `K_0` and `FPR` at bootstrap; after that the machines only need the per-generation `K_g` and the stored `FPR`, so keeping the root around is optional (R12). A kept `K_r` is, by construction, a master key for the chain's rotation authority: **erase it once the chain is up**. Re-seeding the chain exchanges a fresh `S_0` and `K_r`.

---

## The functional spec

### 1. Fingerprint (`FPR`)

```
FPR = HMAC-SHA-256(S_0 ‖ K_r, "fre:v1:fingerprint")
```

The domain tag string `"fre:v1:fingerprint"` is a **literal constant**, hardcoded in the reference implementation and in every port. It exists so that `FPR` can never be confused with another value of the same shape.

> [!NOTE]
>
> `FPR` is fixed for a given `(S_0, K_r)`. It is the "constant and secret" identity of a chain: it never changes across generations, and it is only known to the holders of both `S_0` and `K_r`. Because it is keyed by both secrets, neither one alone can reconstruct it. A leaked `S_0` reveals no fingerprint and no output of any generation. It **does not** authorize rotation because that is the job of `K_r` below.

### 2. Seed chain (the rotation)

Rotation advances **two chains in lockstep**, the seed and the rotation key:

```
S_{g+1} = HMAC-SHA-256(S_g ‖ K_g, "fre:v1:rotate"  ‖ FPR ‖ le64(g))
K_{g+1} = HMAC-SHA-256(K_g,     "fre:v1:ratchet" ‖ FPR ‖ le64(g))
        K_0 = K_r
```

- both outputs follow from things you already have when holding `S_0` **and** `K_r`: the seed `S_g`, the current rotation key `K_g`, the constant `FPR`, and the counter `g`. Every device must call `rotate` exactly once per generation with the same `(S_g, K_g, FPR, g)` to stay in lockstep;
- **rotation is locked (R10)**: the seed's HMAC key is `S_g ‖ K_g` (64 bytes). Advancing the chain requires *both* secrets. An observer who intercepts `S_g` but does not hold `K_g` cannot compute `S_{g+1}`, precompute future patterns, or follow the chain. An eavesdropper who has `K_g` but never had a seed is equally stuck. This is the "exchange" of the spec: the two machines agree on `K_r` out of band, and then carry the seed chain forward together;
- **the rotation gate has forward secrecy too (R11)**: `K_{g+1}` is the HMAC output of `K_g`, so recovering `K_g` from `K_{g+1}` is the key-recovery problem, infeasible for SHA-256. A leak of the current pair `(S_j, K_j)` exposes only generations `≥ j`; it cannot resurrect a seed captured before `j` or ever roll a rotation key backwards. A leak of `K_r` alone is doubly useless, without a seed it authorizes nothing, and if the machines erased it at bootstrap there is nothing to leak (R12);
- the chain is exactly the "olive tree" of the intro: every seed generates children, and all children of a given seed resolve to the same future outputs;
- forward secrecy of the chain (R5) holds because `S_g` is part of the **key** of the HMAC that produces `S_{g+1}`: recovering `S_g` from `S_{g+1}` is the HMAC key-recovery problem, which is infeasible for SHA-256. Even holding `K_g` does not help because HMAC output reveals nothing about the key;
- neither `K_r` nor any `K_g` ever appears in an `S_g`, an output, or a tag; the caller carries `FPR` and the current `K_g` next to the chain, exactly like the seed. Keeping them together costs nothing and keeps rotation gated.

### 3. Encoding

Input is processed in blocks of `B` bytes. A `0x80` terminator byte is appended **after the last input byte**, followed by `0x00` fill up to the block boundary. The terminator is appended **even when `|input|` is an exact multiple of `B`**, so inputs differing only by trailing zero bytes can never alias each other, and an aligned input never collapses into its own prefix. The block count is therefore `⌊|input|/B⌋ + 1`.

```
FRE(input, S_g, FPR, g, ctx):

  blocks = len(input) // B + 1                 # always one terminator block
  out = ""
  for i in 0 .. blocks - 1:
      block = input[i*B .. (i+1)*B - 1]        # pad to B bytes: 0x80 then 0x00 fill
      d_i   = HMAC-SHA-256(S_g ‖ le64(g) ‖ le64(i) ‖ ctx, FPR ‖ block)
      out  += d_i

  return out          # length = (len(input) // B + 1) * 32 bytes
```

- **`ctx` is the domain separator**: mixing the purpose into every block keeps e.g. relay recognition (`"nsc:relay"`) and message encoding (`"nsc:msg"`) from ever producing the same pattern for the same content. An observer cannot cross-match protocols. Empty `ctx` is allowed, it just means "any purpose, don't expect isolation". `ctx` MUST be ≤ 64 bytes (see the notation section): the reference ports reject longer tags (`fre_encode` returns `0`, Rust panics).
- **variable size**: the output is *at most* `ceil(|input|/B) * 32` bytes. No fixed-size guarantee is made: a fixed-size mode is a possible evolution, not a requirement (we do not want to promise something before proving it is possible).
- **single block shortcut**: if `|input| < B`, the output is simply the 32-byte `d_0`. The only boundary case that is *not* a single block is `|input| = B` exactly, which needs one extra block for the terminator.
- **empty input** is valid: a single block of one `0x80` byte followed by `0x00` fill, i.e. a 32-byte output `HMAC-SHA-256(S_g ‖ le64(g) ‖ le64(0) ‖ ctx, FPR ‖ 0x80 ‖ 0x00×63)`.

> [!NOTE]
>
> Rotation is done by the **caller**: to move to generation `g+1`, call `rotate(S_g, K_g, FPR, g)` once then it returns `S_{g+1}` **and** `K_{g+1}` together, so the two chains stay in lockstep and keep the counter. `FRE` itself is a pure function of `(input, S_g, g, ctx)` (R1). There is no hidden mutable state, which is what makes it trivially portable and parallelizable.

---

## Security model

The baseline attacker never holds `S_0`; the cases where `S_0` itself leaks (and what survives it) are analyzed in the warning below.

**Claim 1: reversal cost (R2/R3).** The output is produced by `HMAC-SHA-256` keyed by `S_g`. Reversal of the *input* is brute-force enumeration of the input space, and reversal of the *seed* is the HMAC key-recovery / preimage problem. Both cost `≥ min(2^entropy(input), 2^λ)`. Under standard assumptions on SHA-256, there is no shortcut cheaper than that, and **no secret, `S_0` included, makes it cheaper**. Reversibility is then a fact of the maths, and its cost is the whole protection.

**The balance (R6′).** Forward is microseconds, backward is `2^λ`: this asymmetry *is* the "balance for speed and security" the spec promises. Raising `λ` costs you nothing forward, so the ceiling (R7) is never at risk from a security bump. See [the performance model](#performance-model).

**Claim 2:  keyed PRF (R3).** Outputs are computationally indistinguishable from random to an observer without `S_g`, even against chosen-input queries, because HMAC-SHA-256 is a standard secure PRF.

**Claim 3:  forward secrecy of the chain (R5).** Compromise of `S_{g+1}` does not help recover `S_g`. Compromise of seed `S_j` only exposes generations `≥ j`; generations `< j` remain safe.

**Claim 4:  collision resistance between generations (R6, plus `le64` counters).** Even identical blocks at different `g` or `i` are input to different HMAC messages (`g` and `i` are mixed into the key-side), so outputs across generations/positions differ with overwhelming probability.

**Claim 5:  rotation is locked (R10, R9′).** The chain advances only from `S_{g+1} = HMAC-SHA-256(S_g ‖ K_g, "fre:v1:rotate" ‖ FPR ‖ le64(g))`. An observer holding `S_g` but not `K_g` cannot compute `S_{g+1}`: the output is an HMAC keyed by a 64-byte secret they do not split. Intercepting a seed, a fingerprint, or a generation counter therefore yields nothing that can be rolled forward. `K_g` alone is equally inert without a seed. Rotation is only possible for a machine that completed the authenticated exchange that produced `K_r`.

**Claim 6:  forward secrecy of the rotation gate (R11).** Each rotation derives `K_{g+1}` from `K_g` by HMAC, so the gate has the same one-way property as the seed chain: holding `(S_j, K_j)` exposes only `g ≥ j`, never earlier generations or older rotation keys. A leaked per-generation `K_g` cannot be rolled back (no `K_{g'}`, `g' < g` is recoverable from it) and cannot re-activate a seed captured before it became current. If the machines erased the root `K_r` at bootstrap (R12), no single compromise: seed, rotation key, or root can not undo the chain's past.

**What the ratchet protects, honestly.** `K_g` blocks a *partial-disclosure* channel: a seed intercepted without its current rotation key cannot be rolled forward, and a leaked rotation key can neither go backwards nor resurrect captured seeds from before it was current (R11). It is **not** a defense against *full device compromise*: a machine holding `(S_g, K_g)` deliberately kept together is, functionally, the chain, whoever takes the box takes both, exactly as with a session key. The ratchet's real value is time-decay: it keeps a single historical loss (an old seed capture, an old key spill, a kept `K_r`) from compounding into permanent chain knowledge. Protect the device that holds the pair as carefully as you protect `S_0`.

> [!WARNING]
>
> **Low-entropy inputs are trivially reversible.** The reversal cost is `min(2^entropy(input), 2^λ)`, not `2^λ`. A 4-byte PIN encoded by FRE reverses in ~`2^32` attempts for anyone holding `FPR` (and `S_g`); enumeration is only possible when you can recompute the output to test a candidate. For a *device-hopping* attacker that does mean "any full compromise", but a seed leak *alone* now yields nothing: without `K_r` there is no `FPR`. **FRE does not hide low-entropy payloads.** This is a *chosen* property, not a pending fix: FRE is fast *because* it refuses to pad its forward cost, so protection of small or guessable inputs is on the caller. You should pad or diversify them before encoding, or accept the enumeration.
>
> **The secrecy budget is two-directional and time-decaying.** Compromise of `S_j` **and** `K_j` exposes every **future** generation `≥ j`, and only generations `< j` stay safe (R5, R11). Compromise of `S_j` alone exposes nothing new: without `K_j` there is no rotation (R10). Because both chains ratchet, yesterday's leak does not compound into today's: a captured seed is only as good as the rotation key that was current when it was captured. Do not rotate less carefully than you keep `S_0` and `K_j`.
>
> **`S_0` and `K_r` together are the whole lock.** If `S_0` leaks but `K_r` does not, the chain cannot be followed and because `FPR` is keyed by both secrets, it means **no fingerprint and no output of any generation is reproducible**, not even generation `0`. If `K_r` also leaks, every past and future output can at least be **identified**. Both MUST come from a CSPRNG with ≥ `k` bits of entropy (R9, R9′), never a password, and stay out of any non-secret store. `K_r` is established out of band between the machines (R9′), SHOULD be erased after bootstrap (R12), and is re-established whenever the chain is re-seeded.
>
> These claims inherit the security of SHA-256.

> [!NOTE]
>
> **Length is not hidden.** Output length equals `ceil(|input|/B) * 32`. FRE reveals how long the input was. For NSC-style anonymity, protocol layers that must not leak size should pad inputs to a common chunk size *before* encoding.
>
> **Equality is not hidden either.** FRE is deterministic (R1): the same input under the same `(S_g, FPR, g, ctx)` produces the **byte-identical output on every device at the same generation**, forever. An observer holding `FPR` who sees the same pattern twice with the same relay, same generation, same `ctx` will knows the two payloads are equal. This is a *feature* for relay recognition (the whole point of the fingerprint), but a traffic-analysis vector for anonymity: layers that must not let equal payloads be linkable should randomize or diversify input (wrap each message in fresh entropy) *before* encoding, per `ctx`. FRE authenticates equality, it does not hide it.

---

## Performance model

`HMAC-SHA-256` throughput on commodity hardware is on the order of hundreds of MB/s, i.e. roughly **10–50µs for 1kB** on a laptop and well under **1ms** on a modern embedded MCU. The requirement says `1kB = MAX(100ms)`; we are operating ~3 to 5 orders of magnitude under the ceiling, leaving headroom for memory-tight or interpreter-based ports.

| Environment | estimated per 1kB (measured where available) | vs 100ms ceiling |
| --- | --- | --- |
| laptop / server:  Rust reference impl (release, x86-64) | **~7µs (measured)** | ~0.007% |
| laptop / server: C port (`-O2`, x86-64) | **~38µs (measured)** | ~0.04% |
| embedded MCU (Cortex-M class) | ~0.1 – 1ms (est.) | ~1% |
| interpreted (e.g. Python reference impl) | ~1 – 5ms (est.) | ~5% |

Laptop rows are measured (`examples/vectors.rs` / `c/tests`); embedded and interpreted rows remain estimates to be validated by their own ports. Output may be emitted block-by-block; nothing requires buffering the whole encoding in memory.

**Failure bound**: a port MUST reject target >100ms for 1kB. If a platform cannot meet it, it does not implement FRE, it implements a slow approximation.

**Then how much is λ.** Reversal security and forward speed are decoupled here: satisfying R2/R3 needs `2^128` (or `2^256` if you are generous) of *attacker* work, while forward encoding of 1kB costs some `10µs`. One more `λ` doubles the attacker's bill and costs you nothing in the budget. The "balance" is not a trade-off, it is a headroom we barely touch.

---

## Reference API

A portable impl exposes three core operations. `gen` is the caller-owned counter:

```
fpr(S_0, K_r)                        -> FPR           # once, at init; then erase K_r
rotate(S_g, K_g, FPR, g)             -> (S_{g+1}, K_{g+1})  # advance BOTH chains, exactly once per generation
fre(input, S_g, FPR, g, ctx)         -> output        # the encoding, per spec 3
fre_out_len(input_len)               -> bytes         # size an output buffer, per spec 3
```

Call `rotate` with the same `(S_g, K_g, FPR, g)` on every device; it returns the next pair, keeping the two chains in lockstep. Note that `fpr`, `rotate` and `fre` take `FPR` and `K_g` explicitly: because of forward secrecy (R5/R11), `FPR` is not recoverable from `S_g` for `g > 0`, `K_{g'}` for `g' < g` is not recoverable from `K_g`, and neither ever appears inside any seed, so the caller keeps `FPR` and the current `K_g` next to the chain, exactly as with the seed. `ctx` MUST be ≤ 64 bytes and `g` MUST NOT wrap (see the notation section): both references enforce the former (`fre_encode` returns `0`, Rust panics) and document the latter. The C port also exposes `fre_hmac_sha256`, the exact HMAC primitive `fre_encode` uses, so ports can self-test against RFC 4231 without reimplementing anything.

Enough to implement NSC's relay recognition and any higher layer, without exposing internals.

---

## Test vectors

Produced by the reference implementation (Rust), cross-checked byte-for-byte by the C port. Every port MUST pass them byte-for-byte.

All vectors use `S_0 = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` and `K_r = 2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a`, which gives `FPR = 7d7a69ef67ec88e50dddb455359bc87642b537ee3ba8e91866667690c7028676` and `S_1 = 56970be00fb8136159e66ffe0237481f3d78c9819fe5aa022254176a8e70a122` (unchanged by the ratchet, since `K_0 = K_r`). The reference test suites additionally pin the derived chain quantities `S_2`, `S_42` and the ratcheted rotation keys `K_1 = 5b45c66c033725a0b94c3f7b5d006aedee67ab8c02f0abd7d0f684b2c251ea41`, `K_2 = 5c1cd1b2a8a9115701e0b960f64a1ab60c646be933815dc8a9ce0dffc9318b1b`, `K_42 = a0958ee52ba9841af473d3cd1aa439c94f76f19cb53795d067bfcfbec894ecca` (derived, not tabulated). The C suite additionally checks `fre_hmac_sha256` directly against RFC 4231 cases 1–7 (cases 6/7 use 131-byte keys, exercising the SHA-256 key-reduction branch that also covers the two long-`ctx` rows below) and asserts the `ctx` bound (rejections of `ctx_len` 65 and `NULL` with `len > 0`). `examples/vectors.rs` (Rust) regenerates the FRE vectors in one shot.

| `S_0` | `g` | `ctx` | `input` | `output` |
| --- | --- | --- | --- | --- |
| `000102…1e1f` | 0 | `""` | `"nsc"` | `33b143a2e4e1f02bfca78024a34f00d71ff6fa9736af8fcd1c635026d64988ac` |
| `000102…1e1f` | 1 | `""` | `"nsc"` | `9739e11076bae58ca80d7b8d505b7b612c84729079e1d04b081eb6cb34f65e10` |
| `000102…1e1f` | 42 | `""` | `"nsc"` | `7a1ce5d36dd55f4e908be5b40fc099a6f59cca09b568b7e1b7043fc99810f27f` |
| `000102…1e1f` | 0 | `""` | `""` | `c261e1f9f214eba416fd00407ed5e60a9b270005c09c6827ddfb39ffadd54cab` |
| `000102…1e1f` | 42 | `"nsc:relay"` | `""` | `e5971d59ed5156e1cec9e74c7e971588082527fc92bae7eedd16b85501429672` |
| `000102…1e1f` | 0 | `"nsc:relay"` | `"nsc"` | `a53393e090066281662f106f7dd5dc5f86755b36671b9de1d3bc4f0f4db5ef31` |
| `000102…1e1f` | 0 | `"nsc:msg"` | `"nsc"` | `b005df527f3c821de3bebb4fd683f815c2b7643ddf9265989eea9e0d5cd2c86f` |
| `000102…1e1f` | 0 | `""` | `"a\0"` | `3da0c452ce5ec0e6e2aa612216e218c8fdaf4619d6a316c9593d4f68353e37f1` |
| `000102…1e1f` | 0 | `""` | `"a\0\0"` | `e5b22044373ac1d55f6da3c9c56324ab8fa1110355da22d6e03ccdc24448934e` |
| `000102…1e1f` | 0 | `""` | `0x00`×63 | `65a209fc4b48696a4556a1b2f519062d4a0ba70565b4aa6d5032ad9180c50d11` |
| `000102…1e1f` | 0 | `""` | `0x00`×64 | `7fa054c8133de834e5cd9b50a284f51fdd889de6c0bde333260e7c314de2ba479664b9d5d1f64b357a909fa08265e3fb1b3fe0dbff93798fb157a695b4f551d7` |
| `000102…1e1f` | 0 | `""` | `0x00`×65 | `7fa054c8133de834e5cd9b50a284f51fdd889de6c0bde333260e7c314de2ba47d1eaa88f825827842c6d243c040427a1b1f8f8deb84a0a8680cd870f27c90d10` |
| `000102…1e1f` | 0 | `"nsc:msg"` | 1kB of `0x5a` | `ae6acbaaac0f006b…0d05093a3834` (544 bytes) |
| `000102…1e1f` | 0 | `"nsc:audit:long-context-vector-v1-pad-pad"` (40 B) | `"nsc"` | `0cc816a3444e2746ce8c21a74f8ba11a205ff6e713f0a750fc26fa2bb9c2c7cd` |
| `000102…1e1f` | 0 | 64×`'x'` (max) | `"nsc"` | `f57c98cb53c946e9cf1ec693f23d94d3b357d2574dd500bc8c1b9daca823c82c` |

---

## Open questions

- **Fingerprint origin** (`~DECISION`): the spec proposes `FPR = HMAC(S_0 ‖ K_r, tag)` **resolved**. `FPR` is the encoding identity, keyed by *both* secrets, so neither `S_0` nor `K_r` alone can reconstruct it and an `S_0`-only leak stays silent. Rotation is separately gated by `K_r` (R10). A per-generation rotating fingerprint remains rejected (breaks "constant").
- **Security level `λ`** (`~DECISION`): the spec defaults to `λ = 128` ("good enough, forever likely"). `λ = 256` doubles the margin at zero forward cost, worth choosing now so test vectors do not change twice.
- **Fixed-size output**: should we add a `FRE_FIXED` mode producing a constant-size output for arbitrary input, at the cost of more HMACs (a rate-limit style construction)? Currently deferred (R7, and not promising the impossible).

