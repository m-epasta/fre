//! Differential test-vector generator (Rust side).
//!
//! Emits deterministic FRE cases as `g,input_hex,ctx_hex,out_hex` lines fed to
//! `c/difftest` (and `c/difftest_asan`), which recompute every case with the C
//! port. Any divergence between the two implementations fails the C side.
//!
//! The case mix is aimed at the boundaries that matter:
//!   - input lengths 0..160 dense (covers the 63/64/65 and 127/128/129
//!     padding cliffs), then random lengths up to 4096 bytes;
//!   - ctx lengths concentrated on 0,7,9,16,17,40,63,64 plus random, so the
//!     HMAC key crosses 64 bytes (ctx 17 -> key 65) and the FRE_CTX_MAX bound
//!     (ctx 65 is never emitted; violations are exercised in the unit tests);
//!   - g concentrated on 0,1,41,42,43 plus random 0..=64, so both chains are
//!     rotated far from bootstrap in a reproducible way.
//!
//! PRNG is xorshift64* with a fixed default seed (no external deps); pass a
//! different `[N] [seed]` to re-roll while staying reproducible.

use std::env;

use rust_fre::{CTX_MAX, fpr, fre, rotate};

const S0: [u8; 32] = *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
const KR: [u8; 32] = [0x2a; 32];

struct XorShift(u64);

impl XorShift {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 56) as u8
    }
}

fn parse_u64(s: &str) -> u64 {
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).expect("hex seed")
    } else {
        s.parse().expect("decimal seed")
    }
}

fn hex(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len() * 2);
    for x in b {
        out.push_str(&format!("{x:02x}"));
    }
    out
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let n: usize = args
        .get(1)
        .map(|a| a.parse().expect("usage: difftest [N] [seed]"))
        .unwrap_or(20_000);
    let mut seed = args
        .get(2)
        .map(|a| parse_u64(a))
        .unwrap_or(0xa5a5_a5a5_a5a5_a5a5);
    if seed == 0 {
        seed = 1; // xorshift64* is stuck on state 0
    }
    let mut r = XorShift(seed);

    let f = fpr(&S0, &KR);

    // Precompute the two chains once: S_g and K_g for g in 0..=MAXG.
    const MAXG: usize = 64;
    let mut seeds = [[0u8; 32]; MAXG + 1];
    let mut keys = [[0u8; 32]; MAXG + 1];
    seeds[0] = S0;
    keys[0] = KR;
    for g in 0..MAXG {
        (seeds[g + 1], keys[g + 1]) = rotate(&seeds[g], &keys[g], &f, g as u64);
    }

    const SPECIAL_CTX: [usize; 8] = [0, 7, 9, 16, 17, 40, 63, 64];
    const SPECIAL_G: [u64; 5] = [0, 1, 41, 42, 43];

    for i in 0..n {
        let g = if r.below(6) == 0 {
            SPECIAL_G[r.below(SPECIAL_G.len() as u64) as usize]
        } else {
            r.below(MAXG as u64 + 1)
        };
        let ctx_len = if r.below(5) == 0 {
            SPECIAL_CTX[r.below(SPECIAL_CTX.len() as u64) as usize]
        } else {
            r.below(CTX_MAX as u64 + 1) as usize
        };
        let in_len = if i < 160 {
            i
        } else if r.below(10) < 7 {
            r.below(301) as usize
        } else {
            r.below(4097) as usize
        };
        let mut input = vec![0u8; in_len];
        for b in &mut input {
            *b = r.byte();
        }
        let mut ctx = vec![0u8; ctx_len];
        for b in &mut ctx {
            *b = r.byte();
        }
        let out = fre(&input, &seeds[g as usize], &f, g, &ctx);
        println!("{g},{},{},{}", hex(&input), hex(&ctx), hex(&out));
    }
}

