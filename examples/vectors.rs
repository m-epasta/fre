use rust_fre::{fpr, fre, rotate};

const S0: [u8; 32] = *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
const KR: [u8; 32] = [0x2a; 32];

fn bcases(input: &[u8], g: u64, ctx: &[u8]) {
    let f = fpr(&S0, &KR);
    let (mut s, mut k) = (S0, KR);
    for gi in 0..g {
        (s, k) = rotate(&s, &k, &f, gi);
    }
    let out = fre(input, &s, &f, g, ctx);
    let label = match input {
        b"nsc" => "# \"nsc\"".into(),
        b"a\0" => "# \"a NUL\"".into(),
        b"a\0\0" => "# \"a NUL NUL\"".into(),
        _ => format!("# [0x00 x {}]", input.len()),
    };
    println!(
        "{label} g={g} ctx={:?} |S|={} |out|={}",
        String::from_utf8_lossy(ctx),
        input.len(),
        out.len()
    );
    println!("  S_g = {}", hex::encode(s));
    println!("  out = {}", hex::encode(out));
}

fn fold42() -> ([u8; 32], [u8; 32]) {
    let f = fpr(&S0, &KR);
    let (mut s, mut k) = (S0, KR);
    for g in 0..42 {
        (s, k) = rotate(&s, &k, &f, g);
    }
    (s, k)
}

fn main() {
    println!("S_0 = {}", hex::encode(S0));
    println!("K_r = {}", hex::encode(KR));
    let f = fpr(&S0, &KR);
    println!("FPR = {}", hex::encode(f));
    let (s1, k1) = rotate(&S0, &KR, &f, 0);
    println!("S_1 = {}", hex::encode(s1));
    println!("K_1 = {}", hex::encode(k1));
    let (s2, k2) = rotate(&s1, &k1, &f, 1);
    println!("S_2 = {}", hex::encode(s2));
    println!("K_2 = {}", hex::encode(k2));
    let (s42, k42) = fold42();
    println!("S_42 = {}", hex::encode(s42));
    println!("K_42 = {}", hex::encode(k42));

    let f = fpr(&S0, &KR);
    bcases(b"nsc", 0, b"");
    bcases(b"nsc", 1, b"");
    bcases(b"nsc", 42, b"");
    bcases(b"", 42, b"nsc:relay");
    bcases(b"nsc", 0, b"nsc:relay");
    bcases(b"nsc", 0, b"nsc:msg");
    bcases(b"", 0, b"");
    bcases(b"a\0", 0, b"");
    bcases(b"a\0\0", 0, b"");
    bcases(&[0u8; 63], 0, b"");
    bcases(&[0u8; 64], 0, b"");
    bcases(&[0u8; 65], 0, b"");
    // ctx bound cases: key = 48 + ctx_len, so 40 -> 88 > 64 (long-key HMAC
    // path) and 64 -> 112 (FRE_CTX_MAX / CTX_MAX, the largest legal key).
    bcases(b"nsc", 0, b"nsc:audit:long-context-vector-v1-pad-pad");
    bcases(b"nsc", 0, &[b'x'; 64]);

    let payload1k = vec![0x5au8; 1024];
    let out = fre(&payload1k, &S0, &f, 0, b"nsc:msg");
    println!("# 1kB payload g=0 ctx=\"nsc:msg\" |out|={}", out.len());
    println!("  out = {}", hex::encode(out));
}

