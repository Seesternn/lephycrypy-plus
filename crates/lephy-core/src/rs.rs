//! Reed–Solomon error correction: GF(2^8), primitive polynomial 0x11d, generator α = 2, first
//! consecutive root α^0, systematic code. Codeword `n = k + nsym ≤ 255` bytes; up to `nsym / 2`
//! byte errors (unknown positions) are corrected. Algorithm: syndromes → Berlekamp–Massey → Chien
//! search → Forney. Syndromes are checked again after correcting; damage beyond the capacity is an
//! error (a wrong "correction" is in any case caught by the encryption's authentication).

use std::sync::OnceLock;

/// GF(2^8) tables.
struct Gf {
    exp: [u8; 512],
    log: [u8; 256],
}

fn gf() -> &'static Gf {
    static T: OnceLock<Gf> = OnceLock::new();
    T.get_or_init(|| {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for (i, e) in exp.iter_mut().enumerate().take(255) {
            *e = u8::try_from(x).unwrap_or(0);
            log[usize::from(*e)] = u8::try_from(i).unwrap_or(0);
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Gf { exp, log }
    })
}

fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = gf();
    t.exp[usize::from(t.log[usize::from(a)]) + usize::from(t.log[usize::from(b)])]
}

fn div(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = gf();
    t.exp[(usize::from(t.log[usize::from(a)]) + 255 - usize::from(t.log[usize::from(b)])) % 255]
}

/// `x^p` (p may be negative).
fn pow(x: u8, p: i32) -> u8 {
    if x == 0 {
        return 0;
    }
    let t = gf();
    let l = i32::from(t.log[usize::from(x)]);
    let e = usize::try_from((l * p).rem_euclid(255)).unwrap_or(0);
    t.exp[e]
}

fn inverse(x: u8) -> u8 {
    div(1, x)
}

fn poly_scale(p: &[u8], x: u8) -> Vec<u8> {
    p.iter().map(|&c| mul(c, x)).collect()
}

fn poly_add(p: &[u8], q: &[u8]) -> Vec<u8> {
    let n = p.len().max(q.len());
    let mut r = vec![0u8; n];
    for (i, &c) in p.iter().enumerate() {
        r[i + n - p.len()] = c;
    }
    for (i, &c) in q.iter().enumerate() {
        r[i + n - q.len()] ^= c;
    }
    r
}

fn poly_mul(p: &[u8], q: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; p.len() + q.len() - 1];
    for (j, &qj) in q.iter().enumerate() {
        for (i, &pi) in p.iter().enumerate() {
            r[i + j] ^= mul(pi, qj);
        }
    }
    r
}

/// Horner (highest degree first).
fn poly_eval(p: &[u8], x: u8) -> u8 {
    let mut y = p[0];
    for &c in &p[1..] {
        y = mul(y, x) ^ c;
    }
    y
}

/// Generator polynomial (cached).
fn generator(nsym: usize) -> &'static [u8] {
    static G: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    let all = G.get_or_init(|| {
        (0..=64i32)
            .map(|n| {
                let mut g = vec![1u8];
                for i in 0..n {
                    g = poly_mul(&g, &[1, pow(2, i)]);
                }
                g
            })
            .collect()
    });
    &all[nsym.min(64)]
}

/// Computes `nsym` parity bytes for `msg` (`msg.len() + nsym ≤ 255`, `nsym ≤ 64`).
#[must_use]
pub fn encode(msg: &[u8], nsym: usize) -> Vec<u8> {
    let gpoly = generator(nsym);
    let mut out = vec![0u8; msg.len() + nsym];
    out[..msg.len()].copy_from_slice(msg);
    for i in 0..msg.len() {
        let coef = out[i];
        if coef != 0 {
            for (j, &g) in gpoly.iter().enumerate().skip(1) {
                out[i + j] ^= mul(g, coef);
            }
        }
    }
    out[msg.len()..].to_vec()
}

/// Syndromes, with a leading zero (the shift convention of the algorithms below).
/// Since `x = α^i`, `log x = i`: each Horner step is a single table lookup (hot path).
fn syndromes(cw: &[u8], nsym: usize) -> Vec<u8> {
    let t = gf();
    let mut s = vec![0u8; nsym + 1];
    for (i, out) in s.iter_mut().skip(1).enumerate() {
        let mut y = cw[0];
        for &c in &cw[1..] {
            y = if y == 0 {
                c
            } else {
                t.exp[usize::from(t.log[usize::from(y)]) + i] ^ c
            };
        }
        *out = y;
    }
    s
}

/// Whether the codeword is valid (all syndromes zero) — a fast check.
#[must_use]
pub fn is_valid(cw: &[u8], nsym: usize) -> bool {
    syndromes(cw, nsym).iter().all(|&x| x == 0)
}

fn error_locator(synd: &[u8], nsym: usize) -> Option<Vec<u8>> {
    let mut err_loc = vec![1u8];
    let mut old_loc = vec![1u8];
    let shift = synd.len() - nsym;
    for i in 0..nsym {
        let k = i + shift;
        let mut delta = synd[k];
        for j in 1..err_loc.len() {
            delta ^= mul(err_loc[err_loc.len() - 1 - j], synd[k - j]);
        }
        old_loc.push(0);
        if delta != 0 {
            if old_loc.len() > err_loc.len() {
                let new_loc = poly_scale(&old_loc, delta);
                old_loc = poly_scale(&err_loc, inverse(delta));
                err_loc = new_loc;
            }
            err_loc = poly_add(&err_loc, &poly_scale(&old_loc, delta));
        }
    }
    while err_loc.first() == Some(&0) {
        err_loc.remove(0);
    }
    let errs = err_loc.len().checked_sub(1)?;
    (errs * 2 <= nsym).then_some(err_loc)
}

fn find_errors(err_loc_rev: &[u8], nmess: usize) -> Option<Vec<usize>> {
    let errs = err_loc_rev.len() - 1;
    let mut pos = Vec::with_capacity(errs);
    for i in 0..nmess {
        if poly_eval(err_loc_rev, pow(2, i32::try_from(i).unwrap_or(0))) == 0 {
            pos.push(nmess - 1 - i);
        }
    }
    (pos.len() == errs).then_some(pos)
}

fn errata_locator(coef_pos: &[usize]) -> Vec<u8> {
    let mut e = vec![1u8];
    for &i in coef_pos {
        e = poly_mul(
            &e,
            &poly_add(&[1], &[pow(2, i32::try_from(i).unwrap_or(0)), 0]),
        );
    }
    e
}

fn error_evaluator(synd_rev: &[u8], err_loc: &[u8], nsym: usize) -> Vec<u8> {
    let r = poly_mul(synd_rev, err_loc);
    r[r.len() - (nsym + 1)..].to_vec()
}

fn correct_errata(cw: &mut [u8], synd: &[u8], err_pos: &[usize]) {
    let n = cw.len();
    let coef_pos: Vec<usize> = err_pos.iter().map(|&p| n - 1 - p).collect();
    let err_loc = errata_locator(&coef_pos);
    let synd_rev: Vec<u8> = synd.iter().rev().copied().collect();
    let mut err_eval = error_evaluator(&synd_rev, &err_loc, err_loc.len() - 1);
    err_eval.reverse();
    let x: Vec<u8> = coef_pos
        .iter()
        .map(|&i| pow(2, -(255 - i32::try_from(i).unwrap_or(0))))
        .collect();
    let eval_rev: Vec<u8> = err_eval.iter().rev().copied().collect();
    for (i, &xi) in x.iter().enumerate() {
        let xi_inv = inverse(xi);
        let mut prime = 1u8;
        for (j, &xj) in x.iter().enumerate() {
            if j != i {
                prime = mul(prime, 1 ^ mul(xi_inv, xj));
            }
        }
        let y = mul(xi, poly_eval(&eval_rev, xi_inv));
        cw[err_pos[i]] ^= div(y, prime);
    }
}

/// Corrects a codeword (`data ‖ parity`) in place. Returns the number of corrected bytes, or
/// `None` if the correction capacity was exceeded (the codeword is left unchanged).
#[must_use]
pub fn decode(cw: &mut [u8], nsym: usize) -> Option<usize> {
    let synd = syndromes(cw, nsym);
    if synd.iter().all(|&s| s == 0) {
        return Some(0);
    }
    let err_loc = error_locator(&synd, nsym)?;
    let rev: Vec<u8> = err_loc.iter().rev().copied().collect();
    let pos = find_errors(&rev, cw.len())?;
    let mut fixed = cw.to_vec();
    correct_errata(&mut fixed, &synd, &pos);
    if syndromes(&fixed, nsym).iter().all(|&s| s == 0) {
        cw.copy_from_slice(&fixed);
        Some(pos.len())
    } else {
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    /// Small deterministic generator (for tests).
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 33
        }
        fn byte(&mut self) -> u8 {
            self.next().to_le_bytes()[0]
        }
        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next()).unwrap_or(0) % n
        }
    }

    #[test]
    fn field_tables_are_consistent() {
        for a in 1..=255u8 {
            assert_eq!(mul(a, inverse(a)), 1, "{a}");
            assert_eq!(div(mul(a, 7), 7), a);
        }
        // Known value: 2^8 = 0x1d in the 0x11d field.
        assert_eq!(pow(2, 8), 0x1d);
    }

    #[test]
    fn known_vector_for_generator() {
        // Generator for nsym = 4: (x+1)(x+2)(x+4)(x+8) = x^4 + 15x^3 + 54x^2 + 120x + 64.
        assert_eq!(generator(4), &[1, 15, 54, 120, 64]);
    }

    #[test]
    fn corrects_up_to_half_nsym_errors_and_detects_more() {
        let mut r = Lcg(42);
        for nsym in [8usize, 16, 32] {
            for trial in 0..200 {
                let k = 255 - nsym;
                let msg: Vec<u8> = (0..k).map(|_| r.byte()).collect();
                let mut cw = msg.clone();
                cw.extend(encode(&msg, nsym));
                let clean = cw.clone();
                let errs = trial % (nsym / 2 + 1);
                let mut used = std::collections::HashSet::new();
                while used.len() < errs {
                    let p = r.below(cw.len());
                    if used.insert(p) {
                        cw[p] ^= r.byte() | 1;
                    }
                }
                assert_eq!(
                    decode(&mut cw, nsym),
                    Some(errs),
                    "nsym {nsym}, {errs} errors"
                );
                assert_eq!(cw, clean);
            }
            // Damage beyond the capacity is either rejected or (rarely) corrected to another valid
            // codeword; that case is caught by the AEAD. Here we only check that it does not panic
            // and that the result is consistent.
            let k = 255 - nsym;
            let msg: Vec<u8> = (0..k).map(|_| r.byte()).collect();
            let mut cw = msg.clone();
            cw.extend(encode(&msg, nsym));
            for p in 0..(nsym + 4) {
                cw[p * 3] ^= 0xa5;
            }
            if let Some(_n) = decode(&mut cw, nsym) {
                assert!(syndromes(&cw, nsym).iter().all(|&s| s == 0));
            }
        }
    }

    #[test]
    fn short_codewords_work() {
        let msg = b"tiny";
        let mut cw = msg.to_vec();
        cw.extend(encode(msg, 8));
        cw[1] ^= 0xff;
        cw[9] ^= 0x01;
        assert_eq!(decode(&mut cw, 8), Some(2));
        assert_eq!(&cw[..4], msg);
    }
}
