//! The SIDs a capability's name stands for
//! (`RtlDeriveCapabilitySidsFromName`): a group SID and a capability
//! SID, both made of the SHA-256 hash of the name in capitals, except
//! that the capabilities of the first Windows 8 applications keep the
//! short SIDs they were given then.

use alloc::vec::Vec;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 ([FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final))
/// of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut message = Vec::with_capacity(data.len() + 72);
    message.extend_from_slice(data);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for block in message.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (word, chunk) in w.iter_mut().zip(block.as_chunks::<4>().0) {
            *word = u32::from_be_bytes(*chunk);
        }
        for t in 16..64 {
            let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
            let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
            w[t] = w[t - 16]
                .wrapping_add(s0)
                .wrapping_add(w[t - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for t in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[t])
                .wrapping_add(w[t]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }
    let mut out = [0; 32];
    for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        *chunk = word.to_be_bytes();
    }
    out
}

/// The capabilities whose SIDs are `S-1-15-3-n`, `n` their place here
/// plus one (the pinned kernel's `RtlpLegacyApplicationCapabilityNames`).
const LEGACY: [&str; 12] = [
    "INTERNETCLIENT",
    "INTERNETCLIENTSERVER",
    "PRIVATENETWORKCLIENTSERVER",
    "PICTURESLIBRARY",
    "VIDEOSLIBRARY",
    "MUSICLIBRARY",
    "DOCUMENTSLIBRARY",
    "ENTERPRISEAUTHENTICATION",
    "SHAREDUSERCERTIFICATES",
    "REMOVABLESTORAGE",
    "APPOINTMENTS",
    "CONTACTS",
];

/// A SID of authority `authority` and these sub-authorities.
fn sid(authority: u8, subs: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 4 * subs.len());
    out.extend([1, subs.len() as u8, 0, 0, 0, 0, 0, authority]);
    for sub in subs {
        out.extend(sub.to_le_bytes());
    }
    out
}

/// `(group SID, capability SID)` for the capability named `upper`,
/// already in capitals: `S-1-5-32-h...` and `S-1-15-3-1024-h...`, `h`
/// the eight little-endian words of the name's SHA-256 hash (its
/// UTF-16 bytes), or `S-1-15-3-n` for a legacy capability.
pub fn derive(upper: &[u16]) -> (Vec<u8>, Vec<u8>) {
    let bytes: Vec<u8> = upper.iter().flat_map(|u| u.to_le_bytes()).collect();
    let hash = sha256(&bytes);
    let words: Vec<u32> = hash
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes(*c))
        .collect();
    let mut group = alloc::vec![32];
    group.extend(&words);
    let legacy = LEGACY
        .iter()
        .position(|name| name.encode_utf16().eq(upper.iter().copied()));
    let capability = match legacy {
        Some(at) => sid(15, &[3, at as u32 + 1]),
        None => {
            let mut subs = alloc::vec![3, 1024];
            subs.extend(&words);
            sid(15, &subs)
        }
    };
    (sid(5, &group), capability)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_digests() {
        let hex = |b: &[u8]| -> alloc::string::String {
            b.iter().map(|x| alloc::format!("{x:02x}")).collect()
        };
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    fn subs(sid: &[u8]) -> Vec<u32> {
        sid[8..]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
            .collect()
    }

    #[test]
    fn capability_sids() {
        // The capability pcw.sys's counter sets admit
        // (`windowsPerformanceCounters`): its SID is in the driver's own
        // SDDL string for its device, `S-1-15-3-1024-1221526253-...`.
        let name: Vec<u16> = "WINDOWSPERFORMANCECOUNTERS".encode_utf16().collect();
        let (group, capability) = derive(&name);
        let expected = [
            3, 1024, 1221526253, 3924910130, 1751405008, 69508222, 1499930412, 38408379,
            3528704847, 309525946,
        ];
        assert_eq!(subs(&capability), expected);
        assert_eq!(capability[..8], [1, 10, 0, 0, 0, 0, 0, 15]);
        assert_eq!(group[..8], [1, 9, 0, 0, 0, 0, 0, 5]);
        assert_eq!(subs(&group)[0], 32);
        assert_eq!(subs(&group)[1..], expected[2..]);
        let legacy: Vec<u16> = "CONTACTS".encode_utf16().collect();
        let (_, capability) = derive(&legacy);
        assert_eq!(
            capability,
            [1, 2, 0, 0, 0, 0, 0, 15, 3, 0, 0, 0, 12, 0, 0, 0]
        );
    }
}
