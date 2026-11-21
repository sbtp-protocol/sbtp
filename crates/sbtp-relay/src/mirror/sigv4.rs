//! AWS Signature Version 4 for one signed request with a signed payload (ADR 0050 rule 25), over
//! `sha2`: canonical request, string to sign, signing key derivation, and HMAC-SHA256 by
//! RFC 2104 (no extra crate). Tested with the RFC 4231 vectors and the published examples of the
//! S3 API reference ("Signature Calculations for the Authorization Header").

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// The SHA-256 block size, in bytes (RFC 2104 `B`).
const BLOCK: usize = 64;

/// HMAC-SHA256 (RFC 2104). The padded key blocks are wiped after use.
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = Zeroizing::new([0u8; BLOCK]);
    let mut hashed = Zeroizing::new([0u8; 32]);
    let key = if key.len() > BLOCK {
        hashed.copy_from_slice(&Sha256::digest(key));
        hashed.as_slice()
    } else {
        key
    };
    if let Some(head) = k.get_mut(..key.len()) {
        head.copy_from_slice(key);
    }
    let mut pad = Zeroizing::new([0u8; BLOCK]);
    for (p, b) in pad.iter_mut().zip(k.iter()) {
        *p = b ^ 0x36;
    }
    let inner = Sha256::new()
        .chain_update(*pad)
        .chain_update(data)
        .finalize();
    for (p, b) in pad.iter_mut().zip(k.iter()) {
        *p = b ^ 0x5c;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(
        &Sha256::new()
            .chain_update(*pad)
            .chain_update(inner)
            .finalize(),
    );
    out
}

/// Lowercase hexadecimal.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The hexadecimal SHA-256 of `data` (`x-amz-content-sha256`, the hashed canonical request).
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// URI-encodes a path for the canonical request: every byte except the unreserved characters
/// (`A-Z a-z 0-9 - . _ ~`) and `/` as `%XY`, uppercase.
#[must_use]
pub fn encode_path(path: &str) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(path.len());
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            s.push(char::from(b));
        } else {
            let _ = write!(s, "%{b:02X}");
        }
    }
    s
}

/// The credentials of the archive copy (ADR 0050 rule 22): read once at start-up, in memory
/// only, wiped on drop, never printed (`Debug` shows nothing).
pub struct Credentials {
    /// The access key identifier.
    pub access_key: Zeroizing<String>,
    /// The secret access key.
    pub secret_key: Zeroizing<String>,
    /// The session token of temporary credentials, if any.
    pub session_token: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credentials(..)")
    }
}

/// `YYYYMMDDTHHMMSSZ` for Unix milliseconds `ms` (UTC; the civil-from-days algorithm of
/// H. Hinnant, "chrono-Compatible Low-Level Date Algorithms").
#[must_use]
pub fn amz_date(ms: u64) -> String {
    let secs = ms / 1_000;
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

/// What one request signs.
pub struct Signing<'a> {
    /// `PUT`, `GET`...
    pub method: &'a str,
    /// The path, not yet encoded.
    pub path: &'a str,
    /// The header fields to sign, names lowercase, values as sent. `host` and `x-amz-date`
    /// included; sorted here.
    pub headers: &'a [(&'a str, &'a str)],
    /// The hexadecimal SHA-256 of the body (`x-amz-content-sha256`).
    pub payload_hash: &'a str,
    /// `x-amz-date`.
    pub amz_date: &'a str,
    /// The region, `us-east-1` or `auto` for example.
    pub region: &'a str,
}

/// The signing key: `HMAC(HMAC(HMAC(HMAC("AWS4" + secret, date), region), "s3"), "aws4_request")`.
fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Zeroizing<[u8; 32]> {
    let mut first = Zeroizing::new(Vec::with_capacity(4 + secret.len()));
    first.extend_from_slice(b"AWS4");
    first.extend_from_slice(secret.as_bytes());
    let mut k = hmac_sha256(&first, date.as_bytes());
    for part in [region.as_bytes(), service.as_bytes(), b"aws4_request"] {
        let next = hmac_sha256(&k, part);
        k.zeroize();
        k = next;
    }
    Zeroizing::new(k)
}

/// The `Authorization` header value of `s` with `creds` (service `s3`, empty query string).
#[must_use]
pub fn authorization(s: &Signing<'_>, creds: &Credentials) -> String {
    let date = s.amz_date.get(..8).unwrap_or_default();
    let mut headers: Vec<(&str, &str)> = s.headers.to_vec();
    headers.sort_unstable_by(|a, b| a.0.cmp(b.0));
    let mut canonical_headers = String::new();
    for (n, v) in &headers {
        canonical_headers.push_str(n);
        canonical_headers.push(':');
        canonical_headers.push_str(v.trim());
        canonical_headers.push('\n');
    }
    let signed: Vec<&str> = headers.iter().map(|(n, _)| *n).collect();
    let signed = signed.join(";");
    let canonical = format!(
        "{}\n{}\n\n{canonical_headers}\n{signed}\n{}",
        s.method,
        encode_path(s.path),
        s.payload_hash
    );
    let scope = format!("{date}/{}/s3/aws4_request", s.region);
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        s.amz_date,
        sha256_hex(canonical.as_bytes())
    );
    let key = signing_key(&creds.secret_key, date, s.region, "s3");
    let signature = hex(&hmac_sha256(&*key, to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",
        creds.access_key.as_str()
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// RFC 4231 test cases 1, 2, 4, 6 and 7 (HMAC-SHA256).
    #[test]
    fn hmac_rfc4231() {
        let cases: [(&[u8], &[u8], &str); 5] = [
            (
                &[0x0b; 20],
                b"Hi There",
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                &[
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                    23, 24, 25,
                ],
                &[0xcd; 50],
                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            ),
            (
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
            (
                &[0xaa; 131],
                b"This is a test using a larger than block-size key and a larger than block-size \
                  data. The key needs to be hashed before being used by the HMAC algorithm.",
                "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            ),
        ];
        for (key, data, mac) in cases {
            assert_eq!(hex(&hmac_sha256(key, data)), mac);
        }
    }

    fn example_creds() -> Credentials {
        // The example key pair of the AWS documentation (public, not a credential).
        Credentials {
            access_key: Zeroizing::new("AKIAIOSFODNN7EXAMPLE".into()),
            secret_key: Zeroizing::new("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into()),
            session_token: None,
        }
    }

    /// The signing key example of the AWS Signature Version 4 documentation (service `iam`).
    #[test]
    fn signing_key_example() {
        let k = signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "iam",
        );
        assert_eq!(
            hex(&*k),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }

    /// S3 API reference, "Example: GET Object".
    #[test]
    fn s3_get_object_example() {
        let empty = sha256_hex(b"");
        let s = Signing {
            method: "GET",
            path: "/test.txt",
            headers: &[
                ("host", "examplebucket.s3.amazonaws.com"),
                ("range", "bytes=0-9"),
                ("x-amz-content-sha256", &empty),
                ("x-amz-date", "20130524T000000Z"),
            ],
            payload_hash: &empty,
            amz_date: "20130524T000000Z",
            region: "us-east-1",
        };
        assert_eq!(
            authorization(&s, &example_creds()),
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    /// S3 API reference, "Example: PUT Object" (a path that needs encoding, a signed payload).
    #[test]
    fn s3_put_object_example() {
        let body = sha256_hex(b"Welcome to Amazon S3.");
        assert_eq!(
            body,
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
        let s = Signing {
            method: "PUT",
            path: "/test$file.text",
            headers: &[
                ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
                ("x-amz-date", "20130524T000000Z"),
                ("x-amz-content-sha256", &body),
                ("host", "examplebucket.s3.amazonaws.com"),
                ("date", "Fri, 24 May 2013 00:00:00 GMT"),
            ],
            payload_hash: &body,
            amz_date: "20130524T000000Z",
            region: "us-east-1",
        };
        assert!(authorization(&s, &example_creds()).ends_with(
            "SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, \
             Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
        ));
    }

    #[test]
    fn dates_and_paths() {
        assert_eq!(amz_date(0), "19700101T000000Z");
        assert_eq!(amz_date(1_369_353_600_000), "20130524T000000Z");
        assert_eq!(amz_date(951_782_400_000 + 3_723_000), "20000229T010203Z");
        assert_eq!(encode_path("/a b/$~"), "/a%20b/%24~");
        assert_eq!(format!("{:?}", example_creds()), "Credentials(..)");
    }
}
