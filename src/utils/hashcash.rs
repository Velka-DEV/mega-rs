use base64::{
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
    Engine,
};
use reqwest::header;
use sha2::{
    digest::{FixedOutputReset, Update},
    Digest, Sha256,
};

pub fn gencash(token_b64: &str, easiness: u8) -> String {
    let threshold: u32 = {
        let low = ((easiness & 0b00_111111) as u32) << 1 | 1;
        let shift = ((easiness >> 6) as u32) * 7 + 3;
        low << shift
    };

    const TOKEN_LEN: usize = 48;
    const COPIES: usize = 262_144;
    let token_bytes = URL_SAFE_NO_PAD
        .decode(token_b64)
        .expect("token must be valid Base64");
    assert_eq!(
        token_bytes.len(),
        TOKEN_LEN,
        "token must decode to 48 bytes"
    );

    let mut buffer = vec![0u8; 4 + COPIES * TOKEN_LEN];
    for chunk in buffer[4..].chunks_exact_mut(TOKEN_LEN) {
        chunk.copy_from_slice(&token_bytes);
    }

    let prefix_ptr = buffer.as_mut_ptr() as *mut u32;

    let mut hasher = Sha256::new();

    loop {
        unsafe {
            *prefix_ptr = (*prefix_ptr).wrapping_add(1);
        }

        Update::update(&mut hasher, &buffer);
        let digest = hasher.finalize_fixed_reset();

        let first_u32 = u32::from_be_bytes(digest[..4].try_into().unwrap());
        if first_u32 <= threshold {
            let result_prefix = &buffer[..4];
            return STANDARD_NO_PAD.encode(result_prefix);
        }
    }
}

pub fn parse_hashcash_header(value: &header::HeaderValue) -> Option<(String, u8)> {
    let raw = value.to_str().ok()?.trim();
    let mut parts = raw.splitn(4, ':');

    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("1"), Some(eas), Some(_ts), Some(token)) => {
            let easiness: u8 = eas.parse().ok()?;
            if token.len() == 64 {
                Some((token.to_owned(), easiness))
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
// https://github.com/meganz/sdk/blob/master/tests/unit/hashcash_test.cpp#L35
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        let cases = [
            (
                "wFqIT_wY3tYKcrm5zqwaUoWym3ZCz32cCsrJOgYBgihtpaWUhGyWJ--EY-zfwI-i",
                180u8,
                "owAAAA",
            ),
            (
                "3NIjq_fgu6bTyepwHuKiaB8a1YRjISBhktWK1fjhRx86RhOqKZNAcOZht0wJvmhQ",
                180u8,
                "AQAAAA",
            ),
        ];

        for (token, easiness, expected) in cases {
            assert_eq!(gencash(token, easiness), expected);
        }
    }

    #[test]
    #[should_panic(expected = "valid Base64")]
    fn invalid_base64_panics() {
        let _ = gencash("not_base64!", 180);
    }
}
