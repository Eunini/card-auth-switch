//! Luhn (mod 10) check digit used by PANs.

pub fn check_digit(partial: &str) -> Option<u8> {
    if partial.is_empty() || !partial.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let sum: u32 = partial
        .bytes()
        .rev()
        .enumerate()
        .map(|(i, c)| {
            let d = (c - b'0') as u32;
            if i % 2 == 0 {
                let x = d * 2;
                if x > 9 {
                    x - 9
                } else {
                    x
                }
            } else {
                d
            }
        })
        .sum();
    Some(((10 - (sum % 10)) % 10) as u8)
}

pub fn is_valid(pan: &str) -> bool {
    if pan.len() < 2 {
        return false;
    }
    let (body, last) = pan.split_at(pan.len() - 1);
    match (check_digit(body), last.as_bytes()[0]) {
        (Some(d), c) => c == b'0' + d,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn known_pans() {
        assert!(super::is_valid("4111111111111111"));
        assert!(super::is_valid("5555555555554444"));
        assert!(super::is_valid("79927398713"));
        assert!(!super::is_valid("4111111111111112"));
        assert!(!super::is_valid("41111111a1111111"));
        assert_eq!(super::check_digit("7992739871"), Some(3));
    }
}
