//! JavaScript's `ToInt32`, `ToUint32`, bitwise operators, `Number`, and `parseInt` on `f64`.

/// Converts to a signed 32-bit integer using JavaScript's `value | 0` rules.
#[must_use]
#[inline(always)]
pub(crate) fn int32(value: f64) -> i32 {
    uint32(value) as i32
}

/// Converts to an unsigned 32-bit integer using JavaScript's `value >>> 0` rules.
#[must_use]
#[inline(always)]
pub(crate) fn uint32(value: f64) -> u32 {
    // A truncated value with magnitude below 2^63 fits exactly in `i64`. Its low 32 bits give
    // the value modulo 2^32.
    if value.abs() < 9_223_372_036_854_775_808.0 {
        value as i64 as u32
    } else if value.is_finite() {
        value.rem_euclid(4_294_967_296.0) as u32
    } else {
        0
    }
}

// JavaScript's bitwise operators, with `ushr` as `>>>`. Shifts take the count modulo 32.

#[must_use]
#[inline(always)]
pub(crate) fn bit_and(a: f64, b: f64) -> f64 {
    f64::from(int32(a) & int32(b))
}

#[must_use]
#[inline(always)]
pub(crate) fn bit_or(a: f64, b: f64) -> f64 {
    f64::from(int32(a) | int32(b))
}

#[must_use]
#[inline(always)]
pub(crate) fn bit_xor(a: f64, b: f64) -> f64 {
    f64::from(int32(a) ^ int32(b))
}

#[must_use]
#[inline(always)]
pub(crate) fn bit_not(a: f64) -> f64 {
    f64::from(!int32(a))
}

#[must_use]
#[inline(always)]
pub(crate) fn shl(a: f64, b: f64) -> f64 {
    f64::from(int32(a).wrapping_shl(uint32(b)))
}

#[must_use]
#[inline(always)]
pub(crate) fn shr(a: f64, b: f64) -> f64 {
    f64::from(int32(a).wrapping_shr(uint32(b)))
}

#[must_use]
#[inline(always)]
pub(crate) fn ushr(a: f64, b: f64) -> f64 {
    f64::from(uint32(a).wrapping_shr(uint32(b)))
}

/// Matches ECMAScript whitespace and line terminators skipped by `Number`, `parseInt`, and
/// `trim`. Includes the byte order mark (BOM) and excludes U+0085 (NEXT LINE).
fn is_whitespace(c: char) -> bool {
    c == '\u{feff}' || (c.is_whitespace() && c != '\u{85}')
}

/// `Number(text)`: JavaScript's StringToNumber.
#[must_use]
pub(crate) fn string_number(text: &str) -> f64 {
    let text = text.trim_matches(is_whitespace);
    match text {
        "" => return 0.0,
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    let radix = match text.get(..2) {
        Some("0x" | "0X") => Some(16),
        Some("0o" | "0O") => Some(8),
        Some("0b" | "0B") => Some(2),
        _ => None,
    };
    if let Some(radix) = radix {
        let digits = &text[2..];
        if digits.is_empty() {
            return f64::NAN;
        }
        let value = digits.chars().try_fold(0.0, |n, c| {
            Some(n * f64::from(radix) + f64::from(c.to_digit(radix)?))
        });
        return value.unwrap_or(f64::NAN);
    }
    if text
        .bytes()
        .any(|b| !b.is_ascii_digit() && !b"+-.eE".contains(&b))
    {
        return f64::NAN;
    }
    text.parse().unwrap_or(f64::NAN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_follows_string_to_number() {
        assert_eq!(string_number(" \u{feff}12 "), 12.0);
        assert_eq!(string_number(""), 0.0);
        assert_eq!(string_number("0x1f"), 31.0);
        assert!(string_number("0x").is_nan());
        assert_eq!(string_number("-Infinity"), f64::NEG_INFINITY);
        assert!(string_number("1_000").is_nan());
        for (text, number) in [("0b101", 5.0), ("1e3", 1000.0), (".5", 0.5), ("5.", 5.0)] {
            assert_eq!(string_number(text), number, "{text:?}");
        }
        let whitespace = "\t\n\r\u{b}\u{c} \u{a0}\u{1680}\u{2000}\u{2001}\u{2002}\u{2003}\u{2004}\
                          \u{2005}\u{2006}\u{2007}\u{2008}\u{2009}\u{200a}\u{2028}\u{2029}\
                          \u{202f}\u{205f}\u{3000}\u{feff}";
        for c in whitespace.chars() {
            assert_eq!(string_number(&format!("{c}12{c}")), 12.0, "{c:?}");
        }
        for text in [
            "\u{85}12",
            "\u{200b}12",
            "\u{180e}12",
            "inf",
            "nan",
            "infinity",
            "-0x1",
            "e5",
            "+",
        ] {
            assert!(string_number(text).is_nan(), "{text:?}");
        }
    }

    #[test]
    fn integer_conversions_wrap_and_truncate() {
        assert_eq!(int32(-1.5), -1);
        assert_eq!(int32(2_147_483_648.0), -2_147_483_648);
        assert_eq!(int32(f64::NAN), 0);
        assert_eq!(int32(f64::INFINITY), 0);
        assert_eq!(uint32(-1.0), 4_294_967_295);
        assert_eq!(uint32(-4_294_967_297.5), 4_294_967_295);
        assert_eq!(uint32(2f64.powi(63) + 2f64.powi(31) * 3.0), 2_147_483_648);
        assert_eq!(int32(-2f64.powi(70)), 0);
        assert_eq!(uint32(f64::NEG_INFINITY), 0);
    }

    #[test]
    fn shifts_take_the_count_modulo_32() {
        assert_eq!(shl(1.0, 33.0), 2.0);
        assert_eq!(shl(1.0, 31.0), -2_147_483_648.0);
        assert_eq!(shr(-8.0, 1.0), -4.0);
        assert_eq!(ushr(-8.0, 1.0), 2_147_483_644.0);
        assert_eq!(ushr(-1.0, 0.0), 4_294_967_295.0);
        assert_eq!(bit_not(f64::NAN), -1.0);
    }
}
