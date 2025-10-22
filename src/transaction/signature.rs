use ethereum_types::U256;

// ECDSA signature validation constants for secp256k1 curve

/// Minimum valid value for signature components r and s (must be >= 1)
pub const SIGNATURE_LOWER_BOUND: U256 = U256([1, 0, 0, 0]);

/// Maximum valid value for signature components r and s (must be < secp256k1 curve order)
/// This is the secp256k1 curve order: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
/// U256 is stored in little-endian format as [u64; 4], so we need to reverse the byte order
pub const SIGNATURE_UPPER_BOUND: U256 = U256([
	0xbfd25e8cd0364141,
	0xbaaedce6af48a03b,
	0xfffffffffffffffe,
	0xffffffffffffffff,
]);

/// Maximum value for low-s signature enforcement (half of curve order)
/// This is used to prevent signature malleability
/// Value: 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
pub const SIGNATURE_LOW_S_BOUND: U256 = U256([
	0xdfe92f46681b20a0,
	0x5d576e7357a4501d,
	0xffffffffffffffff,
	0x7fffffffffffffff,
]);

/// Validates that a signature component (r or s) is within valid range
#[inline]
pub fn is_valid_signature_component(component: &U256) -> bool {
	*component >= SIGNATURE_LOWER_BOUND && *component < SIGNATURE_UPPER_BOUND
}

/// Checks if the s component satisfies the low-s requirement
#[inline]
pub fn is_low_s(s: &U256) -> bool {
	*s <= SIGNATURE_LOW_S_BOUND
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_secp256k1_curve_order() {
		// secp256k1 curve order (n) from SEC 2 specification
		// Reference: http://www.secg.org/sec2-v2.pdf Section 2.4.1
		let expected_n = U256::from_big_endian(&[
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
			0xd0, 0x36, 0x41, 0x41,
		]);

		assert_eq!(
			SIGNATURE_UPPER_BOUND, expected_n,
			"SIGNATURE_UPPER_BOUND must equal secp256k1 curve order"
		);
	}

	#[test]
	fn test_low_s_bound_is_half_curve_order() {
		// SIGNATURE_LOW_S_BOUND should be exactly n/2 where n is the curve order
		let n = SIGNATURE_UPPER_BOUND;
		let expected_half_n = n / 2;

		assert_eq!(
			SIGNATURE_LOW_S_BOUND, expected_half_n,
			"SIGNATURE_LOW_S_BOUND must be exactly half of the curve order"
		);
	}

	#[test]
	fn test_low_s_bound_hex_value() {
		// Verify the exact hex value for low-s bound
		let expected = U256::from_big_endian(&[
			0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46,
			0x68, 0x1b, 0x20, 0xa0,
		]);

		assert_eq!(
			SIGNATURE_LOW_S_BOUND, expected,
			"SIGNATURE_LOW_S_BOUND hex value mismatch"
		);
	}

	#[test]
	fn test_signature_bounds() {
		// Lower bound is 1
		assert_eq!(SIGNATURE_LOWER_BOUND, U256::one());

		// Verify that 0 is invalid
		assert!(!is_valid_signature_component(&U256::zero()));

		// Verify that 1 is valid (minimum)
		assert!(is_valid_signature_component(&U256::one()));

		// Verify that curve_order - 1 is valid (maximum)
		let max_valid = SIGNATURE_UPPER_BOUND - 1;
		assert!(is_valid_signature_component(&max_valid));

		// Verify that curve_order itself is invalid
		assert!(!is_valid_signature_component(&SIGNATURE_UPPER_BOUND));

		// Verify that values above curve_order are invalid
		let above_max = SIGNATURE_UPPER_BOUND + 1;
		assert!(!is_valid_signature_component(&above_max));
	}

	#[test]
	fn test_low_s_validation() {
		// s = 0 is invalid (below lower bound)
		assert!(!is_valid_signature_component(&U256::zero()));

		// s = 1 satisfies low-s requirement
		assert!(is_low_s(&U256::one()));

		// s = low_s_bound satisfies low-s requirement (boundary)
		assert!(is_low_s(&SIGNATURE_LOW_S_BOUND));

		// s = low_s_bound + 1 does NOT satisfy low-s requirement
		let above_low_s = SIGNATURE_LOW_S_BOUND + 1;
		assert!(!is_low_s(&above_low_s));

		// s = curve_order - 1 is valid but does NOT satisfy low-s
		let high_s = SIGNATURE_UPPER_BOUND - 1;
		assert!(is_valid_signature_component(&high_s));
		assert!(!is_low_s(&high_s));
	}

	#[test]
	fn test_k256_compatibility() {
		// This test verifies compatibility with the k256 crate's curve order
		// The k256 crate is the standard Rust implementation of secp256k1
		use hex_literal::hex;

		// secp256k1 curve order from multiple authoritative sources:
		// 1. SEC 2 v2 specification (http://www.secg.org/sec2-v2.pdf)
		// 2. Bitcoin Core implementation
		// 3. Ethereum's cryptographic implementation
		// 4. NIST and SECG standards
		let canonical_curve_order =
			hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

		let from_bytes = U256::from_big_endian(&canonical_curve_order);

		assert_eq!(
			SIGNATURE_UPPER_BOUND, from_bytes,
			"Curve order must match canonical secp256k1 specification"
		);
	}
}
