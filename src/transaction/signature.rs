use ethereum_types::H256;

// ECDSA signature validation constants for secp256k1 curve

/// Minimum valid value for signature components r and s (must be >= 1)
pub const SIGNATURE_LOWER_BOUND: H256 = H256([
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
]);

/// Maximum valid value for signature components r and s (must be < secp256k1 curve order)
/// This is the secp256k1 curve order: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
pub const SIGNATURE_UPPER_BOUND: H256 = H256([
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
]);

/// Maximum value for low-s signature enforcement (half of curve order)
/// This is used to prevent signature malleability
/// Value: 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
pub const SIGNATURE_LOW_S_BOUND: H256 = H256([
	0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
]);

/// Validates that a signature component (r or s) is within valid range
///
/// A valid signature component must satisfy:
/// - Greater than or equal to 1 (SIGNATURE_LOWER_BOUND)
/// - Less than the secp256k1 curve order (SIGNATURE_UPPER_BOUND)
#[inline]
pub fn is_valid_signature_component(component: &H256) -> bool {
	*component >= SIGNATURE_LOWER_BOUND && *component < SIGNATURE_UPPER_BOUND
}

/// Checks if the s component satisfies the low-s requirement
///
/// The low-s requirement helps prevent signature malleability by requiring
/// that s <= n/2 where n is the curve order.
#[inline]
pub fn is_low_s(s: &H256) -> bool {
	*s <= SIGNATURE_LOW_S_BOUND
}

#[cfg(test)]
mod tests {
	use super::*;
	use ethereum_types::U256;

	/// Helper function to convert H256 to U256 for arithmetic operations in tests
	#[inline]
	fn h256_to_u256(h: &H256) -> U256 {
		U256::from_big_endian(h.as_bytes())
	}

	/// Helper function to convert U256 to H256
	#[inline]
	fn u256_to_h256(u: U256) -> H256 {
		H256::from(u.to_big_endian())
	}

	#[test]
	fn test_low_s_bound_is_half_curve_order() {
		// SIGNATURE_LOW_S_BOUND should be exactly n/2 where n is the curve order
		let n = h256_to_u256(&SIGNATURE_UPPER_BOUND);
		let expected_half_n = u256_to_h256(n / 2);

		assert_eq!(
			SIGNATURE_LOW_S_BOUND, expected_half_n,
			"SIGNATURE_LOW_S_BOUND must be exactly half of the curve order"
		);
	}

	#[test]
	fn test_signature_bounds() {
		// Lower bound is 1
		assert_eq!(SIGNATURE_LOWER_BOUND, H256::from_low_u64_be(1));

		// Verify that 0 is invalid
		assert!(!is_valid_signature_component(&H256::zero()));

		// Verify that 1 is valid (minimum)
		assert!(is_valid_signature_component(&H256::from_low_u64_be(1)));

		// Verify that curve_order - 1 is valid (maximum)
		let max_valid = u256_to_h256(h256_to_u256(&SIGNATURE_UPPER_BOUND) - 1);
		assert!(is_valid_signature_component(&max_valid));

		// Verify that curve_order itself is invalid
		assert!(!is_valid_signature_component(&SIGNATURE_UPPER_BOUND));

		// Verify that values above curve_order are invalid
		let above_max = u256_to_h256(h256_to_u256(&SIGNATURE_UPPER_BOUND) + 1);
		assert!(!is_valid_signature_component(&above_max));
	}

	#[test]
	fn test_low_s_validation() {
		// s = 0 is invalid (below lower bound)
		assert!(!is_valid_signature_component(&H256::zero()));

		// s = 1 satisfies low-s requirement
		assert!(is_low_s(&u256_to_h256(U256::one())));

		// s = low_s_bound satisfies low-s requirement (boundary)
		assert!(is_low_s(&SIGNATURE_LOW_S_BOUND));

		// s = low_s_bound + 1 does NOT satisfy low-s requirement
		let above_low_s = u256_to_h256(h256_to_u256(&SIGNATURE_LOW_S_BOUND) + 1);
		assert!(!is_low_s(&above_low_s));

		// s = curve_order - 1 is valid but does NOT satisfy low-s
		let high_s = u256_to_h256(h256_to_u256(&SIGNATURE_UPPER_BOUND) - 1);
		assert!(is_valid_signature_component(&high_s));
		assert!(!is_low_s(&high_s));
	}

	#[test]
	fn test_boundary_conditions() {
		// Test exact boundary values
		assert_eq!(h256_to_u256(&SIGNATURE_LOWER_BOUND), U256::one());

		// Ensure low-s bound is exactly half the curve order (curve_order / 2)
		// Note: The curve order is odd, so half_order * 2 + 1 = curve_order
		let curve_order = h256_to_u256(&SIGNATURE_UPPER_BOUND);
		let half_order = h256_to_u256(&SIGNATURE_LOW_S_BOUND);
		assert_eq!(curve_order / 2, half_order);
	}
}
