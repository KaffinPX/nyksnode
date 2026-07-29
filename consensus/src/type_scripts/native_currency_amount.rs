use std::fmt::Display;
use std::iter::Sum;
use std::ops::Add;
use std::ops::AddAssign;
use std::ops::Neg;
use std::ops::Sub;
use std::str::FromStr;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::ensure;
use get_size2::GetSize;
use itertools::Itertools;
use num_bigint::BigInt;
use num_rational::BigRational;
use num_traits::CheckedAdd;
use num_traits::CheckedSub;
use num_traits::FromPrimitive;
use num_traits::ToPrimitive;
use num_traits::Zero;
use regex::Regex;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::prelude::LabelledInstruction;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use super::native_currency::NativeCurrency;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::transaction::utxo::Coin;
use crate::triton_vm::prelude::triton_instr;

/// Records an amount of Nyks coins. Amounts are internally represented by an
/// atomic unit called Nyks atomic units (nyx), which itself is represented
/// as a 128 bit integer.
///
/// 1 Nyks coin = 10^8 nyx.
///
/// This conversion factor was chosen such that:
///  - The largest possible amount, corresponding to 4 200 000 000 Nyks coins, takes 124 bits.
///    The top bit is the sign bit and is used for negative amounts (in two's complement).
///  - When expanding amounts of Nyks coins in decimal form, we can represent them exactly
///    up to 8 decimal digits.
///
/// When using `NativeCurrencyAmount` in a type script or a lock script, or even another consensus
/// program related to block validity, it is important to use `safe_add` rather than `+` as
/// the latter operation does not care about overflow. Not testing for overflow can cause
/// inflation bugs.
#[derive(Clone, Debug, Copy, Serialize, Deserialize, Eq, Default, BFieldCodec)]
pub struct NativeCurrencyAmount(i128);

impl TasmObject for NativeCurrencyAmount {
    fn label_friendly_name() -> String {
        "NativeCurrencyAmount".to_owned()
    }

    fn compute_size_and_assert_valid_size_indicator(
        library: &mut tasm_lib::prelude::Library,
    ) -> Vec<tasm_lib::triton_vm::prelude::LabelledInstruction> {
        u128::compute_size_and_assert_valid_size_indicator(library)
    }

    fn decode_iter<Itr: Iterator<Item = tasm_lib::triton_vm::prelude::BFieldElement>>(
        iterator: &mut Itr,
    ) -> std::result::Result<Box<Self>, Box<dyn std::error::Error + Send + Sync>> {
        let inner = *u128::decode_iter(iterator)? as i128;

        std::result::Result::Ok(Box::new(NativeCurrencyAmount(inner)))
    }
}

impl NativeCurrencyAmount {
    /// Maximum number of nyx that is still a valid amount.
    /// We consider the next 1000~ years period...
    pub const MAX_NAU: i128 = 23_000_000_000 * Self::conversion_factor();

    /// The maximum amount that is still valid.
    pub fn max() -> Self {
        Self(Self::MAX_NAU)
    }

    /// The minimum amount that is still valid.
    pub fn min() -> Self {
        Self(-Self::MAX_NAU)
    }

    pub const fn coin_as_nau() -> i128 {
        Self::conversion_factor()
    }

    /// The conversion factor is 10^8.
    const fn conversion_factor() -> i128 {
        let mut product = 1i128;
        let ten = 10i128;
        let mut i = 0;
        while i < 8 {
            product *= ten;
            i += 1;
        }
        product
    }

    /// Return the element that corresponds to 1 nau. Use in tests only.
    #[cfg(test)]
    pub fn one_nau() -> NativeCurrencyAmount {
        NativeCurrencyAmount(1i128)
    }

    /// Create an NativeCurrencyAmount object of the given number of whole coins.
    ///
    /// Note that the maximum number of whole coins is 4.2 billion which fits
    /// within a u64.
    pub const fn coins(num_whole_coins: u64) -> NativeCurrencyAmount {
        assert!(
            num_whole_coins <= 4_200_000_000,
            "Number of coins must be less than or equal to 4200000000"
        );
        let number: i128 = num_whole_coins as i128;
        Self(Self::conversion_factor() * number)
    }

    pub fn div_two(&mut self) {
        self.0 /= 2;
    }

    pub fn half(self) -> Self {
        Self(self.0 / 2)
    }

    /// Create a `coins` object for use in a UTXO
    pub fn to_native_coins(&self) -> Vec<Coin> {
        let dictionary = vec![Coin {
            type_script_hash: NativeCurrency.hash(),
            state: self.encode(),
        }];
        dictionary
    }

    /// Convert the amount to Nyks atomic units (nau) as a 64-bit floating
    /// point number. Note that this function loses precision!
    ///
    /// Quantities whose unit is nau are used for internal logic and are not to
    /// be used for user-facing displays.
    pub fn to_nau_f64(&self) -> f64 {
        self.0 as f64
    }

    /// Return the number of whole coins, rounded up to nearest integeer.
    /// Negative numbers are rounded up to nearest whole negative number such
    /// that -2.5 is rounded up to -2.
    ///
    /// # Panics
    ///
    /// - If the amount is outside of the range between minimum and
    ///   maximum allowed value.
    pub fn ceil_num_whole_coins(&self) -> i64 {
        assert!(
            *self <= Self::max() && *self >= Self::min(),
            "Amount must be contained between min and max"
        );

        // Manual implementation of `div_ceil`
        let conversion_factor = Self::conversion_factor();
        let term = i128::from(self.is_positive()) * (conversion_factor - 1);
        ((self.0 + term) / conversion_factor)
            .try_into()
            .expect("Any amount divided conversion factor must be a valid i64")
    }

    /// Convert the amount (of Nyks coins) to Nyks atomic units (nau).
    ///
    /// Quantities whose unit is nau are used for internal logic and are not to
    /// be used for user-facing displays.
    pub const fn to_nau(&self) -> i128 {
        self.0
    }

    /// Convert the number of Nyks atomic units (nau) to a
    /// `NativeCurrencyAmount`.
    pub const fn from_nau(nau: i128) -> Self {
        Self(nau)
    }

    /// Multiply the amount by a non-negative 32-bit number.
    ///
    /// Returns `None` in the case of overflow.
    pub fn checked_scalar_mul(&self, factor: u32) -> Option<Self> {
        let factor_as_i128 = i128::from(factor);
        self.0.checked_mul(factor_as_i128).map(NativeCurrencyAmount)
    }

    /// Multiply the amount by a non-negative 32-bit number.
    ///
    /// Crashes in case of overflow.
    pub fn scalar_mul(&self, factor: u32) -> Self {
        let factor_as_i128 = i128::from(factor);
        let (res, overflow) = self.0.overflowing_mul(factor_as_i128);
        assert!(!overflow, "Overflow on scalar multiplication not allowed.");
        NativeCurrencyAmount(res)
    }

    /// Multiply a coin amount with a fraction, in a lossy manner. Result is
    /// guaranteed to not exceed `self`.
    ///
    /// # Panics
    ///
    /// If the provided fraction is not between 0 and 1 (inclusive).
    pub fn lossy_f64_fraction_mul(&self, fraction: f64) -> NativeCurrencyAmount {
        assert!(
            (0.0..=1.0).contains(&fraction),
            "fraction must be between 0 and 1"
        );

        if self.is_negative() {
            return self.neg().lossy_f64_fraction_mul(fraction);
        }

        if fraction == 1.0 {
            return *self;
        }

        let value_as_f64 = self.to_nau_f64();
        let res = fraction * value_as_f64;
        let as_i128 = match res.to_i128() {
            Some(i) => i.clamp(0, self.0),
            None => 0_i128,
        };
        Self::from_nau(as_i128)
    }

    /// Generate an iterator for the running balance, updated with each item.
    ///
    /// Note that balances cannot be negative, so this method clamps at zero.
    pub fn scan_balance<I: IntoIterator<Item = Self> + Clone>(
        balance_update_itr: &I,
        initial_balance: Self,
    ) -> impl Iterator<Item = Self> + '_ {
        balance_update_itr.clone().into_iter().scan(
            initial_balance,
            |current_balance, new_update| {
                *current_balance = if new_update.is_negative() {
                    current_balance
                        .checked_add_negative(&new_update)
                        .unwrap_or(Self::zero())
                } else {
                    *current_balance + new_update
                };
                Some(*current_balance)
            },
        )
    }

    /// Add two [`NativeCurrencyAmount`]s, of which at most one is negative.
    ///
    /// The following cases generate `None`:
    ///  - adding two negative numbers
    ///  - adding two numbers whose sum is negative
    ///  - adding two numbers whose sum is greater than the max. amount of nau.
    pub fn checked_add_negative(&self, rhs: &Self) -> Option<Self> {
        if self.is_negative() && rhs.is_negative() {
            return None;
        }

        let value = self.0.checked_add(rhs.0)?;

        if value > Self::MAX_NAU || value.is_negative() {
            None
        } else {
            Some(Self(value))
        }
    }

    /// Return tasm code for pushing this amount to the stack.
    pub fn push_to_stack(&self) -> Vec<LabelledInstruction> {
        self.encode()
            .into_iter()
            .rev()
            .map(|b| triton_instr!(push b))
            .collect()
    }

    /// Display the `NativeCurrencyAmount` as a fractional number of coins in
    /// base 10 with `n` decimal digits after the comma.
    ///
    /// This method rounds the amount if necessary. To avoid losing precision,
    /// set `n` to `usize::MAX` or anything greater than or equal to 8, or just
    /// call [`Self::display_lossless`].
    pub fn display_n_decimals(&self, n: usize) -> String {
        if self.is_negative() {
            return "-".to_owned() + &self.neg().display_n_decimals(n);
        }

        let conversion_factor = Self::conversion_factor();

        let mut remainder = self.0;
        let integer_part = remainder / conversion_factor;
        remainder %= conversion_factor;

        let mut decimals = vec![integer_part];
        for _ in 0..n {
            remainder *= 10;
            let digit = remainder / conversion_factor;
            remainder %= conversion_factor;
            decimals.push(digit);
        }
        if (remainder * 10) / conversion_factor > 5 {
            let mut i = decimals.len() - 1;
            decimals[i] += 1;
            while decimals[i] == 10 {
                decimals[i] = 0;
                decimals[i - 1] += 1;
                if i == 1 {
                    break;
                }
                i -= 1;
            }
        }

        format!(
            "{}.{}",
            decimals[0],
            decimals.iter().skip(1).copied().join("")
        )
    }

    /// Display the `NativeCurrencyAmount` as a fractional number of coins in
    /// base 10 with enough decimal places to guarantee zero precision loss.
    pub fn display_lossless(&self) -> String {
        self.display_n_decimals(8)
    }
}

impl NativeCurrencyAmount {
    pub fn is_negative(&self) -> bool {
        self.0.is_negative()
    }

    pub fn is_positive(&self) -> bool {
        self.0.is_positive()
    }
}

impl GetSize for NativeCurrencyAmount {
    fn get_stack_size() -> usize {
        std::mem::size_of::<Self>()
    }

    fn get_heap_size(&self) -> usize {
        0
    }

    fn get_size(&self) -> usize {
        Self::get_stack_size() + GetSize::get_heap_size(self)
    }
}

impl Ord for NativeCurrencyAmount {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl Add for NativeCurrencyAmount {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl AddAssign for NativeCurrencyAmount {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs
    }
}

impl Sum for NativeCurrencyAmount {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        NativeCurrencyAmount(iter.map(|a| a.0).sum())
    }
}

impl Sub for NativeCurrencyAmount {
    type Output = NativeCurrencyAmount;

    fn sub(self, _rhs: Self) -> Self::Output {
        panic!("Cannot subtract `NativeCurrencyAmount`s; use `checked_sub` instead.")
    }
}

impl CheckedSub for NativeCurrencyAmount {
    /// Return Some(self-other) if the result is positive (or zero); otherwise
    /// return None.
    fn checked_sub(&self, v: &Self) -> Option<Self> {
        if !self.is_negative() && !v.is_negative() && self >= v {
            Some(NativeCurrencyAmount(self.0 - v.0))
        } else {
            None
        }
    }
}

impl CheckedAdd for NativeCurrencyAmount {
    /// Return Some(self+other) if (there is no i128-overflow and) the result is
    /// smaller than the maximum number of nau.
    fn checked_add(&self, v: &Self) -> Option<Self> {
        self.0.checked_add(v.0).and_then(|sum| {
            (-Self::MAX_NAU..=Self::MAX_NAU)
                .contains(&sum)
                .then_some(Self(sum))
        })
    }
}

impl Neg for NativeCurrencyAmount {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl PartialEq for NativeCurrencyAmount {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PartialOrd for NativeCurrencyAmount {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Zero for NativeCurrencyAmount {
    fn zero() -> Self {
        NativeCurrencyAmount(0)
    }

    fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

#[derive(Debug, Copy, Clone)]
pub enum FloatConversionError {
    NaN,
    Infinity,
    Negative,
    Overflow,
    InvalidAmount,
}

impl TryFrom<f64> for NativeCurrencyAmount {
    type Error = FloatConversionError;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        let i = if value.is_nan() {
            Err(FloatConversionError::NaN)
        } else if value.is_infinite() {
            Err(FloatConversionError::Infinity)
        } else if value < 0.0 {
            Err(FloatConversionError::Negative)
        } else if value > Self::MAX_NAU as f64 {
            Err(FloatConversionError::Overflow)
        } else {
            Ok(value as i128)
        }?;
        Ok(Self::from_nau(i))
    }
}

impl NativeCurrencyAmount {
    /// Convert a decimal string representation of a not necessarily integral
    /// amount of native currency into a `NativeCurrencyAmount` object.
    pub fn coins_from_str(s: &str) -> Result<Self, anyhow::Error> {
        let re = Regex::new(r#"^(-?)([0-9]*)\.?([0-9]*)$"#).unwrap();
        let Some((_full, substrings)) = re.captures(s).map(|c| c.extract::<3>()) else {
            bail!("invalid amount: unmatched regex");
        };
        let sign = match substrings[0] {
            "-" => num_bigint::Sign::Minus,
            "" => num_bigint::Sign::Plus,
            _ => bail!("invalid amount: matched but unrecognized sign symbol"),
        };
        let integer_part = if substrings[1].is_empty() {
            BigInt::zero()
        } else {
            BigInt::from_str(substrings[1])?
        };
        let fractional_part = if substrings[2].is_empty() {
            BigInt::zero()
        } else {
            BigInt::from_str(substrings[2])?
        };
        let power = substrings[2].len();
        let ten = BigInt::from(10_u8);
        let mut decimal_shift = BigInt::from(1_u8);
        for _ in 0..power {
            decimal_shift *= ten.clone();
        }
        let numerator = integer_part * decimal_shift.clone() + fractional_part;
        let nau = if numerator.is_zero() {
            BigInt::zero()
        } else {
            let denominator = decimal_shift;
            let conversion_factor = BigInt::from_i128(Self::conversion_factor()).unwrap();
            let nau_rational = BigRational::new(numerator * conversion_factor, denominator).round();
            match sign {
                num_bigint::Sign::Minus => -nau_rational.numer(),
                num_bigint::Sign::Plus => nau_rational.numer().to_owned(),
                num_bigint::Sign::NoSign => unreachable!(),
            }
        };

        let max_nau = BigInt::from(Self::MAX_NAU);
        ensure!(nau >= -max_nau.clone(), "amount of Nyks coins too small");
        ensure!(nau <= max_nau, "amount of Nyks coins too large");

        i128::try_from(nau)
            .map(Self)
            .map_err(|e| anyhow!("invalid amount of Nyks coins: {e:?}"))
    }
}

impl Display for NativeCurrencyAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_n_decimals(8))
    }
}
