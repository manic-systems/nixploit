//! Validated SHA-256 values shared by archive checks and evidence fingerprints.

use std::{
   fmt::{Display, Formatter, Result as FormatResult},
   io::Read,
   str::{FromStr, from_utf8},
};

use hmac_sha256::Hash;
use misstep::{Report, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
/// A SHA-256 digest with its fixed size enforced by the type.
pub struct Sha256([u8; 32]);

impl Sha256 {
   /// Hashes a stream, failing once it yields more than `limit` bytes.
   pub fn read_from<Reader>(reader: &mut Reader, limit: u64) -> Result<Self, Report>
   where
      Reader: Read,
   {
      let mut hasher = Hash::new();
      let mut buffer = vec![0; 64 * 1024].into_boxed_slice();
      let mut size = 0;

      loop {
         let count = reader.read(&mut buffer)?;

         if count == 0 {
            break;
         }

         size += u64::try_from(count)?;
         ensure!(size <= limit, "Hashed input exceeds {} bytes", limit);
         hasher.update(&buffer[..count]);
      }

      Ok(Self(hasher.finalize()))
   }
}

impl From<[u8; 32]> for Sha256 {
   fn from(bytes: [u8; 32]) -> Self {
      Self(bytes)
   }
}

impl FromStr for Sha256 {
   type Err = Report;

   fn from_str(value: &str) -> Result<Self, Self::Err> {
      if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
         return Err(Report::msg("SHA-256 digest must be 64 ASCII hex digits"));
      }

      let mut bytes = [0; 32];
      let (pairs, _remainder) = value.as_bytes().as_chunks::<2>();

      for (byte, pair) in bytes.iter_mut().zip(pairs) {
         *byte = u8::from_str_radix(from_utf8(pair)?, 16)?;
      }

      Ok(Self(bytes))
   }
}

impl Display for Sha256 {
   #[expect(
      clippy::renamed_function_params,
      reason = "The repository requires names longer than the trait's f parameter"
   )]
   fn fmt(&self, formatter: &mut Formatter<'_>) -> FormatResult {
      for byte in self.0 {
         write!(formatter, "{byte:02x}")?;
      }

      Ok(())
   }
}

impl Serialize for Sha256 {
   fn serialize<Encoder>(&self, serializer: Encoder) -> Result<Encoder::Ok, Encoder::Error>
   where
      Encoder: Serializer,
   {
      serializer.collect_str(self)
   }
}

impl<'de> Deserialize<'de> for Sha256 {
   fn deserialize<Decoder>(deserializer: Decoder) -> Result<Self, Decoder::Error>
   where
      Decoder: Deserializer<'de>,
   {
      String::deserialize(deserializer)?
         .parse()
         .map_err(Decoder::Error::custom)
   }
}
