use argon2::password_hash::Error;
use argon2::{password_hash::SaltString, PasswordVerifier};
use argon2::{Argon2, PasswordHash, PasswordHasher};
use rand_core::OsRng;

/// Simple API for computing a hash from a password.
pub fn verify(hashed: &str, password: &str) -> Result<bool, Error> {
    let parsed_hash = PasswordHash::new(hashed)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Compute this password hashing function against the provided password using the parameters from the provided password hash and see if the computed output matches.
pub fn hash(password: &str) -> Result<String, Error> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}
