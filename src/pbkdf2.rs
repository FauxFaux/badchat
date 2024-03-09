use anyhow::Result;
use pbkdf2::password_hash::PasswordHash;
use pbkdf2::password_hash::PasswordHasher;
use pbkdf2::password_hash::PasswordVerifier;
use pbkdf2::password_hash::SaltString;
use pbkdf2::Pbkdf2;

pub fn pbkdf2_simple(pass: &str) -> Result<String> {
    let salt = SaltString::generate(rand::thread_rng());
    let hash = Pbkdf2
        .hash_password_simple(pass.as_bytes(), &salt)
        .map_err(|e| anyhow!("{:?}", e))?;
    Ok(hash.to_string())
}

pub fn pbkdf2_check(pass: &str, hash: &str) -> Result<bool> {
    let hash = PasswordHash::new(hash).map_err(|e| anyhow!("{:?}", e))?;
    Ok(Pbkdf2.verify_password(pass.as_bytes(), &hash).is_ok())
}

#[test]
fn test_pbkdf2() -> Result<()> {
    let pass = "password";
    let hash = pbkdf2_simple(pass)?;
    assert!(pbkdf2_check(pass, &hash)?);
    assert!(!pbkdf2_check("wrong", &hash)?);
    Ok(())
}
