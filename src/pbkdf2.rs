use anyhow::Result;
use pbkdf2::password_hash::PasswordHash;
use pbkdf2::password_hash::PasswordHasher;
use pbkdf2::password_hash::PasswordVerifier;
use pbkdf2::password_hash::SaltString;
use pbkdf2::Pbkdf2;

pub fn pbkdf2_simple(pass: &str) -> Result<String> {
    let salt = SaltString::generate(rand::thread_rng());
    let mut params = pbkdf2::Params::default();
    if cfg!(test) {
        // default is unusably slow in test (debug configuration), >30 seconds (2024)
        params.rounds = 1000;
    } else {
        assert!(params.rounds >= 600_000);
    }
    let hash = Pbkdf2
        .hash_password_customized(pass.as_bytes(), None, None, params, &salt)
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
