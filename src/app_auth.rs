//! GitHub App authentication: an RS256 JWT for the App itself, and listing
//! every installation with its permissions.
//!
//! An installation token covers a single account. Seeing every repository the
//! App can reach therefore means asking the App (JWT) for all installations and
//! minting a token for each one.
use crate::github::GitHub;
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// The JWT for `app_id`, valid from 60 s before `now` (clock skew) for 9 minutes.
/// GitHub rejects App JWTs that live longer than 10 minutes.
pub fn app_jwt(app_id: &str, private_key_pem: &str, now: i64) -> Result<String> {
    let key = parse_key(private_key_pem)?;
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = URL_SAFE_NO_PAD.encode(json!({ "iat": now - 60, "exp": now + 540, "iss": app_id }).to_string());
    let signing_input = format!("{header}.{claims}");
    let mut sig = vec![0; key.public().modulus_len()];
    key.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), signing_input.as_bytes(), &mut sig)
        .map_err(|_| anyhow::anyhow!("signing the App JWT failed"))?;
    Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig)))
}

/// Accept the PKCS#1 key GitHub hands out and PKCS#8 (`openssl genpkey`).
fn parse_key(pem: &str) -> Result<RsaKeyPair> {
    let (label, der) = pem_der(pem)?;
    match label.as_str() {
        "RSA PRIVATE KEY" => RsaKeyPair::from_der(&der).map_err(|e| anyhow::anyhow!("invalid PKCS#1 App private key: {e}")),
        "PRIVATE KEY" => RsaKeyPair::from_pkcs8(&der).map_err(|e| anyhow::anyhow!("invalid PKCS#8 App private key: {e}")),
        other => bail!("unsupported App private key type {other:?}; expected an RSA private key"),
    }
}

fn pem_der(pem: &str) -> Result<(String, Vec<u8>)> {
    let pem = pem.trim();
    let first = pem.lines().next().unwrap_or_default();
    let label = first
        .strip_prefix("-----BEGIN ")
        .and_then(|l| l.strip_suffix("-----"))
        .context("the App private key is not PEM (no BEGIN line)")?
        .to_string();
    let end = format!("-----END {label}-----");
    let body: String = pem.lines().skip(1).take_while(|l| *l != end).collect::<Vec<_>>().concat();
    if !pem.lines().any(|l| l == end) {
        bail!("the App private key has no {end} line");
    }
    Ok((label, STANDARD.decode(body.trim()).context("the App private key is not valid base64")?))
}

#[derive(Debug, Clone)]
pub struct Installation {
    pub id: u64,
    /// The account login the installation belongs to.
    pub account: String,
    /// `all` or `selected`.
    pub repository_selection: String,
    /// Permission name → `read` or `write`.
    pub permissions: BTreeMap<String, String>,
}

impl Installation {
    fn from_json(v: &Value) -> Option<Self> {
        Some(Installation {
            id: v["id"].as_u64()?,
            account: v["account"]["login"].as_str()?.to_string(),
            repository_selection: v["repository_selection"].as_str().unwrap_or("selected").to_string(),
            permissions: permissions(&v["permissions"]),
        })
    }
}

fn permissions(v: &Value) -> BTreeMap<String, String> {
    v.as_object().map(|m| m.iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect()).unwrap_or_default()
}

/// Every installation of the App. `app` must be authenticated with the App JWT.
pub async fn installations(app: &GitHub) -> Result<Vec<Installation>> {
    let raw = app.paginate_all("/app/installations?per_page=100", None, 50).await.context("listing App installations")?;
    raw.iter().map(|v| Installation::from_json(v).with_context(|| format!("unexpected installation object: {v}"))).collect()
}

/// A token for one installation, and the permissions GitHub actually granted it.
pub async fn installation_token(app: &GitHub, id: u64) -> Result<(String, BTreeMap<String, String>)> {
    let v = app.post(&format!("/app/installations/{id}/access_tokens"), &json!({})).await?;
    let token = v["token"].as_str().with_context(|| format!("installation {id}: no token in the response"))?;
    Ok((token.to_string(), permissions(&v["permissions"])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::tests::{json_response, mock};
    use ring::signature::{UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};

    /// A throwaway key generated for this test run; nothing is committed.
    fn test_key(args: &[&str]) -> Option<String> {
        let out = std::process::Command::new("openssl").args(args).output().ok()?;
        out.status.success().then(|| String::from_utf8(out.stdout).unwrap())
    }

    fn check_jwt(pem: &str) {
        let jwt = app_jwt("12345", pem, 1_000_000).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims, json!({ "iat": 999_940, "exp": 1_000_540, "iss": "12345" }));
        let key = parse_key(pem).unwrap();
        let public = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public().as_ref().to_vec());
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        public.verify(signing_input.as_bytes(), &URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).expect("signature verifies");
    }

    #[test]
    fn jwt_signs_with_pkcs8_and_pkcs1_keys() {
        let Some(pkcs8) = test_key(&["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]) else {
            eprintln!("openssl not available; skipping");
            return;
        };
        assert!(pkcs8.starts_with("-----BEGIN PRIVATE KEY-----"));
        check_jwt(&pkcs8);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.pem");
        std::fs::write(&path, &pkcs8).unwrap();
        let pkcs1 = test_key(&["rsa", "-in", path.to_str().unwrap(), "-traditional"]).expect("convert to PKCS#1");
        assert!(pkcs1.starts_with("-----BEGIN RSA PRIVATE KEY-----"));
        check_jwt(&pkcs1);
    }

    #[test]
    fn rejects_non_rsa_or_malformed_keys() {
        assert!(app_jwt("1", "not a key", 0).is_err());
        assert!(app_jwt("1", "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----", 0).is_err());
        assert!(app_jwt("1", "-----BEGIN PRIVATE KEY-----\nAAAA\n", 0).is_err());
    }

    #[tokio::test]
    async fn lists_installations_and_mints_tokens() {
        let (gh, finish) = mock(vec![
            json_response(
                r#"[{"id":1,"account":{"login":"me"},"repository_selection":"selected","permissions":{"contents":"write","issues":"write"}}]"#,
                "Link: <{base}/app/installations?per_page=100&page=2>; rel=\"next\"\r\n",
            ),
            json_response(r#"[{"id":2,"account":{"login":"Org"},"repository_selection":"all","permissions":{"contents":"read"}}]"#, ""),
            json_response(r#"{"token":"ghs_FAKEFAKEFAKE","permissions":{"contents":"read","metadata":"read"}}"#, ""),
        ]);
        let inst = installations(&gh).await.unwrap();
        assert_eq!(inst.iter().map(|i| (i.id, i.account.as_str())).collect::<Vec<_>>(), [(1, "me"), (2, "Org")]);
        assert_eq!(inst[0].permissions["contents"], "write");
        assert_eq!(inst[1].repository_selection, "all");
        let (token, perms) = installation_token(&gh, 2).await.unwrap();
        assert_eq!(token, "ghs_FAKEFAKEFAKE");
        assert_eq!(perms["contents"], "read");
        let requests = finish();
        assert!(requests[2].starts_with("POST /app/installations/2/access_tokens HTTP/1.1"));
    }
}
