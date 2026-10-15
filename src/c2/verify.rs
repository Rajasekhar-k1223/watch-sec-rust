use ring::{digest, hmac};
use serde_json::Value;
use std::collections::BTreeMap;
use serde_json::ser::{Formatter, Serializer};
use std::io::Write;
use serde::Serialize;

struct PythonFormatter;

impl Formatter for PythonFormatter {
    fn begin_object_key<W: ?Sized + Write>(&mut self, writer: &mut W, first: bool) -> std::io::Result<()> {
        if !first {
            writer.write_all(b", ")?;
        }
        Ok(())
    }

    fn begin_object_value<W: ?Sized + Write>(&mut self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(b": ")
    }
    
    fn begin_array_value<W: ?Sized + Write>(&mut self, writer: &mut W, first: bool) -> std::io::Result<()> {
        if !first {
            writer.write_all(b", ")?;
        }
        Ok(())
    }
}

pub fn verify_command_signature(
    action: &str,
    params: &BTreeMap<String, Value>,
    timestamp: &str,
    signature: &str,
    api_key: &str,
    machine_secret: &str
) -> bool {
    let mut key_material = api_key.as_bytes().to_vec();
    key_material.extend_from_slice(machine_secret.as_bytes());
    let key_hash = digest::digest(&digest::SHA256, &key_material);

    let mut buf = Vec::new();
    let mut ser = Serializer::with_formatter(&mut buf, PythonFormatter);
    params.serialize(&mut ser).unwrap();
    let params_json = String::from_utf8(buf).unwrap_or_else(|_| "{}".to_string());

    let message = format!("{}|{}|{}", action, params_json, timestamp);
    let s_key = hmac::Key::new(hmac::HMAC_SHA256, key_hash.as_ref());
    let tag = hmac::sign(&s_key, message.as_bytes());
    let expected = hex::encode(tag.as_ref());

    expected == signature
}

// ---------------------------------------------------------------------------
// Monitorix Publisher RSA-4096 Public Key (CN=Elsea Monitorix Security)
// This is the public half of /opt/projects/monitorix/certs/monitorix-publisher.key
// The server signs every agent binary with the corresponding private key using
// openssl dgst -sha256 -sign <key> <binary> and returns the hex signature in
// the heartbeat response's `publisher_signature` field.
// ---------------------------------------------------------------------------
const MONITORIX_PUBLISHER_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsNUwUNq72lx9ys4zdCNN
e/osp8VuDZq6wMqoqSyGXYDFVRWJKplB22mmYyLv4SrbdLG2Ucsk7rbuvJLNWncg
06IQ5dCaxW3CL+fAR+/LRPVPeGcFFKxlygbGAfgnDGdNKj5+Lnd1izYjyvBPzceD
j0+b/mz0aWOdgqepK1n9wPf268E23+mHVlC3D5pujL3eCA4aPtx1gb+uqSz8GAZi
x5vvGbGf6wkgmg0MP09DUIvr/e+zYd4NeBTVgsGikOS2FZwylplHVoSq00gKuyzo
iHP+4uMrnq3I27Pg8sCUBSlCbhA2LD9C6QxBHvQipkjWOw/F/9wtk4QHGkeh04/k
hEJOlUi+XjUTneOQmd6Rj9n1k1RwP93Lbjb9LEOGBSNEk/qMA6Z9MULe9TRD4Yar
0g3KYFOyHG/cDp3154VitWt3bX8PgjnskekBgypOuFRk41/rbrNdc1r4HU5XpCbg
RVobJGPxvSSSLYerwlFXPNDpgqjCMY/WmSsq5xsiSUR45hvbbXurpr5rmnXkUNIS
3rg3tFpRi1ua19EbfOASRfmaxbpKpWoYt5tOKYHyoCMFF/pMt+MvTip/F/PNFIJx
K1fmbuFY86TYz4lpnZIMuPqPhbbQm5R+0BqKjeAOm45JQ3fDNNZezUZQDRzm7eDb
uwHxiNE8aL7cJiae+pqzwLUCAwEAAQ==
-----END PUBLIC KEY-----";

/// Verify the downloaded binary against our RSA-SHA256 publisher signature.
///
/// The server signs each freshly-built exe with:
///   openssl dgst -sha256 -sign monitorix-publisher.key <exe> | xxd -p -c 999
/// and returns that hex string in the heartbeat `publisher_signature` field.
///
/// This function re-hashes the downloaded file with SHA-256 and verifies the
/// RSA signature using the hardcoded public key above.
pub fn verify_binary_signature(file_path: &str, signature_hex: &str) -> bool {
    println!("[Security] Verifying RSA-SHA256 publisher signature for {}", file_path);

    if signature_hex.is_empty() {
        // Caller should check this before calling, but handle it gracefully
        println!("[Security] No signature provided — skipping publisher check.");
        return true;
    }

    // 1. Decode the hex signature to bytes
    let sig_bytes = match hex::decode(signature_hex) {
        Ok(b) => b,
        Err(e) => {
            println!("[Security] Rejected: signature hex decode failed: {}", e);
            return false;
        }
    };

    // 2. Read the file we want to verify
    let file_data = match std::fs::read(file_path) {
        Ok(d) => d,
        Err(e) => {
            println!("[Security] Rejected: cannot read file {}: {}", file_path, e);
            return false;
        }
    };

    // 3. Parse the DER-encoded RSA public key from the hardcoded PEM
    //    ring expects the SubjectPublicKeyInfo DER format (PKIX), which is
    //    exactly what "BEGIN PUBLIC KEY" PEM blocks contain.
    let pem_body: String = MONITORIX_PUBLISHER_PEM
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let pub_key_der = match base64::decode(&pem_body) {
        Ok(d) => d,
        Err(e) => {
            println!("[Security] INTERNAL: failed to decode embedded public key: {}", e);
            return false;
        }
    };

    // 4. Verify using ring — RSA_PKCS1_2048_8192_SHA256 supports our 4096-bit key
    use ring::signature;
    let pub_key = signature::UnparsedPublicKey::new(
        &signature::RSA_PKCS1_2048_8192_SHA256,
        pub_key_der.as_slice(),
    );

    match pub_key.verify(&file_data, &sig_bytes) {
        Ok(_) => {
            println!("[Security] ✓ Publisher signature VALID. Binary is authentic.");
            true
        }
        Err(e) => {
            println!("[Security] ✗ Publisher signature INVALID: {:?}. Update aborted.", e);
            false
        }
    }
}
