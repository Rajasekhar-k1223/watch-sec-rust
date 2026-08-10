use ring::{hmac, digest};

fn main() {
    let secret = "my_secret_key_which_is_long_enough_for_testing";
    let body = "some_body";
    let timestamp = "123456789";

    let signing_key = digest::digest(&digest::SHA256, secret.as_bytes());
    let key = hmac::Key::new(hmac::HMAC_SHA256, signing_key.as_ref());
    let msg = format!("{}|{}", body, timestamp);
    let signature = hmac::sign(&key, msg.as_bytes());
    println!("Rust Signature: {}", hex::encode(signature.as_ref()));
}
