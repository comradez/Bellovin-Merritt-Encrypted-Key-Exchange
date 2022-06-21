use std::io::Write;
use std::net::TcpStream;
use rsa::{PublicKey, RsaPublicKey, RsaPrivateKey};
use rsa::pkcs8::{LineEnding, EncodePublicKey};
use chacha20::{ChaCha20};
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use rand::random;
use rsa::pkcs8::der::Document;

const KEY: [u8; 32] = [
    0x74u8, 0xa8u8, 0x25u8, 0xaeu8,
    0xd5u8, 0xa0u8, 0xb3u8, 0x68u8,
    0x28u8, 0x3bu8, 0xdeu8, 0x46u8,
    0x8cu8, 0x31u8, 0xd1u8, 0x40u8,
    0x74u8, 0xa8u8, 0x25u8, 0xaeu8,
    0xd5u8, 0xa0u8, 0xb3u8, 0x68u8,
    0x28u8, 0x3bu8, 0xdeu8, 0x46u8,
    0x8cu8, 0x31u8, 0xd1u8, 0x40u8
];

fn main() -> std::io::Result<()> {

    let mut stream = TcpStream::connect("127.0.0.1:7230")?;
    println!("Connected to server on local port 7230...");

    // Phase 1
    let mut rng = rand::thread_rng();
    // random generator

    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let public_key = RsaPublicKey::from(&private_key);
    // generate public & private key

    let nonce: [u8; 12] = random();
    let mut cipher = ChaCha20::new(&KEY.into(), &nonce.into());
    let mut buffer = public_key
        .to_public_key_der()
        .unwrap()
        .as_ref()
        .to_vec();
    cipher.apply_keystream(&mut buffer);
    // cipher with ChaCha20 stream cipher

    stream.write_all(&nonce)?;
    stream.write_all(&buffer.len().to_le_bytes())?;
    stream.write_all(&buffer)?;
    // send to server

    Ok(())
}