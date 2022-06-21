use std::io::Read;
use std::net::TcpListener;
use chacha20::ChaCha20;
use rsa::pkcs8::der::Document;
use rsa::pkcs8::Error::PublicKey;
use rsa::pkcs8::{DecodePublicKey, PublicKeyDocument};
use rsa::RsaPublicKey;

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
    let listener = TcpListener::bind("127.0.0.1:7230")?;
    println!("Waiting for connection on local port 7230...");
    let (mut stream, address) = listener.accept()?;
    println!("Connected to {}.", address);

    let rng = rand::thread_rng();
    // random generator

    let mut nonce = [0u8; 12];
    let mut length = [0u8; 8];
    stream.read_exact(&mut nonce)?;
    stream.read_exact(&mut length)?;
    let length = u64::from_le_bytes(length) as usize;
    let mut buffer = vec![0u8; length];
    stream.read_exact(&mut buffer)?;

    let mut cipher = ChaCha20::new(&KEY.into(), &nonce.into());
    cipher.apply_keystream(&mut buffer);
    let public_key = RsaPublicKey::from_public_key_der(buffer.as_ref()).unwrap();
    // retrieve the public key

    Ok(())
}