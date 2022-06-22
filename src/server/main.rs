extern crate core;

use std::net::TcpListener;
use rsa::pkcs8::DecodePublicKey;
use rsa::{PaddingScheme, PublicKey, RsaPublicKey};
use utils::{recv, send};

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

    let mut rng = rand::thread_rng();
    let listener = TcpListener::bind("127.0.0.1:7230")?;
    println!("Waiting for connection on local port 7230...");
    let (mut stream, address) = listener.accept()?;
    println!("Connected to {}.", address);

    // Phase 1
    let buffer = recv(&KEY, &mut stream)?;
    let public_key = RsaPublicKey::from_public_key_der(buffer.as_ref()).unwrap();
    println!("Public key received from {}.", address);
    // retrieve P(E_A) and decrypt, obtaining E_A

    // Phase 2
    let secret_key: [u8; 32] = rand::random();
    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    let encrypted = public_key.encrypt(&mut rng, padding, &secret_key).unwrap();
    send(&KEY, encrypted.as_ref(), &mut stream)?;
    println!("Secret key sent to {}.", address);
    // generate secret key R and send P(E_A(R)) to client

    // Phase 4
    let challenge1 = recv(secret_key.as_ref(), &mut stream)?;
    let challenge2: [u8; 32] = rand::random();
    let challenge = [challenge1.as_ref(), challenge2.as_ref()].concat();
    send(secret_key.as_ref(), challenge.as_ref(), &mut stream)?;
    // receive R(challenge_A), decrypt to obtain challenge_B, and send R(challenge_A, challenge_B) back to client

    // Phase 5
    let challenge2_recv = recv(secret_key.as_ref(), &mut stream)?;
    if challenge2_recv == challenge2 {
        println!("Login successful.");
    } else {
        panic!("Challenge B illegal.");
    }

    Ok(())
}