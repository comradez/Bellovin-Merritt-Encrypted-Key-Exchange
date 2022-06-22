extern crate core;

use std::net::TcpStream;
use rsa::{RsaPublicKey, RsaPrivateKey, PaddingScheme};
use rsa::pkcs8::EncodePublicKey;
use utils::{send, recv};

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
    let mut stream = TcpStream::connect("127.0.0.1:7230")?;
    println!("Connected to server on 127.0.0.1:7230.");

    // Phase 1
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = RsaPublicKey::from(&private_key);
    // generate (D_A, E_A)

    let message = public_key.to_public_key_der().unwrap();
    send(KEY.as_ref(), message.as_ref(), &mut stream)?;
    println!("Public key sent to 127.0.0.1:7230.");
    // send P(E_A) to server

    // Phase 2
    let encrypted = recv(KEY.as_ref(), &mut stream)?;
    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    let secret_key = private_key.decrypt(padding, encrypted.as_ref()).unwrap();
    println!("Secret key received from 127.0.0.1:7230.");
    // receive P(E_A(R)) from server and decrypt to obtain R

    // Phase 3
    let challenge1: [u8; 32] = rand::random();
    send(secret_key.as_ref(), challenge1.as_ref(), &mut stream)?;
    println!("Challenge A sent to 127.0.0.1:7230");
    // generate challenge_A, send R(challenge_A) to server

    // Phase 5
    let challenge_recv = recv(secret_key.as_ref(), &mut stream)?;
    if &challenge_recv[0 .. 32] == &challenge1 {
        let challenge2 = &challenge_recv[32 .. 64];
        send(secret_key.as_ref(), challenge2, &mut stream)?;
        println!("Login successful.");
    } else {
        panic!("Challenge A illegal.");
    }
    Ok(())
}