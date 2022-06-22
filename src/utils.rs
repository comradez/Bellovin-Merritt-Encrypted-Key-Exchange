use std::io::{Read, Write};
use std::net::TcpStream;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};

pub fn send(key: &[u8], data: &[u8], stream: &mut TcpStream) -> std::io::Result<()> {
    let nonce: [u8; 12] = rand::random();
    stream.write_all(&nonce)?;
    // generate and send nonce

    let mut cipher = ChaCha20::new(key.into(), &nonce.into());
    let mut buffer = data.to_vec();
    cipher.apply_keystream(&mut buffer);
    stream.write_all(&buffer.len().to_be_bytes())?;
    stream.write_all(&buffer)?;
    // cipher buffer and send (length + self)

    Ok(())
}

pub fn recv(key: &[u8], stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    stream.read_exact(&mut nonce)?;
    // Recv nonce [fixed size]

    let mut length = [0u8; 8];
    stream.read_exact(&mut length)?;
    // Recv buffer length [64 bits]

    let length = u64::from_be_bytes(length);
    let mut buffer = vec![0u8; length as usize];
    stream.read_exact(&mut buffer)?;
    // Recv buffer

    let mut cipher = ChaCha20::new(key.into(), &nonce.into());
    cipher.apply_keystream(&mut buffer);
    // decipher buffer

    Ok(buffer)
}