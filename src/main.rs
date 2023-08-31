use aes::cipher::generic_array::GenericArray;
use aes_modes::{Aes128CBC, Aes128CTR};
use hex_literal::hex;

const BLOCK_SIZE: usize = 16;

fn decrypt_cbc(key: &[u8], iv: &[u8], cipher_text: &[u8]) -> String {
    let aes_cbc = Aes128CBC::new(GenericArray::from_slice(key), GenericArray::from_slice(&iv));
    let plain_text = aes_cbc.decrypt(cipher_text);
    String::from_utf8_lossy(&plain_text).into_owned()
}

fn decrypt_ctr(key: &[u8], iv: &[u8], cipher_text: &[u8]) -> String {
    let aes_ctr = Aes128CTR::new(GenericArray::from_slice(key), GenericArray::from_slice(&iv));
    let plain_text = aes_ctr.decrypt(cipher_text);
    String::from_utf8_lossy(&plain_text).into_owned()
}

fn main() {
    let key = hex!("140b41b22a29beb4061bda66b6747e14");
    let input = hex!(
        "4ca00ff4c898d61e1edbf1800618fb28
         28a226d160dad07883d04e008a7897ee
         2e4b7465d5290d0c0e6c6822236e1daa
         fb94ffe0c5da05d9476be028ad7c1d81"
    );
    let plain_text = decrypt_cbc(&key, &input[..BLOCK_SIZE], &input[BLOCK_SIZE..]);
    println!("{}", plain_text);

    let input = hex!(
        "5b68629feb8606f9a6667670b75b38a5
         b4832d0f26e1ab7da33249de7d4afc48
         e713ac646ace36e872ad5fb8a512428a
         6e21364b0c374df45503473c5242a253"
    );
    let plain_text = decrypt_cbc(&key, &input[..BLOCK_SIZE], &input[BLOCK_SIZE..]);
    println!("{}", plain_text);

    let key = hex!("36f18357be4dbd77f050515c73fcf9f2");
    let input = hex!(
        "69dda8455c7dd4254bf353b773304eec
         0ec7702330098ce7f7520d1cbbb20fc3
         88d1b0adb5054dbd7370849dbf0b88d3
         93f252e764f1f5f7ad97ef79d59ce29f
         5f51eeca32eabedd9afa9329"
    );
    let plain_text = decrypt_ctr(&key, &input[..BLOCK_SIZE], &input[BLOCK_SIZE..]);
    println!("{}", plain_text);

    let input = hex!(
        "770b80259ec33beb2561358a9f2dc617
         e46218c0a53cbeca695ae45faa8952aa
         0e311bde9d4e01726d3184c34451"
    );
    let plain_text = decrypt_ctr(&key, &input[..BLOCK_SIZE], &input[BLOCK_SIZE..]);
    println!("{}", plain_text);
}
