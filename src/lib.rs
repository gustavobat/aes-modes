//! This crate contains the implementation of AES-128 in CBC and CTR modes.
//! The implementation is based on the `aes` crate.
//! The structs `Aes128CBC` and `Aes128CTR` implement the respective modes.
//! The `encrypt` and `decrypt` methods are used to encrypt and decrypt an
//! u8 slice. They return owned objects to preserve the original data.

use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128, Block,
};

/// AES-128 in CBC mode with PKCS5 padding scheme
pub struct Aes128CBC {
    aes: Aes128,
    iv: Block,
}

impl Aes128CBC {
    pub fn new(key: &Block, iv: &Block) -> Self {
        Self {
            aes: Aes128::new(key),
            iv: *iv,
        }
    }

    pub fn set_key(&mut self, key: &Block) {
        self.aes = Aes128::new(key);
    }

    pub fn set_iv(&mut self, iv: &Block) {
        self.iv = *iv;
    }

    /// Returns an owned vector of bytes with PKCS5 padding applied
    fn apply_pkcs5_padding(plain_text: &[u8]) -> Vec<u8> {
        let padding = (16 - plain_text.len() % 16) as u8;
        plain_text
            .iter()
            .chain(std::iter::repeat(&padding).take(padding as usize))
            .copied()
            .collect()
    }

    pub fn encrypt(&self, plain_text: &[u8]) -> Vec<u8> {
        let padded_plain_text = Self::apply_pkcs5_padding(plain_text);
        let mut blocks: Vec<Block> = padded_plain_text
            .chunks(16)
            .map(GenericArray::clone_from_slice)
            .collect();
        self.encrypt_blocks(blocks.iter_mut())
    }

    fn encrypt_blocks<'a, I>(&self, blocks: I) -> Vec<u8>
    where
        I: Iterator<Item = &'a mut Block>,
    {
        let mut prev = self.iv;
        let mut cipher_text = Vec::new();

        for block in blocks {
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= prev[i];
            }
            self.aes.encrypt_block(block);
            prev = *block;
            cipher_text.extend_from_slice(block);
        }
        cipher_text
    }

    pub fn decrypt(&self, cipher_text: &[u8]) -> Vec<u8> {
        let mut blocks: Vec<Block> = cipher_text
            .chunks(16)
            .map(GenericArray::clone_from_slice)
            .collect();
        self.decrypt_blocks(blocks.iter_mut())
    }

    fn decrypt_blocks<'a, I>(&self, blocks: I) -> Vec<u8>
    where
        I: Iterator<Item = &'a mut Block>,
    {
        let mut prev = self.iv;
        let mut plain_text = Vec::new();

        for block in blocks {
            let new_prev = *block;
            self.aes.decrypt_block(block);
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= prev[i];
            }
            prev = new_prev;
            plain_text.extend_from_slice(block);
        }
        // Remove padding and return
        let padding = plain_text[plain_text.len() - 1];
        plain_text.truncate(plain_text.len() - padding as usize);
        plain_text
    }
}

/// AES-128 in CTR mode with PKCS5 padding scheme
pub struct Aes128CTR {
    aes: Aes128,
    iv: Block,
}

impl Aes128CTR {
    pub fn new(key: &Block, iv: &Block) -> Self {
        Self {
            aes: Aes128::new(key),
            iv: *iv,
        }
    }

    pub fn set_key(&mut self, key: &Block) {
        self.aes = Aes128::new(key);
    }

    pub fn set_iv(&mut self, iv: &Block) {
        self.iv = *iv;
    }

    pub fn encrypt(&self, cipher_text: &[u8]) -> Vec<u8> {
        let mut extension = 0;
        let mut blocks: Vec<Block> = cipher_text
            .chunks(16)
            .map(|block| {
                if block.len() < 16 {
                    extension = 16 - block.len();
                    let mut new_block = Block::default();
                    new_block[..block.len()].copy_from_slice(block);
                    new_block
                } else {
                    GenericArray::clone_from_slice(block)
                }
            })
            .collect();
        let mut result = self.encrypt_blocks(blocks.iter_mut());
        result.truncate(result.len() - extension);
        result
    }

    fn encrypt_blocks<'a, I>(&self, blocks: I) -> Vec<u8>
    where
        I: Iterator<Item = &'a mut Block>,
    {
        let (nonce, counter) = self.iv.split_at(8);
        let mut counter_u64 = u64::from_be_bytes(counter[..8].try_into().unwrap());
        let mut plain_text = Vec::new();

        for block in blocks {
            // encrypt counter then XOR with block
            let mut counter_block = Block::default();
            counter_block[..8].copy_from_slice(nonce);
            counter_block[8..].copy_from_slice(&counter_u64.to_be_bytes());
            self.aes.encrypt_block(&mut counter_block);
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= counter_block[i];
            }
            counter_u64 += 1;
            plain_text.extend_from_slice(block);
        }
        plain_text
    }

    pub fn decrypt(&self, plain_text: &[u8]) -> Vec<u8> {
        self.encrypt(plain_text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_input_data() -> Vec<&'static [u8]> {
        vec![
            &hex_literal::hex!("0123456789abcdef0123456789abcdef"),
            "".as_bytes(),
            "a".as_bytes(),
            "It's dangerous to go alone, take this!".as_bytes(),
        ]
    }

    #[test]
    fn test_cbc() {
        let key = hex_literal::hex!("0123456789abcdef0123456789abcdef");
        let iv = hex_literal::hex!("00001111222233334444555566667777");
        let aes_cbc = Aes128CBC::new(
            GenericArray::from_slice(&key),
            GenericArray::from_slice(&iv),
        );
        for input in get_input_data() {
            let cipher_text = aes_cbc.encrypt(&input);
            let decrypted_text = aes_cbc.decrypt(&cipher_text);
            assert_eq!(input, decrypted_text);
        }
    }

    #[test]
    fn test_ctr() {
        let key = hex_literal::hex!("0123456789abcdef0123456789abcdef");
        let iv = hex_literal::hex!("00001111222233334444555566667777");
        let aes_ctr = Aes128CTR::new(
            GenericArray::from_slice(&key),
            GenericArray::from_slice(&iv),
        );
        for input in get_input_data() {
            let cipher_text = aes_ctr.decrypt(&input);
            let decrypted_text = aes_ctr.encrypt(&cipher_text);
            assert_eq!(input, decrypted_text);
        }
    }
}
