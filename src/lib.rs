use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit, BlockEncrypt},
    Aes128, Block,
};

pub struct Aes128CBC {
    key: Block,
    iv: Block,
}

impl Aes128CBC {
    pub fn new(key: &Block, iv: &Block) -> Self {
        Self { key: *key, iv: *iv }
    }

    pub fn set_key(&mut self, key: &Block) {
        self.key = *key;
    }

    pub fn set_iv(&mut self, iv: &Block) {
        self.iv = *iv;
    }

    pub fn decrypt(&self, cipher_text: &[u8]) -> Vec<u8> {
        let mut blocks: Vec<Block> = cipher_text
            .chunks(16)
            .map(GenericArray::clone_from_slice)
            .collect();
        self.decrypt_blocks(blocks.iter_mut())
    }

    pub fn decrypt_blocks<'a, I>(&self, blocks: I) -> Vec<u8>
    where
        I: Iterator<Item = &'a mut Block>,
    {
        let aes = Aes128::new(&self.key);
        let mut prev = self.iv;
        let mut plain_text = Vec::new();

        for block in blocks {
            let new_prev = *block;
            aes.decrypt_block(block);
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= prev[i];
            }
            prev = new_prev;
            plain_text.extend_from_slice(block);
        }
        plain_text
    }
}

pub struct Aes128CTR {
    key: Block,
    iv: Block,
}

impl Aes128CTR {
    pub fn new(key: &Block, iv: &Block) -> Self {
        Self { key: *key, iv: *iv }
    }

    pub fn set_key(&mut self, key: &Block) {
        self.key = *key;
    }

    pub fn set_iv(&mut self, iv: &Block) {
        self.iv = *iv;
    }

    pub fn decrypt(&self, cipher_text: &[u8]) -> Vec<u8> {
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
        let mut result = self.decrypt_blocks(blocks.iter_mut());
        result.truncate(result.len() - extension);
        result
    }

    pub fn decrypt_blocks<'a, I>(&self, blocks: I) -> Vec<u8>
    where
        I: Iterator<Item = &'a mut Block>,
    {
        let aes = Aes128::new(&self.key);
        let (nonce, counter) = self.iv.split_at(8);
        let mut counter_u64 = u64::from_be_bytes(counter[..8].try_into().unwrap());
        let mut plain_text = Vec::new();

        for block in blocks {
            // encrypt counter then XOR with block
            let mut counter_block = Block::default();
            counter_block[..8].copy_from_slice(nonce);
            counter_block[8..].copy_from_slice(&counter_u64.to_be_bytes());
            aes.encrypt_block(&mut counter_block);
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= counter_block[i];
            }
            counter_u64 += 1;
            plain_text.extend_from_slice(block);
        }
        plain_text
    }
}
