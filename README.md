# aes-modes

Rust implementation of CBC & CTR modes for AES, as an exercise of 
Stanford's Cryptography I course from Coursera.

This crate uses [aes](https://docs.rs/aes/latest/aes/) crate in the underlying implementation.

## Example
The first exercise is solved by the following snippet:
```rust
use aes::cipher::generic_array::GenericArray;
use aes_modes::{Aes128CBC, Aes128CTR};

let key = hex!("140b41b22a29beb4061bda66b6747e14");
let input = hex!(
    "4ca00ff4c898d61e1edbf1800618fb28
     28a226d160dad07883d04e008a7897ee
     2e4b7465d5290d0c0e6c6822236e1daa
     fb94ffe0c5da05d9476be028ad7c1d81"
);
let (iv, cipher_text) = (&input[..16], &input[16..]);
let aes_cbc = Aes128CBC::new(
    GenericArray::from_slice(&key),
    GenericArray::from_slice(&iv),
);
let plain_text = aes_cbc.decrypt(&cipher_text);
let plain_text = String::from_utf8_lossy(&plain_text).into_owned();

```

Which outputs:

```Basic CBC mode encryption needs padding.```
