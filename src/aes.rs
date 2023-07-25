#![allow(dead_code)]

// --------------------------------KEY GENERATION-------------------------------------------

pub fn key_schedule(key_seed: u128) -> [u128; 11] {
    let rc: u8 = 1;
    let mut rcon = (rc as u32) << 24;
    // let key_len: u16 = 128; // 256 for AES-256
    let num_round_keys: usize = 11; // 15 for AES-256
    // let key_seed: u128 = 0;
    let expanded_key_vec = (0..num_round_keys).fold(vec![], |mut acc, round| {
        if round > 0 {
            acc.push(compute_next_key(rcon, acc[round-1]));
            rcon = increment_rcon(rcon);
        } else {
            acc.push(key_seed);
        }
        acc
    });
    let expanded_key_arr = vec_to_arr(expanded_key_vec);
    expanded_key_arr
}

pub fn vec_to_arr<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a vector with {} values, but received {}.", N, v.len()))
}

// this function could be cleaned up. Was having some trouble keeping the order of the vectors straight in my mind.
fn compute_next_key(rcon: u32, prev_key: u128) -> u128 {
    let mut prev_words: [u32; 4] = u128_to_words(prev_key); // 4 is key length in words
    prev_words.reverse();
    let mut res_words: [u32; 4] = [0, 0, 0, 0];
    res_words[0] = substitute_word(rotate_word(prev_words[3])) ^ prev_words[0] ^ rcon;
    for i in 1..4 {
        res_words[i] = prev_words[i] ^ res_words[i-1];
    }
    res_words.reverse();
    words_to_u128(res_words)
}

fn words_to_u128(words: [u32; 4]) -> u128 {
    let bytes_iter = words.iter().flat_map(|word| word.to_le_bytes());
    let bytes_vec: Vec<u8> = bytes_iter.collect();
    let bytes_arr = vec_to_arr(bytes_vec);
    u128::from_le_bytes(bytes_arr)
}

fn u128_to_words(num: u128) -> [u32; 4] {
    let bytes = num.to_le_bytes();
    let words = bytes.chunks(4)
    .map(|chunk| {
        let mut buf: [u8; 4] = [0, 0, 0, 0];
        buf.copy_from_slice(chunk);
        u32::from_le_bytes(buf)
    });
    let words_vec = words.collect::<Vec<u32>>();
    let words_arr = vec_to_arr(words_vec);
    words_arr
}

// left circular shift of 1 byte
fn rotate_word(word: u32) -> u32 {
    let left_byte = word ^ !(0xff << 24);
    (word << 8) ^ (left_byte >> 24) 
}

// apply S box substitution to each byte
fn substitute_word(word: u32) -> u32 {
    let bytes: [u8; 4] = word.to_le_bytes();
    let substituted_bytes = bytes.iter()
        .map(|byte| substitute_byte(*byte));
    let (new_word, _) = substituted_bytes.fold((0u32, 0u8), |(res_word, cnt), byte| {
        let byte_shifted: u32 = (byte as u32) << (cnt * 8);
        let res = res_word | byte_shifted;
        return (res, cnt + 1)
    });
    return new_word;
}

fn substitute_byte(byte: u8) -> u8 {
    let right_nibble: usize = (byte & 0xf).into();
    let left_nibble: usize = (byte >> 4).into();
    S_BOX[left_nibble][right_nibble]
}

// increment round constant
fn increment_rcon(rcon: u32) -> u32 {
    let bytes = rcon.to_le_bytes();
    let rc = bytes[3];
    let new_rc = increment_rc(rc);
    let res = u32::from_le_bytes([0, 0, 0, new_rc]);
    res
}

fn increment_rc(rc: u8) -> u8 {
    if rc >= 0x80 {
        return (rc << 1) ^ 0x1B;
    }else {
        return rc << 1;
    }
}

// ------------------------------- ENCRYPTION/DECRYPTION -------------------------------

// fn encrypt(msg: &str, key: Vec<u128>) {
//     let mut data = vectorize_msg(String::from(msg));
//     for round in 0..11 {
//         let round_key = key[round];
//         data = encrypt_round(&data, round_key);
//         // let data = data.iter().map(|byte| substitute_byte(*byte));
        
//     }
// }

// fn encrypt_round(data: &Vec<u8>, round_key: u128) {
//     let data = data.iter().map(|byte| substitute_byte(*byte));
//     let data = shift_rows(data);
// }

// fn shift_rows(data: &Vec<u8>) -> Vec<u8> {
//     let mut data_words = u128_to_words(u128::from_le_bytes(data));
//     for i in 0..4 {
//         for j in 0..i {
//             data_words[i] = rotate_word(data_words[i]);
//         }
//     }
//     words_to_u128(data_words).to_le_bytes().to_vec()
// }

fn vectorize_msg(msg: String) -> Vec<u8>{
    let padding = 128 - (msg.len() % 128);
    let msg = format!("{:-<padding$}", msg);
    let res: Vec<u8> = msg.as_bytes().to_vec();
    res
}

fn add_round_key(data: Vec<u8>, round_key: u128) -> Vec<u8> {
    let round_key_vec = round_key.to_le_bytes();
    data.iter().enumerate()
    .map(| (ind, byte) | {
        byte ^ round_key_vec[ind]
    }).collect()
}


// -------------------------------CONSTANTS---------------------------------------------

static S_BOX: [[u8;16];16] = [
[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
[0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
[0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
[0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
[0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
[0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
[0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
[0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
[0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
[0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
[0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
[0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
[0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
[0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
[0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
[0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
];

// static INVERSE_S_BOX: [[u8;16];16] = [];

// could define round constant here...

// -------------------------------UNIT TESTS--------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_round_key() {
        let input_u128: u128 = 0x00000101_03030707_0f0f1f1f_3f3f7f7f;
        let input_vec: Vec<u8> = input_u128.to_le_bytes().to_vec();
        let key: u128 = 0x62636363_62636363_62636363_62636363;
        let res = add_round_key(input_vec, key);
        let expected: Vec<u8> = (0x62636262_61606464_6d6c7c7c_5d5c1c1c as u128).to_le_bytes().to_vec();
        assert_eq!(res, expected)
    }

    #[test]
    fn test_key_schedule() {
        let res = key_schedule(0);
        let expected: [u128; 11] = [
            0x00000000_00000000_00000000_00000000,
            0x62636363_62636363_62636363_62636363,
            0x9b9898c9_f9fbfbaa_9b9898c9_f9fbfbaa,
            0x90973450_696ccffa_f2f45733_0b0fac99,
            0xee06da7b_876a1581_759e42b2_7e91ee2b,
            0x7f2e2b88_f8443e09_8dda7cbb_f34b9290,
            0xec614b85_1425758c_99ff0937_6ab49ba7,
            0x21751787_3550620b_acaf6b3c_c61bf09b,
            0x0ef90333_3ba96138_97060a04_511dfa9f,
            0xb1d4d8e2_8a7db9da_1d7bb3de_4c664941,
            0xb4ef5bcb_3e92e211_23e951cf_6f8f188e
        ];
        assert_eq!(res, expected)
    }

    #[test]
    fn test_u128_to_words() {
        let num: u128 = 0x1200001234;
        let expected: [u32; 4] = [0x1234, 0x12, 0, 0];
        let res = u128_to_words(num);
        assert_eq!(res, expected)
    }

    #[test]
    fn test_words_to_u128() {
        let words: [u32; 4] = [0x1234, 0x12, 0, 0];
        let expected: u128 = 0x1200001234;
        let res = words_to_u128(words);
        assert_eq!(res, expected)
    }

    #[test]
    fn test_increment_rcon() {
        let mut rcon = 0x1000000;
        for _ in 1..10{
            rcon = increment_rcon(rcon);
        }
        assert_eq!(rcon, 0x36000000);
    }

    #[test]
    fn test_rotate_word() {
        let word = 0x12345678;
        assert_eq!(rotate_word(word), 0x34567812)
    }

    #[test]
    fn test_substitute_word() {
        let word = 0x12345678;
        assert_eq!(substitute_word(word), 0xc918b1bc)
    }

    #[test]
    fn test_compute_next_key() {
        let rc: u8 = 1;
        let rcon = (rc as u32) << 24;
        let key_seed: u128 = 0;
        let r1 = compute_next_key(rcon, key_seed);
        assert_eq!(r1, 0x62636363626363636263636362636363);
        let rcon = increment_rcon(rcon);
        let r2 = compute_next_key(rcon, r1);
        assert_eq!(r2, 0x9b9898c9f9fbfbaa9b9898c9f9fbfbaa);
    }
}