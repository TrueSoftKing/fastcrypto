// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use bip39::{Language, Mnemonic, MnemonicType, Seed};
use clap::Parser;
use fastcrypto::{
    ed25519::Ed25519KeyPair,
    encoding::{Base64, Encoding},
    error::FastCryptoError,
    traits::{KeyPair, ToFromBytes},
};
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use serde_json::Value;
use slip10_ed25519::derive_ed25519_private_key;
use std::io::Read;
use std::{fs::File, time::Instant};

#[derive(Parser)]
#[command(name = "mnemonics-cli")]
#[command(about = "Try to derive the 12-word mnemonics from 8-word", long_about = None)]
enum Command {
    ConvertMnemonics(PartialMnemonics),
    Generate,
}

#[derive(Parser, Clone)]
struct PartialMnemonics {
    #[clap(long)]
    short: String,
    #[clap(long)]
    target_pk: String,
}

fn main() {
    match execute(Command::parse()) {
        Ok(_) => {
            std::process::exit(exitcode::OK);
        }
        Err(e) => {
            println!("Error: {}", e);
            std::process::exit(exitcode::DATAERR);
        }
    }
}

fn lpad(mut s: String, pad_string: char, length: usize) -> String {
    while s.len() < length {
        s = format!("{}{}", pad_string, s);
    }
    s
}

fn execute(cmd: Command) -> Result<(), FastCryptoError> {
    match cmd {
        Command::Generate => {
            let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
            let seed = Seed::new(&mnemonic, "");
            let derived = derive_ed25519_private_key(seed.as_bytes(), &[44, 784, 0, 0, 0]);
            let kp = Ed25519KeyPair::from_bytes(&derived).unwrap();
            println!("12 word mnemonic: {:?}", mnemonic.phrase());
            println!("pk: {:?}", kp.public());

            let wordlist = load();

            let mut compressed = "".to_string();
            println!("Entropy: {:?}", mnemonic.entropy());
            for chunk in mnemonic.entropy().chunks(2) {
                let combined_bytes = u16::from_be_bytes([chunk[0], chunk[1]]);
                let index = combined_bytes >> 3;
                let digit = combined_bytes & 0b111;
                let word = &wordlist[index as usize];
                let combined_word = format!("{}{} ", word, digit);
                compressed.push_str(&combined_word);
            }
            println!("8 word mnemonic: {:?}", compressed);
            Ok(())
        }
        Command::ConvertMnemonics(arg) => {
            let wordlist = load();
            let mut owned_string = "".to_string();
            for m in arg.short.split(' ') {
                if let Some(index) = wordlist.iter().position(|word| word == m) {
                    let s0 = lpad(format!("{:b}", index), '0', 13);
                    owned_string.push_str(&s0);
                } else {
                    return Err(FastCryptoError::GeneralError(format!(
                        "cannot find word {:?}",
                        m
                    )));
                }
            }

            if owned_string.len() != 104 {
                return Err(FastCryptoError::GeneralError(
                    "incorrect length".to_string(),
                ));
            }

            let bytes = bits_string_to_bytes(&owned_string);
            println!("bytes: {:?}", bytes);

            let total_combinations = 1 << 24;
            let chunk_size = total_combinations / rayon::current_num_threads();
            let chunks: Vec<_> = (0..total_combinations)
                .into_par_iter()
                .chunks(chunk_size)
                .collect();

            let start_time = Instant::now();

            // Perform the parallel processing
            let result = chunks.into_par_iter().find_any(|chunk| {
                for i in chunk {
                    let mut bytes = bytes.clone();
                    let digit_bytes = bits_string_to_bytes(&format!("{:024b}", i));
                    bytes.extend_from_slice(&digit_bytes);

                    let mnemonic = Mnemonic::from_entropy(&bytes, Language::English).unwrap();
                    let seed = Seed::new(&mnemonic, "");
                    let derived = derive_ed25519_private_key(seed.as_bytes(), &[44, 784, 0, 0, 0]);

                    if let Ok(kp) = Ed25519KeyPair::from_bytes(&derived) {
                        if kp.public().as_bytes() == Base64::decode(&arg.target_pk).unwrap() {
                            println!("Found target");
                            return true;
                        }
                    }
                }
                false
            });

            if result.is_none() {
                println!("Target not found");
            }

            println!("Time elapsed: {:?}", start_time.elapsed());
            Ok(())
        }
    }
}

fn bits_string_to_bytes(bits_string: &str) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();

    // Iterate over chunks of 8 bits (a byte)
    for chunk in bits_string.chars().collect::<Vec<_>>().chunks(8) {
        let mut byte = 0;

        // Iterate over each bit in the chunk
        for (i, bit_char) in chunk.iter().enumerate() {
            let bit = bit_char == &'1';
            if bit {
                // Set the corresponding bit in the byte
                byte |= 1 << i;
            }
        }

        // Push the resulting byte to the result vector
        result.push(byte);
    }

    result
}

fn load() -> Vec<String> {
    let mut file = File::open("fastcrypto-cli/src/english_8192.json").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let json_value: Value = serde_json::from_str(&contents).unwrap();
    let mut wordlist: Vec<String> = Vec::new();

    if let Value::Array(arr) = json_value {
        for element in arr {
            if let Value::String(s) = element {
                wordlist.push(s);
            }
        }
    }
    wordlist
}
