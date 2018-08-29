//! Test keygen / signature verifier

extern crate openssl;
extern crate hex;

use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::sign::{Signer, Verifier};
use openssl::hash::MessageDigest;
use std::str;

use std::fs::File;
use std::io::prelude::*;

use std::error::Error;

use std::env;

use std::process;

fn generate_keypair() -> openssl::pkey::PKey<openssl::pkey::Private> {
    let keypair = Rsa::generate(2048).unwrap();
    let keypair = PKey::from_rsa(keypair).unwrap();
    return keypair;
}

fn get_signature(string_to_sign: &str, keypair: &openssl::pkey::PKey<openssl::pkey::Private>) -> String {
    let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
    let bytes = string_to_sign.as_bytes();
    signer.update(bytes).unwrap();
    let signature = signer.sign_to_vec().unwrap();
    let signature = hex::encode(signature);
    return signature;
}

fn get_pub_key_from_keypair( keypair: &openssl::pkey::PKey<openssl::pkey::Private> ) -> String {
    let pub_key: Vec<u8> = keypair.public_key_to_pem().unwrap();
    let pub_key = str::from_utf8(pub_key.as_slice()).unwrap();
    return pub_key.to_string();
}

fn get_priv_key_from_keypair( keypair: &openssl::pkey::PKey<openssl::pkey::Private>) -> String {
    let priv_key: Vec<u8> = keypair.private_key_to_pem_pkcs8().unwrap();
    let priv_key = str::from_utf8(priv_key.as_slice()).unwrap();
    return priv_key.to_string();
} 

fn write_file(data: &str, filename: &str) {

    let mut file = match File::create(filename) {
        Err(why) => panic!("Couldn't create {}: {}",
                           filename,
                           why.description()),
        Ok(file) => file,
    };

    match file.write_all(data.as_bytes()) {
        Err(why) => {
            panic!("Couldn't write to {}: {}", filename,
                                               why.description())
        },
        Ok(_) => println!("Successfully wrote to {}", filename),
    }
}

fn read_file(filename: &str) -> Vec<u8> {
    let mut file = match File::open(filename) {
        Err(why) => panic!("Couldn't open {}: {}",
                    filename,
                    why.description()),
        Ok(file) => file,
    };

    let mut buffer = Vec::<u8>::new();
    file.read_to_end(&mut buffer);

    return buffer;
}

fn generate_keys(pub_key_filename: &str, priv_key_filename: &str) {

    let keypair = generate_keypair();

    let pub_key = get_pub_key_from_keypair(&keypair);
    let priv_key = get_priv_key_from_keypair(&keypair);

    //print usefull information
    println!("Generated key pair:\n\n");
    println!("{}", pub_key);
    println!("{}", priv_key);

    //write files
    write_file(&pub_key, pub_key_filename);
    write_file(&priv_key, priv_key_filename);

}

fn sign(string_to_sign: &str, priv_key_filename: &str, signature_filename: &str) {

    let key = read_file(priv_key_filename);
    let key = PKey::private_key_from_pem(&key).unwrap();
    let signature = get_signature(string_to_sign, &key);

    println!("String to sign: '{}'\n", string_to_sign);
    println!("Signature: {}\n", signature);

    write_file(&signature, signature_filename);
}

fn validate_signature(string_to_validate: &str, pub_key_filename: &str, signature_filename: &str) {
    let pub_key = read_file(pub_key_filename);
    let signature = read_file(signature_filename);
    let signature = hex::decode(&signature);

    if signature.is_err() {
        println!("Signature file is damaged!");
        return;
    }

    let pub_key = PKey::public_key_from_pem(&pub_key).unwrap();
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pub_key).unwrap();
    verifier.update(string_to_validate.as_bytes()).unwrap();

    if verifier.verify(&signature.unwrap()).unwrap() {
        println!("The signature is valid!");
    } else {
        println!("The signature is NOT valid!");
    }
}

fn print_help_and_exit() {
    println!("USAGE:\n");
    println!("\ttest_keygen generate [public key file name] [private key file name]");
    println!("\ttest_keygen sign [string to validate] [private key file name] [signature file name]");
    println!("\ttest_keygen validate [string to validate] [public key file name] [signature file name]");
    process::exit(-1);
}

fn main() {

    let args: Vec<String> = env::args().collect();

    if args.len()<2 {
        print_help_and_exit();
    }

    let option = &args[1];

    if option == "generate"  {
        if args.len() != 4 {
            print_help_and_exit();
        }
        generate_keys(&args[2], &args[3]);

    } else if option == "sign" {
        if args.len() != 5 {
            print_help_and_exit();
        }
        sign(&args[2], &args[3], &args[4]);

    } else if option == "validate" {
        if args.len() != 5 {
            print_help_and_exit();
        }
        validate_signature(&args[2], &args[3], &args[4]);
    }

}

