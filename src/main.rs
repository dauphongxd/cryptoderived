use anyhow::Result;
use bip39::{Language, Mnemonic};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use bitcoin::{
    address::Address,
    key::PublicKey,
    network::Network,
};
use bip32::{DerivationPath, ExtendedPrivateKey, Seed};
use clap::Parser;
use colored::*;
use log::warn;
use rand::{rngs::OsRng, RngCore};
use std::str::FromStr;
use k256::Secp256k1 as K256Secp256k1;
use ecdsa::SigningKey;
use arrayref::array_ref;
use sha3::{Keccak256, Digest};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = 1)]
    count: u32,
    

    #[arg(short, long)]
    gpu: bool,
    
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Clone)]
pub enum WalletType {
    RandomBitcoin,
    RandomEthereum,
    Bitcoin,
    Ethereum,
    SearchBitcoin,
    SearchEthereum,
}

#[derive(Debug, Clone)]
pub struct Wallet {
    pub mnemonic: String,
    pub wallet_type: WalletType,
    pub bech32_address: Option<String>,
    pub p2sh_address: Option<String>,
    pub p2pkh_address: Option<String>,
    pub ethereum_address: Option<String>,
}

pub struct Database {
    addresses: HashMap<String, u64>, // address -> balance in satoshis
}

impl Database {
    pub fn new() -> Self {
        Self {
            addresses: HashMap::new(),
        }
    }
    
    pub fn load_from_file(&mut self, file_path: &str) -> Result<()> {
        println!("{}", "Loading database...".bright_cyan().bold());
        
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);
        let mut count = 0;
        
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 2 {
                let address = parts[0].trim().to_string();
                if let Ok(balance) = parts[1].trim().parse::<u64>() {
                    self.addresses.insert(address, balance);
                    count += 1;
                    
                    if count % 1000000 == 0 {
                        println!("{}", format!("Loaded {} addresses...", count).bright_yellow());
                    }
                }
            }
        }
        
        println!("{}", format!("Loaded {} addresses from database", count).bright_green().bold());
        Ok(())
    }
    
    pub fn check_address(&self, address: &str) -> Option<u64> {
        self.addresses.get(address).copied()
    }
    
    pub fn get_total_addresses(&self) -> usize {
        self.addresses.len()
    }
}

impl Wallet {
    pub fn new_bitcoin() -> Result<Self> {
        // Generate random entropy for mnemonic
        let mut entropy = [0u8; 16]; // 128 bits for 12 words
        OsRng.fill_bytes(&mut entropy);
        
        // Generate mnemonic phrase
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)?;
        let mnemonic_str = mnemonic.to_string();
        
        // Generate seed from mnemonic using PBKDF2
        let seed_bytes = mnemonic.to_seed("");
        
        // Generate Bitcoin addresses using proper BIP32 derivation paths
        let bech32_address = Self::generate_bech32_address(&seed_bytes)?;
        let p2sh_address = Self::generate_p2sh_address(&seed_bytes)?;
        let p2pkh_address = Self::generate_p2pkh_address(&seed_bytes)?;
        
        Ok(Wallet {
            mnemonic: mnemonic_str,
            wallet_type: WalletType::Bitcoin,
            bech32_address: Some(bech32_address),
            p2sh_address: Some(p2sh_address),
            p2pkh_address: Some(p2pkh_address),
            ethereum_address: None,
        })
    }
    
    pub fn new_ethereum() -> Result<Self> {
        // Generate random entropy for mnemonic
        let mut entropy = [0u8; 16]; // 128 bits for 12 words
        OsRng.fill_bytes(&mut entropy);
        
        // Generate mnemonic phrase
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)?;
        let mnemonic_str = mnemonic.to_string();
        
        // Generate seed from mnemonic using PBKDF2
        let seed_bytes = mnemonic.to_seed("");
        
        // Generate Ethereum address using proper BIP32 derivation path
        let ethereum_address = Self::generate_ethereum_address(&seed_bytes)?;
        
        Ok(Wallet {
            mnemonic: mnemonic_str,
            wallet_type: WalletType::Ethereum,
            bech32_address: None,
            p2sh_address: None,
            p2pkh_address: None,
            ethereum_address: Some(ethereum_address),
        })
    }
    
    fn generate_bech32_address(seed_bytes: &[u8]) -> Result<String> {
        // BIP84: m/84'/0'/0'/0/0 for Bech32 (P2WPKH)
        let seed = Seed::new(*array_ref!(seed_bytes, 0, 64));
        let path = DerivationPath::from_str("m/84'/0'/0'/0/0")?;
        let xprv = ExtendedPrivateKey::<SigningKey<K256Secp256k1>>::derive_from_path(&seed, &path)?;
        let public_key = xprv.public_key();
        let bitcoin_pubkey = PublicKey::from_slice(&public_key.to_bytes())?;
        let address = Address::p2wpkh(&bitcoin_pubkey, Network::Bitcoin)?;
        Ok(address.to_string())
    }
    
    fn generate_p2sh_address(seed_bytes: &[u8]) -> Result<String> {
        // BIP49: m/49'/0'/0'/0/0 for P2SH-wrapped SegWit (P2WPKH-in-P2SH)
        let seed = Seed::new(*array_ref!(seed_bytes, 0, 64));
        let path = DerivationPath::from_str("m/49'/0'/0'/0/0")?;
        let xprv = ExtendedPrivateKey::<SigningKey<K256Secp256k1>>::derive_from_path(&seed, &path)?;
        let public_key = xprv.public_key();
        let bitcoin_pubkey = PublicKey::from_slice(&public_key.to_bytes())?;
        let address = Address::p2shwpkh(&bitcoin_pubkey, Network::Bitcoin)?;
        Ok(address.to_string())
    }
    
    fn generate_p2pkh_address(seed_bytes: &[u8]) -> Result<String> {
        // BIP44: m/44'/0'/0'/0/0 for P2PKH (legacy)
        let seed = Seed::new(*array_ref!(seed_bytes, 0, 64));
        let path = DerivationPath::from_str("m/44'/0'/0'/0/0")?;
        let xprv = ExtendedPrivateKey::<SigningKey<K256Secp256k1>>::derive_from_path(&seed, &path)?;
        let public_key = xprv.public_key();
        let bitcoin_pubkey = PublicKey::from_slice(&public_key.to_bytes())?;
        let address = Address::p2pkh(&bitcoin_pubkey, Network::Bitcoin);
        Ok(address.to_string())
    }
    
    fn generate_ethereum_address(seed_bytes: &[u8]) -> Result<String> {
        // BIP44: m/44'/60'/0'/0/0 for Ethereum
        let seed = Seed::new(*array_ref!(seed_bytes, 0, 64));
        let path = DerivationPath::from_str("m/44'/60'/0'/0/0")?;
        let xprv = ExtendedPrivateKey::<SigningKey<K256Secp256k1>>::derive_from_path(&seed, &path)?;
        let public_key = xprv.public_key();
        let public_key_bytes = public_key.to_bytes();
        
        // Convert to secp256k1 public key for Ethereum address generation
        let secp_pubkey = secp256k1::PublicKey::from_slice(&public_key_bytes)?;
        
        // Get uncompressed public key (65 bytes: 0x04 + 32 bytes x + 32 bytes y)
        let uncompressed = secp_pubkey.serialize_uncompressed();
        
        // Remove the 0x04 prefix and take the remaining 64 bytes (x + y coordinates)
        let xy_coords = &uncompressed[1..];
        
        // Hash with Keccak256 and take the last 20 bytes
        let mut hasher = Keccak256::new();
        hasher.update(xy_coords);
        let hash = hasher.finalize();
        let address_bytes = &hash[12..]; // Last 20 bytes
        
        // Generate EIP-55 checksummed address
        let address_hex = hex::encode(address_bytes);
        let checksummed_address = Self::to_checksum_address(&address_hex);
        
        Ok(format!("0x{}", checksummed_address))
    }
    
    // EIP-55 checksumming for Ethereum addresses
    fn to_checksum_address(address: &str) -> String {
        // Remove 0x prefix if present
        let address = if address.starts_with("0x") {
            &address[2..]
        } else {
            address
        };
        
        // Convert to lowercase for hashing
        let address_lower = address.to_lowercase();
        
        // Hash the lowercase address with Keccak256
        let mut hasher = Keccak256::new();
        hasher.update(address_lower.as_bytes());
        let hash = hasher.finalize();
        let hash_hex = hex::encode(hash);
        
        // Build checksummed address
        let mut result = String::new();
        for (i, c) in address.chars().enumerate() {
            if c.is_ascii_digit() {
                // Digits remain unchanged
                result.push(c);
            } else {
                // Letters: uppercase if hash digit >= 8, lowercase otherwise
                let hash_char = hash_hex.chars().nth(i).unwrap_or('0');
                let hash_value = hash_char.to_digit(16).unwrap_or(0);
                
                if hash_value >= 8 {
                    result.push(c.to_ascii_uppercase());
                } else {
                    result.push(c.to_ascii_lowercase());
                }
            }
        }
        
        result
    }
    
}

async fn generate_wallets_continuously(wallet_type: WalletType, use_gpu: bool) -> Result<()> {
    let mut counter = 0;
    
    loop {
        if use_gpu {
            warn!("GPU acceleration not yet implemented, using CPU");
        }
        
        let wallet = match wallet_type {
            WalletType::Bitcoin => Wallet::new_bitcoin()?,
            WalletType::Ethereum => Wallet::new_ethereum()?,
            WalletType::RandomBitcoin => Wallet::new_bitcoin()?,
            WalletType::RandomEthereum => Wallet::new_ethereum()?,
            WalletType::SearchBitcoin | WalletType::SearchEthereum => {
                // These should not reach here as they're handled separately
                return Err(anyhow::anyhow!("Invalid wallet type for continuous generation"));
            }
        };
        counter += 1;
        
        // Print each wallet as it's generated with colors
        match wallet.wallet_type {
            WalletType::Bitcoin | WalletType::RandomBitcoin => {
                println!("\n{}", format!("=== Bitcoin Wallet #{} ===", counter).bright_cyan().bold());
                if let Some(addr) = &wallet.bech32_address {
                    println!("{} {}", "BECH32 address:".bright_green().bold(), addr.bright_white());
                }
                if let Some(addr) = &wallet.p2sh_address {
                    println!("{} {}", "P2SH address:".bright_yellow().bold(), addr.bright_white());
                }
                if let Some(addr) = &wallet.p2pkh_address {
                    println!("{} {}", "P2PKH address:".bright_blue().bold(), addr.bright_white());
                }
            }
            WalletType::Ethereum | WalletType::RandomEthereum => {
                println!("\n{}", format!("=== Ethereum Wallet #{} ===", counter).bright_cyan().bold());
                if let Some(addr) = &wallet.ethereum_address {
                    println!("{} {}", "Ethereum address:".bright_green().bold(), addr.bright_white());
                }
            }
            WalletType::SearchBitcoin | WalletType::SearchEthereum => {
                // These should not reach here
                unreachable!();
            }
        }
        println!("{} {}", "mnemonic:".bright_magenta().bold(), wallet.mnemonic.bright_white());
        println!("{}", "=".repeat(50).bright_cyan());
        
        // Add a small delay to prevent overwhelming the system
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}


fn show_menu() -> WalletType {
    loop {
        println!("\n{}", "Wallet Generator Menu".bright_cyan().bold());
        println!("{}", "=".repeat(30).bright_cyan());
        println!("{}", "1. Generate Bitcoin address".bright_green());
        println!("{}", "2. Generate Ethereum address".bright_blue());
        println!("{}", "3. Search Bitcoin wallets with balance".bright_green());
        println!("{}", "4. Search Ethereum wallets with balance".bright_blue());
        println!("{}", "=".repeat(30).bright_cyan());
        print!("{}", "Enter your choice (1-4): ".bright_yellow().bold());
        
        use std::io::{self, Write};
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        
        match input.trim() {
            "1" => {
                println!("{}", "Selected: Random Bitcoin address generation".bright_green().bold());
                return WalletType::RandomBitcoin;
            }
            "2" => {
                println!("{}", "Selected: Random Ethereum address generation".bright_blue().bold());
                return WalletType::RandomEthereum;
            }
            "3" => {
                println!("{}", "Selected: Search Bitcoin wallets with balance".bright_green().bold());
                return WalletType::SearchBitcoin;
            }
            "4" => {
                println!("{}", "Selected: Search Ethereum wallets with balance".bright_blue().bold());
                return WalletType::SearchEthereum;
            }
            _ => {
                println!("{}", "Invalid choice! Please enter 1, 2, 3, or 4.".bright_red().bold());
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    
    let args = Args::parse();
    
    // Show menu and get user choice
    let wallet_type = show_menu();
    
    match wallet_type {
        WalletType::RandomBitcoin => {
            println!("\n{}", "Generating random Bitcoin address...".bright_green().bold());
            let wallet = Wallet::new_bitcoin()?;
            print_single_wallet(&wallet);
        }
        WalletType::RandomEthereum => {
            println!("\n{}", "Generating random Ethereum address...".bright_blue().bold());
            let wallet = Wallet::new_ethereum()?;
            print_single_wallet(&wallet);
        }
        WalletType::SearchBitcoin => {
            generate_bitcoin_with_database_check().await?;
        }
        WalletType::SearchEthereum => {
            generate_ethereum_with_database_check().await?;
        }
        _ => {
            println!("\n{}", "Starting continuous wallet generation...".bright_green().bold());
            println!("{}", "Press Ctrl+C to stop".bright_yellow().bold());
            println!("{}", format!("GPU mode: {}", args.gpu).bright_cyan());
            
            // Set up signal handling for graceful shutdown
            let ctrl_c = async {
                tokio::signal::ctrl_c()
                    .await
                    .expect("Failed to install Ctrl+C handler");
            };
            
            // Run wallet generation until interrupted
            tokio::select! {
                _ = generate_wallets_continuously(wallet_type, args.gpu) => {
                    // This should never complete normally
                }
                _ = ctrl_c => {
                    println!("\n\n{}", "Shutting down gracefully...".bright_red().bold());
                }
            }
        }
    }
    
    Ok(())
}

fn print_single_wallet(wallet: &Wallet) {
    println!("\n{}", "=".repeat(60).bright_cyan());
    match wallet.wallet_type {
        WalletType::Bitcoin | WalletType::RandomBitcoin => {
            println!("{}", "=== BITCOIN WALLET ===".bright_green().bold());
            println!("{} {}", "Mnemonic:".bright_yellow().bold(), wallet.mnemonic.bright_white());
            println!("{} {}", "BECH32:".bright_green().bold(), 
                wallet.bech32_address.as_ref().unwrap_or(&"N/A".to_string()).bright_white());
            println!("{} {}", "P2SH:".bright_yellow().bold(), 
                wallet.p2sh_address.as_ref().unwrap_or(&"N/A".to_string()).bright_white());
            println!("{} {}", "P2PKH:".bright_blue().bold(), 
                wallet.p2pkh_address.as_ref().unwrap_or(&"N/A".to_string()).bright_white());
        }
        WalletType::Ethereum | WalletType::RandomEthereum => {
            println!("{}", "=== ETHEREUM WALLET ===".bright_blue().bold());
            println!("{} {}", "Mnemonic:".bright_yellow().bold(), wallet.mnemonic.bright_white());
            println!("{} {}", "Ethereum:".bright_blue().bold(), 
                wallet.ethereum_address.as_ref().unwrap_or(&"N/A".to_string()).bright_white());
        }
        WalletType::SearchBitcoin | WalletType::SearchEthereum => {
            // These wallet types are not used for single wallet display
            unreachable!();
        }
    }
    println!("{}", "=".repeat(60).bright_cyan());
}

fn save_found_wallet(wallet_info: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("found_wallets.txt")?;
    
    writeln!(file, "{}", wallet_info)?;
    file.flush()?;
    Ok(())
}

async fn generate_bitcoin_with_database_check() -> Result<()> {
    println!("\n{}", "GENERATING BITCOIN WALLETS WITH DATABASE CHECK".bright_green().bold());
    println!("{}", "=".repeat(50).bright_green());
    
    // Load database
    let mut database = Database::new();
    database.load_from_file("database.txt")?;
    
    println!("{}", "Press Ctrl+C to stop".bright_yellow().bold());
    
    let mut counter = 0;
    let mut matches_found = 0;
    
    // Set up signal handling for graceful shutdown
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };
    
    // Run wallet generation until interrupted
    tokio::select! {
        _ = async {
            loop {
                // Generate random Bitcoin wallet
                let wallet = match Wallet::new_bitcoin() {
                    Ok(w) => w,
                    Err(e) => {
                        eprintln!("Error generating wallet: {}", e);
                        continue;
                    }
                };
                counter += 1;
                
                // Check all addresses against database
                let mut wallet_has_balance = false;
                let mut balance_info = Vec::new();
                
                if let Some(addr) = &wallet.bech32_address {
                    if let Some(balance) = database.check_address(addr) {
                        wallet_has_balance = true;
                        balance_info.push(format!("BECH32: {} ({} satoshis)", addr, balance));
                        matches_found += 1;
                    }
                }
                
                if let Some(addr) = &wallet.p2sh_address {
                    if let Some(balance) = database.check_address(addr) {
                        wallet_has_balance = true;
                        balance_info.push(format!("P2SH: {} ({} satoshis)", addr, balance));
                        matches_found += 1;
                    }
                }
                
                if let Some(addr) = &wallet.p2pkh_address {
                    if let Some(balance) = database.check_address(addr) {
                        wallet_has_balance = true;
                        balance_info.push(format!("P2PKH: {} ({} satoshis)", addr, balance));
                        matches_found += 1;
                    }
                }
                
                // Print wallet info
                println!("\n{}", format!("=== Bitcoin Wallet #{} ===", counter).bright_cyan().bold());
                if let Some(addr) = &wallet.bech32_address {
                    println!("{} {}", "BECH32 address:".bright_green().bold(), addr.bright_white());
                }
                if let Some(addr) = &wallet.p2sh_address {
                    println!("{} {}", "P2SH address:".bright_yellow().bold(), addr.bright_white());
                }
                if let Some(addr) = &wallet.p2pkh_address {
                    println!("{} {}", "P2PKH address:".bright_blue().bold(), addr.bright_white());
                }
                println!("{} {}", "mnemonic:".bright_magenta().bold(), wallet.mnemonic.bright_white());
                
                // If wallet has balance, highlight it and save to file
                if wallet_has_balance {
                    println!("{}", "WALLET WITH BALANCE FOUND!".bright_green().bold());
                    for info in &balance_info {
                        println!("{}", format!("💰 {}", info).bright_green().bold());
                    }
                    
                    // Save to found_wallets.txt
                    let wallet_data = format!(
                        "=== BITCOIN WALLET #{} ===\nMnemonic: {}\n{}\nTimestamp: {}\n{}\n",
                        counter,
                        wallet.mnemonic,
                        balance_info.join("\n"),
                        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
                        "=".repeat(50)
                    );
                    
                    if let Err(e) = save_found_wallet(&wallet_data) {
                        eprintln!("Error saving wallet: {}", e);
                    } else {
                        println!("{}", "💾 Saved to found_wallets.txt".bright_cyan().bold());
                    }
                }
                
                println!("{}", format!("Total matches found: {}", matches_found).bright_yellow());
                println!("{}", "=".repeat(50).bright_cyan());
                
                // Add a small delay to prevent overwhelming the system
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        } => {}
        _ = ctrl_c => {
            println!("\n\n{}", "Shutting down gracefully...".bright_red().bold());
            println!("{}", format!("Total wallets generated: {}", counter).bright_cyan());
            println!("{}", format!("Total matches found: {}", matches_found).bright_green().bold());
        }
    }
    
    Ok(())
}

async fn generate_ethereum_with_database_check() -> Result<()> {
    println!("\n{}", "GENERATING ETHEREUM WALLETS WITH DATABASE CHECK".bright_blue().bold());
    println!("{}", "=".repeat(50).bright_blue());
    
    // Load database
    let mut database = Database::new();
    database.load_from_file("database.txt")?;
    
    println!("{}", "Press Ctrl+C to stop".bright_yellow().bold());
    
    let mut counter = 0;
    let mut matches_found = 0;
    
    // Set up signal handling for graceful shutdown
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };
    
    // Run wallet generation until interrupted
    tokio::select! {
        _ = async {
            loop {
                // Generate random Ethereum wallet
                let wallet = match Wallet::new_ethereum() {
                    Ok(w) => w,
                    Err(e) => {
                        eprintln!("Error generating wallet: {}", e);
                        continue;
                    }
                };
                counter += 1;
                
                // Check address against database
                let mut wallet_has_balance = false;
                let mut balance_info = String::new();
                
                if let Some(addr) = &wallet.ethereum_address {
                    if let Some(balance) = database.check_address(addr) {
                        wallet_has_balance = true;
                        balance_info = format!("{} ({} satoshis)", addr, balance);
                        matches_found += 1;
                    }
                }
                
                // Print wallet info
                println!("\n{}", format!("=== Ethereum Wallet #{} ===", counter).bright_cyan().bold());
                if let Some(addr) = &wallet.ethereum_address {
                    println!("{} {}", "Ethereum address:".bright_blue().bold(), addr.bright_white());
                }
                println!("{} {}", "mnemonic:".bright_magenta().bold(), wallet.mnemonic.bright_white());
                
                // If wallet has balance, highlight it and save to file
                if wallet_has_balance {
                    println!("{}", "WALLET WITH BALANCE FOUND!".bright_green().bold());
                    println!("{}", format!("💰 {}", balance_info).bright_green().bold());
                    
                    // Save to found_wallets.txt
                    let wallet_data = format!(
                        "=== ETHEREUM WALLET #{} ===\nMnemonic: {}\n{}\nTimestamp: {}\n{}\n",
                        counter,
                        wallet.mnemonic,
                        balance_info,
                        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
                        "=".repeat(50)
                    );
                    
                    if let Err(e) = save_found_wallet(&wallet_data) {
                        eprintln!("Error saving wallet: {}", e);
                    } else {
                        println!("{}", "💾 Saved to found_wallets.txt".bright_cyan().bold());
                    }
                }
                
                println!("{}", format!("Total matches found: {}", matches_found).bright_yellow());
                println!("{}", "=".repeat(50).bright_cyan());
                
                // Add a small delay to prevent overwhelming the system
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        } => {}
        _ = ctrl_c => {
            println!("\n\n{}", "Shutting down gracefully...".bright_red().bold());
            println!("{}", format!("Total wallets generated: {}", counter).bright_cyan());
            println!("{}", format!("Total matches found: {}", matches_found).bright_green().bold());
        }
    }
    
    Ok(())
}

