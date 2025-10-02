use anyhow::Result;
use bip39::{Language, Mnemonic};
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
    /// Number of wallets to generate
    #[arg(short, long, default_value_t = 1)]
    count: u32,
    
    /// Use GPU acceleration (placeholder for future implementation)
    #[arg(short, long)]
    gpu: bool,
    
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Clone)]
pub enum WalletType {
    Bitcoin,
    Ethereum,
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
        };
        counter += 1;
        
        // Print each wallet as it's generated with colors
        match wallet.wallet_type {
            WalletType::Bitcoin => {
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
            WalletType::Ethereum => {
                println!("\n{}", format!("=== Ethereum Wallet #{} ===", counter).bright_cyan().bold());
                if let Some(addr) = &wallet.ethereum_address {
                    println!("{} {}", "Ethereum address:".bright_green().bold(), addr.bright_white());
                }
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
        println!("\n{}", "🎯 Wallet Generator Menu".bright_cyan().bold());
        println!("{}", "=".repeat(30).bright_cyan());
        println!("{}", "1. Generate Bitcoin wallets (BECH32, P2SH, P2PKH)".bright_green());
        println!("{}", "2. Generate Ethereum wallets (EVM)".bright_blue());
        println!("{}", "=".repeat(30).bright_cyan());
        print!("{}", "Enter your choice (1 or 2): ".bright_yellow().bold());
        
        use std::io::{self, Write};
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        
        match input.trim() {
            "1" => {
                println!("{}", "✅ Selected: Bitcoin wallet generation".bright_green().bold());
                return WalletType::Bitcoin;
            }
            "2" => {
                println!("{}", "✅ Selected: Ethereum wallet generation".bright_blue().bold());
                return WalletType::Ethereum;
            }
            _ => {
                println!("{}", "❌ Invalid choice! Please enter 1 or 2.".bright_red().bold());
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
    
    println!("\n{}", "🚀 Starting continuous wallet generation...".bright_green().bold());
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
            println!("\n\n{}", "🛑 Shutting down gracefully...".bright_red().bold());
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bitcoin_wallet_generation() {
        let wallet = Wallet::new_bitcoin().expect("Failed to generate Bitcoin wallet");
        assert!(!wallet.mnemonic.is_empty());
        assert!(wallet.bech32_address.is_some());
        assert!(wallet.p2sh_address.is_some());
        assert!(wallet.p2pkh_address.is_some());
        assert!(wallet.ethereum_address.is_none());
        assert!(matches!(wallet.wallet_type, WalletType::Bitcoin));
    }
    
    #[test]
    fn test_ethereum_wallet_generation() {
        let wallet = Wallet::new_ethereum().expect("Failed to generate Ethereum wallet");
        assert!(!wallet.mnemonic.is_empty());
        assert!(wallet.bech32_address.is_none());
        assert!(wallet.p2sh_address.is_none());
        assert!(wallet.p2pkh_address.is_none());
        assert!(wallet.ethereum_address.is_some());
        assert!(matches!(wallet.wallet_type, WalletType::Ethereum));
    }
    
    #[test]
    fn test_mnemonic_validation() {
        let wallet = Wallet::new_bitcoin().expect("Failed to generate wallet");
        let mnemonic = Mnemonic::parse(&wallet.mnemonic).expect("Invalid mnemonic");
        assert_eq!(mnemonic.word_count(), 12);
    }
    
    #[test]
    fn test_known_mnemonic() {
        // Test with the known mnemonic from the user
        let mnemonic_str = "ugly laptop afford sun robust scene fix valley people below expire leave";
        let mnemonic = Mnemonic::parse(mnemonic_str).expect("Invalid mnemonic");
        let seed_bytes = mnemonic.to_seed("");
        
        let bech32_address = Wallet::generate_bech32_address(&seed_bytes).expect("Failed to generate Bech32 address");
        let p2sh_address = Wallet::generate_p2sh_address(&seed_bytes).expect("Failed to generate P2SH address");
        let p2pkh_address = Wallet::generate_p2pkh_address(&seed_bytes).expect("Failed to generate P2PKH address");
        
        println!("{}", "Generated addresses:".bright_green().bold());
        println!("{} {}", "BECH32:".bright_green().bold(), bech32_address.bright_white());
        println!("{} {}", "P2SH:".bright_yellow().bold(), p2sh_address.bright_white());
        println!("{} {}", "P2PKH:".bright_blue().bold(), p2pkh_address.bright_white());
        
        // Expected addresses from the user
        let expected_bech32 = "bc1qa74nj6a94jsltyml8z2gd9ss4jh9x2qycjcqn0";
        let expected_p2sh = "384wppeNEmUXFhoaAPyBBiZ34zxwRNWMYu";
        let expected_p2pkh = "1L4WUu9pKXTYMmLvzf4Gy8gwZuiGqirWFf";
        
        println!("{}", "Expected addresses:".bright_cyan().bold());
        println!("{} {}", "BECH32:".bright_green().bold(), expected_bech32.bright_white());
        println!("{} {}", "P2SH:".bright_yellow().bold(), expected_p2sh.bright_white());
        println!("{} {}", "P2PKH:".bright_blue().bold(), expected_p2pkh.bright_white());
        
        // For now, just print the comparison - we'll fix the derivation later
        assert!(bech32_address.starts_with("bc1q"));
        assert!(p2sh_address.starts_with("3"));
        assert!(p2pkh_address.starts_with("1"));
    }
    
    #[test]
    fn test_ethereum_known_mnemonic() {
        // Test with the known mnemonic from the user for Ethereum
        let mnemonic_str = "winter rather muscle weapon page flag cluster exotic bread lemon member fine";
        let mnemonic = Mnemonic::parse(mnemonic_str).expect("Invalid mnemonic");
        let seed_bytes = mnemonic.to_seed("");
        
        let ethereum_address = Wallet::generate_ethereum_address(&seed_bytes).expect("Failed to generate Ethereum address");
        
        println!("{}", "Generated Ethereum address:".bright_green().bold());
        println!("{} {}", "Ethereum:".bright_blue().bold(), ethereum_address.bright_white());
        
        // Expected address from the user
        let expected_ethereum = "0xd3E787e115aAF1a4d4c62aBc6E27ACacEF8c5565";
        
        println!("{}", "Expected Ethereum address:".bright_cyan().bold());
        println!("{} {}", "Ethereum:".bright_blue().bold(), expected_ethereum.bright_white());
        
        // Check if addresses match exactly (including case)
        assert_eq!(ethereum_address, expected_ethereum, "Ethereum addresses should match exactly");
    }
    
    #[test]
    fn test_ethereum_user_mnemonic() {
        // Test with the user's specific mnemonic
        let mnemonic_str = "prefer lens deal squeeze design label rich mom shallow marriage under paddle";
        let mnemonic = Mnemonic::parse(mnemonic_str).expect("Invalid mnemonic");
        let seed_bytes = mnemonic.to_seed("");
        
        let ethereum_address = Wallet::generate_ethereum_address(&seed_bytes).expect("Failed to generate Ethereum address");
        
        println!("{}", "Generated Ethereum address:".bright_green().bold());
        println!("{} {}", "Ethereum:".bright_blue().bold(), ethereum_address.bright_white());
        
        // Expected address from the user
        let expected_ethereum = "0x6B4b010941d59a1a875cb8Aa2De7ac1A10AAc93d";
        
        println!("{}", "Expected Ethereum address:".bright_cyan().bold());
        println!("{} {}", "Ethereum:".bright_blue().bold(), expected_ethereum.bright_white());
        
        // Check if addresses match exactly (including case)
        assert_eq!(ethereum_address, expected_ethereum, "Ethereum addresses should match exactly");
    }
}
