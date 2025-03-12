use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Error as AesGcmError};
use rand::seq::SliceRandom;
use std::env;
use std::convert::TryInto;
use serde::{Deserialize, Deserializer};
use serde_json;
use hex;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The #[derive(Deserialize)] attribute tells the Rust compiler to automatically
/// generate code that can convert JSON data into this struct. Without this, we had 
/// to write the conversion logic manually.
///
/// The #[derive(Clone)] attribute automatically implement the `Clone` trait, allowing
/// instances of `RelayConfig` to be duplicated.
#[derive(Deserialize)]
#[derive(Clone)]
struct RelayConfig {
    address: String,
    // Use custom function to convert `pub_key` hexadecimal string into Vec<u8>.
    // This avoids boilerplate codes, better for error handling, as if there's
    // something wrong, it is catched during the deserialization process.
    // Also, it makes it clearer that `pub_key` is expected to be a hex string
    // that we want to convert to bytes.
    #[serde(deserialize_with = "deserialize_hex_to_bytes")]
    pub_key: Vec<u8>,
}

/// The Directory struct represents the overall configuration.
/// The JSON structure must match the structure of this Rust type.
#[derive(Deserialize)]
struct Directory {
    relays: Vec<RelayConfig>,
}

/// --- `deserialize_hex_to_bytes` ---
///
/// Custom deserialization function for hex string to Vec<u8>.
/// For more details, refer to the comments inside the `RelayConfig`
/// struct's `pub_key` field.
fn deserialize_hex_to_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    // Deserialize the hex string
    let hex_string = String::deserialize(deserializer)?;

    // Convert the hex string to Vec<u8>
    hex::decode(&hex_string).map_err(serde::de::Error::custom)
}

/// --- `load_relay_list` ---
///
/// Reads the configuration file from the provided path, parses
/// the JSON and returns a Directory struct.
fn load_relay_list(path: &str) -> Directory {
    // Read the entire file into a String.
    // expect() here will panic if reading fails.
    let config_text = std::fs::read_to_string(path)
        .expect("Unable to read config file. Ensure the file exists and is in the correct location.");

    // Parse the JSON text into our Directory struct using serde_json.
    // serde_json::from_str takes a &str and returns a Result<Directory, _>.
    // expect() will panic if the JSON is malformed.
    let directory: Directory = serde_json::from_str(&config_text)
        .expect("JSON format error: Check that the file is correctly formatted.");

    directory
}

/// --- `choose_relay_path` ---
///
/// Randomly selects a path from the available `RelayConfig` objects.
/// Uses the `SliceRandom` trait's `choose_multiple` method, makes it
/// possible that each client session can have a randomized path.
fn choose_relay_path(nodes: &[RelayConfig]) -> Vec<RelayConfig> {
    let mut rng = rand::thread_rng(); // Creates a random number generator (rng), seeded from the
                                      // OS.
    // `choose_multiple` select 3 random nodes from the slice. We then clone the selected nodes
    // (creating owned copies) and collect them into a new `Vec<RelayConfig>`.
    nodes.choose_multiple(&mut rng, 3).cloned().collect()
}

/// --- `create_relay_header` ---
///
/// builds a message header that is prependeed to
/// the payload. The header format is:
/// [4 bytes: next hop address length][next hop address (if any)][payload]
/// - If `next_hop` is `Some(addr)`, we encode its length and bytes.
/// - If `next_hop` is `None`, we encode 0 (meaning this is the exit node).
fn create_relay_header(next_hop: Option<&str>, payload: Vec<u8>) -> Vec<u8> {
    let mut message = Vec::new();
    match next_hop {
        Some(addr) => {
            let addr_bytes = addr.as_bytes();
            // Convert length of next hop address into a 4-byte big-endian
            // representation.
            let len = (addr_bytes.len() as u32).to_be_bytes();
            message.extend(&len);
            message.extend(addr_bytes);
        }
        None => {
            // Zero length indicates that it's an exit node.
            message.extend(&0u32.to_be_bytes());
        }
    }
    // Append the remaining payload.
    message.extend(payload);
    message
}

/// --- `parse_relay_header` ---
///
/// Parses a message that begins with a 4-byte header (length of next hop).
/// The input is a `&Result<Vec<u8>, AesGcmError>`, which represents the decrypted payload.
///
/// Returns a `Result` containing:
/// - An `Option<String>`: the next hop address (if present),
/// - A `Vec<u8>`: the remaining payload.
///
/// If the input is an `Err`, the error is propagated.
/// If the header is malformed (e.g., too short or invalid), an `AesGcmError` is returned.
fn parse_relay_header(data: &Result<Vec<u8>, AesGcmError>) -> Result<(Option<String>, Vec<u8>), AesGcmError> {
    // Ensure there are at least 4 bytes for the length field.
    let bytes = match data {
        Ok(vec) => vec,
        Err(e) => return Err(e.clone()), // Clone the error to avoid ownership issue.
    };
    
    // Ensure there are at least 4 bytes data.
    if bytes.len() < 4 {
        return Err(AesGcmError);
    }

    // Read the first 4 bytes and convert them into a u32 (big-endian).
    let len = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;

    // Ensure there are enough bytes for the next hop.
    if bytes.len() < 4 + len {
        return Err(AesGcmError);
    }

    // If length is non-zero, extract the next hop address.
    let next_hop = if len > 0 {
        Some(String::from_utf8_lossy(&bytes[4..4 + len]).to_string())
    } else {
        None
    };

    // The remainder is the payload.
    let payload = bytes[4 + len..].to_vec();

    Ok((next_hop, payload))
}

/// --- `encrypt_layer` ---
///
/// Encrypts one layer of data using AES-256-GCM with a fixed nonce (for now).
/// The nonce has to be 12-bytes to satisfy AES-GCM.
fn encrypt_layer(data: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce = Nonce::from_slice(b"unique_nonce");
    cipher.encrypt(nonce, data).unwrap()
}

/// --- `decrypt_layer` ---
///
/// Decrypts one layer of the onion. It reverses what we apply in `encrypt_layer`.
fn decrypt_layer(data: &[u8], key: &[u8]) -> Result<Vec<u8>, AesGcmError>{
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce = Nonce::from_slice(b"unique_nonce");
    cipher.decrypt(nonce, data)
}

/// --- `encrypt_onion` ---
///
/// Applies onion encryption by wrapping the data in multiple encryption layers.
/// Process: For each relay node in the provided `path` (iterated in reverse order),
/// we prepend a header that indicates the next hop (or None for exit nodes) and
/// then encrypt the current payload using the node's key.
fn encrypt_onion(data: &[u8], path: &[RelayConfig]) -> Vec<u8>{
    // Initial payload is the plaintext.
    let mut payload = data.to_vec();
    // Iterate over the relay nodes in reverse order (from exit to entry).
    for (i, node) in path.iter().enumerate().rev() {
        // Determine next hop:
        // For the last one (exit node), there is no next hop.
        // For others, next hop is the address of the subsequent node.
        let next_hop = if i == path.len() - 1 {
            None
        } else {
            Some(path[i + 1].address.as_str())
        };
        // Create a header for this layer and prepend it to the current payload.
        let header = create_relay_header(next_hop, payload);
        // Encrypt the combined header and payload with the current node's key.
        payload = encrypt_layer(&header, &node.pub_key);
    }
    payload
}

/// --- `decrypt_onion` ---
///
/// Removes one layer of encryption from the onion using the relay's key.
/// In the reverse path, each relay (or client) will call this to peel off
/// one layer.
fn decrypt_onion(data: &[u8], key: &[u8]) -> Result<Vec<u8>, AesGcmError> {
    decrypt_layer(data, key)
}

/// --- `run_client`
///
/// In client mode, we build an onion payload and send it to the first relay.
/// Then we wait for the response and peel off the onion layers to retrieve
/// the original message.
async fn run_client(relays: &[RelayConfig]) {

    // Randomly choose a relay path from the available nodes.
    let path = choose_relay_path(relays);
    println!("Chosen relay path:");
    for node in &path {
        println!(" - {}", node.address);
    }

    // Some static message for now. 
    let message = b"This is my message."; 
    println!("Original message: {}", String::from_utf8_lossy(message));

    // Build onion-encrypted payload.
    let onion_payload = encrypt_onion(message, &path);
    println!("Onion-encrypted payload ({} bytes): {}", onion_payload.len(), hex::encode(&onion_payload));

    // Connect to the first relay in the chosen path.
    let first_relay = &path[0];
    println!("Connecting to first relay: {}", first_relay.address);
    let mut stream = TcpStream::connect(&first_relay.address).await.unwrap();

    // Send the complete onion payload to the first relay.
    stream.write_all(&onion_payload).await.unwrap();
    println!("Payload sent. Waiting for response...");

    // Shutdown the write side to signal EOF.
    stream.shutdown().await.unwrap();

    // Read the response from the first relay.
    let mut response = Vec::new();
    match stream.read_to_end(&mut response).await {
        Ok(bytes) => println!("Received {} bytes", bytes),
        Err(e) => {
            println!("Failed to read response: {}", e);
            return;
        }
    }

    // Peel off the onion layers from the response.
    let mut decrypted_response = response;
    // We iterate from the first relay (entry) to the last.
    for node in &path {
        decrypted_response = match decrypt_onion(&decrypted_response, &node.pub_key) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Failed to decrypt layer: {:?}", e);
                return;
            }
        };
    }

    println!("Decrypted response: {}", String::from_utf8_lossy(&decrypted_response));
}

/// --- `run_relay` ---
///
/// Each relay performs the following tasks:
/// 1) Read the incoming data.
/// 2) Decrypt one layer using its own key.
/// 3) Parse the header to determine the next hop and the inner payload.
/// 4) If there's a next hop, connect to it, forward the payload, and wait for response.
/// 5) If there's no next hop, it is an exit node. Process the payload (echo it back for now).
async fn run_relay(port: u16, relays: &[RelayConfig]) {
    let addr = format!("0.0.0.0:{}", port);
    println!("Relay listening on {}", addr);
    let listener = TcpListener::bind(&addr).await.unwrap();

    // Find this relay's key based on its address.
    let relay = relays.iter()
        .find(|r| r.address == format!("127.0.0.1:{}", port))
        .expect("Relay not found in the configuration.");
    let key = relay.pub_key.clone();

    loop {
        // Accept an incoming connection.
        let (mut stream, client_addr) = listener.accept().await.unwrap();
        println!("Accepted connection from {}", client_addr);

        // Clone the key for use in the spawned task.
        let key_clone = key.clone();

        tokio::spawn(async move {
            let mut buf = Vec::new();
            // Read the message from the stream.
            stream.read_to_end(&mut buf).await.unwrap();
            println!("Received {} bytes.", buf.len());

            // Decrypt this relay's layer.
            let decrypted_layer = decrypt_onion(&buf, &key_clone);
            // Parse the header to extract next hop (if there's any) and the inner payload.
            if let Ok((next_hop_opt, inner_payload)) = parse_relay_header(&decrypted_layer) {
                // Determine the response that will be sent upstream.
                let response_payload = if let Some(next_hop) = next_hop_opt {
                    // Not the exit node: forward the inner payload to the next hop.
                    println!("Forwarding payload to the next hop: {}", next_hop);
                    // Establish connection to the next relay.
                    let mut next_stream = TcpStream::connect(&next_hop).await.unwrap();
                    // Send the inner payload.
                    next_stream.write_all(&inner_payload).await.unwrap();
                    // Shutdown write to signal EOF.
                    next_stream.shutdown().await.unwrap();
                    // Read the response from next hop.
                    let mut next_response = Vec::new();
                    next_stream.read_to_end(&mut next_response).await.unwrap();
                    println!("Received {} bytes from next hop", next_response.len());
                    next_response
                } else {
                    // Exit node: process the payload. For now, we only echo it back.
                    println!("Exit node reached. Processing payload...");
                    inner_payload
                };

                // Re-encrypt the response using this relay's key before sending it back upstream.
                let encrypted_response = encrypt_layer(&response_payload, &key_clone);
                stream.write_all(&encrypted_response).await.unwrap();
                println!("Sent encrypted response upstream.");
            }
        });
    }
}

/// --- Application Entry Point ---
///
/// The `#[tokio::main]` initializes tokio runtime, allowing us to use async/await in main.
/// The program's mode (client or relay) and port (if relay) are determined via command-line arguments.
#[tokio::main]
async fn main() {
    // Collect command-line arguments.
    let args: Vec<String>  = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} [client|relay] [port (if relay)]", args[0]);
        return;
    }
    
    // Load the configuration from the specified file.
    let config_path = "config/relays.json";

    let directory = load_relay_list(config_path);

    // Print the relay nodes that we loaded from the config file.
    println!("Loaded relays:");
    for relay in &directory.relays {
        println!("Address: {}, Public key: {}", relay.address, hex::encode(&relay.pub_key));
    }

    // Determine mode based on first argument.
    match args[1].as_str() {
        "client" => run_client(&directory.relays).await,
        "relay" => {
            // If a port is provided as the second argument, parse it; otherwise, default to 1234.
            let port = if args.len() > 2 {
                args[2].parse::<u16>().unwrap_or(1234)
            } else {
                1234
            };
            run_relay(port, &directory.relays).await
        }
        _ => eprintln!("Unknown mode: {}. Use 'client' or 'relay'.", args[1]),
    }
}


