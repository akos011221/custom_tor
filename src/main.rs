use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::seq::SliceRandom;
use std::env;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{copy, split, AsyncReadExt, AsyncWriteExt};

/// The `#[derive(Clonse)]` attribute automatically implement the
/// `Clone` trait, allowing instances of `RelayNode` to be duplicated.
/// This is required when passing data into asynchronous tasks
/// without losing ownership.
#[derive(Clone)]
struct RelayNode {
    address: String, // String is owned & heap-allocated
    pub_key: Vec<u8>, // Dynamically sized array of bytes
}

/// `choose_relay_path` selects a random relay path from a slice
/// of available nodes. 
fn choose_relay_path(nodes: &[RelayNode]) -> Vec<RelayNode> {
    // Random number generator sseeded by the OS.
    let mut rng = rand::thread_rng();
    // `choose_multiple` is provided by the `SliceRandom` trait.
    // It selects 3 random items from the slice. With `cloned()`
    // we create owned copies of the nodes (bc our function returns
    // a vector of wned `RelayNode` objects). Then, `collect()`
    // gathers the iterator into a new `Vec<RelayNode>`.
    nodes.choose_multiple(&mut rng, 3).cloned().collect()
}

/// `encrypt_layer` performs encryption for one layer in the onion
/// routing.
fn encrypt_layer(data: &[u8], key: &[u8]) -> Vec<u8> {
    // Create a new cipher using the provided key.
    // `new_from_slice` is a constructor method, returns a Result,
    // with `unwrap()` we extract the value or panic if the key
    // is invalid. 
    // TODO: handle the error gracefully.
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();

    // Create a nonce (number used once), it is required for AES-GCM.
    // This time, it is a fixed one, but we should generate a unique
    // one each time.
    let nonce = Nonce::from_slice(b"unique_nonce");

    // Encrypt the data using the cipher and nonce.
    // `encrypt` returns a Result, and `unwrap()` is used to get the
    // ciphertext, panicking on error. It's resulting in a `Vec<u8>`
    // that contains the encrypted bytes.
    cipher.encrypt(nonce, data).unwrap()
}

/// `decrypt_layer` decrypts one layer of the onion.
/// This reverses what is applied in `encrypt_layer`.
fn decrypt_layer(data: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce = Nonce::from_slice(b"unique_nonce");
    // The `decrypt` method attempts to reverse the encryption.
    cipher.decrypt(nonce, data).unwrap()
}

/// `encrypt_onion` applies onion encryption by wrapping the data in
/// multiple encryption layers. The nodes are processed in reverse
/// order so that the first node in the path will be the last layer
/// applied and thus the first to be removed during decryption.
fn encrypt_onion(data: &[u8], path: &[RelayNode]) -> Vec<u8> {
    let mut payload = data.to_vec(); // Convert the data slice into an owned vector.
    // Iterate over the relay nodes in reverse order.
    for node in path.iter().rev() {
        payload = encrypt_layer(&payload, &node.pub_key);
    }
    payload
}

/// `decrypt_onion` removes one layer of encryption using the relay's key.
/// Later, Eech relay would call this on the received data.
fn decrypt_onion(data: &[u8], key: &[u8]) -> Vec<u8> {
    decrypt_layer(data, key)
}

/// `run_client` runs the client mode, which construct an onion-encrypted
/// payload from a message, connnects to the first relay, sends the payload,
/// and then waits for a response.
async fn run_client() {
    // Define the available relay nodes.
    let relay_nodes = vec![
        RelayNode { address: "127.0.0.1:4004".to_string(), pub_key: vec![0; 32] },
        RelayNode { address: "127.0.0.1:4005".to_string(), pub_key: vec![0; 32] },
        RelayNode { address: "127.0.0.1:4006".to_string(), pub_key: vec![0; 32] },
    ];

    // Randomly select a relay path from the available nodes.
    let path = choose_relay_path(&relay_nodes);
    println!("Chosen relay path:");
    for node in &path {
        println!(" - {}", node.address);
    }

    // Use static message for now, later we'll read from standard input.
    let message = b"Hello..... testing through this network.";
    println!("Original message: {}", String::from_utf8_lossy(message));

    // Apply onion encryption by wrapping the message in multiple encryption layers.
    let onion_payload = encrypt_onion(message, &path);
    println!("Onion-encrypted payload  ({} bytes)", onion_payload.len());
    
    // Connect to the first relay node in the chosen path.
    let first_relay = &path[0];
    println!("Connecting to first relay: {}", first_relay.address);
    let mut stream = TcpStream::connect(&first_relay.address).await.unwrap();

    // Send the fully onion-encrypted payload.
    stream.write_all(&onion_payload).await.unwrap();
    println!("Payload sent. Waiting for response...");

    // Read the response from the relay.
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();

    // Assume the response is encrypted by the first relay's layer.
    // We remove decryption by removing that layer.
    let decrypted_response = decrypt_onion(&response, &first_relay.pub_key);
    println!("Decrypted response: {}", String::from_utf8_lossy(&decrypted_response));
}

/// `run_relay` runs the relay mode, which listens on `port`, accepts connections,
/// decrypts one layer of the onion, and echoes the decrypted payload back.
/// TODO: relay should forward the payload to the next hop.
async fn run_relay(port: u16) {
    let addr = format!("0.0.0.0:{}", port);
    println!("Relay listening on {}", addr);
    let listener = TcpListener::bind(&addr).await.unwrap();

    // For now each relay uses a fixed key.
    let key = vec![0; 32];

    loop {
        // Accept incoming TCP connection.
        let (mut stream, client_addr) = listener.accept().await.unwrap();
        println!("Accepted connection from {}", client_addr);

        // Copy the key, so each task gets its own copy.
        let key_clone = key.clone();

        // Spawn a new asynchronous task to handle this connection concurrently.
        tokio::spawn(async move {
            let mut buf = Vec::new();
            // Read all data from the stream.
            stream.read_to_end(&mut buf).await.unwrap();
            println!("Received {} bytes", buf.len());
            
            // Decrypt one layer of the onion using the relay's key.
            let decrypted = decrypt_onion(&buf, &key_clone);
            println!("Decrypted payload: {}", String::from_utf8_lossy(&decrypted));

            // For now, simply echo the decrypted payload back to the client.
            stream.write_all(&decrypted).await.unwrap();
            println!("Echoed back the decrypted payload");
        });
    }
}

/// The `#[tokio::main]` macro sets up the Tokio runtime, allowing us to use async/await
/// in the main function.
#[tokio::main]
async fn main() {
    // Collect command-line arguments into a vector of strings.
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} [client|relay] [port (if relay)]", args[0]);
        return;
    }

    // Match on the first argument to determine the mode.
    match args[1].as_str() {
        "client" => run_client().await,
        "relay" => {
            // If a port is provided as the second argument, parse it; otherwise use 4004.
            let port = if args.len() > 2 {
                args[2].parse::<u16>().unwrap_or(4004)
            } else {
                4004
            };
            run_relay(port).await
        }

        _ => eprintln!("Unknown mode: {}. Use 'client' or 'relay'.", args[1]),
    }
}
