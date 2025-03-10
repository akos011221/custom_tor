use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::seq::SliceRandom;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{copy, split};

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
    let nonce = Nonce::from_slice(b"unique_nonce_");

    // Encrypt the data using the cipher and nonce.
    // `encrypt` returns a Result, and `unwrap()` is used to get the
    // ciphertext, panicking on error. It's resulting in a `Vec<u8>`
    // that contains the encrypted bytes.
    cipher.encrypt(nonce, data).unwrap()
}

/// `handle_client` is asynchronous, handles an invidual client connection.
async fn handle_client(inbound: TcpStream, relay_nodes: Vec<RelayNode>) {
    // Choose a random relay path from the lsit of relay nodes.
    let path = choose_relay_path(&relay_nodes);
    // Get the final node in the path, that will be the exit node.
    // `.last()` returns an `Option<&RelayNode>, so with `unwrap`,
    // we can get the value.
    let _final_node = path.last().unwrap();

    // Establish a TCP to the first relay node in the path.
    // `TcpStream::connect` returns a Future, which we `await`
    // to get the actual connection.
    let outbound = TcpStream::connect(&path[0].address).await.unwrap();

    // `split` divides bidirectional `TcpStream` into two parts:
    // (ri/ro) for reading, (wi/wo) for writing.
    // It's useful when handling input and output concurrently.
    let (mut ri, mut wi) = split(inbound);
    let (mut ro, mut wo) = split(outbound);

    // For now, we use a static plaintext message. // TODO: read from `ri`.
    // We encrypt the plaintext using the public key of the first relay node.
    let _encrypted_request = encrypt_layer(b"User request data", &path[0].pub_key);

    // Spawn an asynchronous task to handle data flow from the client to the relay.
    // `tokio::spawn` takes an async block (or a Future) and runs it concurrently.
    tokio::spawn(async move {
        // `copy` continously reads from the client's read half (`ri`) and writes
        // to the relay's write half (`wo`). It handles asynchronous transfer of 
        // data until the end-of-stream (EOF).
        let _ = copy(&mut ri, &mut wo).await;
        // TODO: Implement error handling.
    });
        
    // Spawn another asynchronous task to handle data flow in the reverse
    // direction: from the relay back to the client.
    tokio::spawn(async move {
        // This copies data from the relay's read half (`ro`) to the client's
        // write half (`wi`).
        let _ = copy(&mut ro, &mut wi).await;
        // TODO: Implement error handling.
    });
}

/// The `#[tokio::main]` macro sets up the Tokio runtime, allowing us to use async/await
/// in the main function.
#[tokio::main]
async fn main() {
    // `bind` method returns a Future that resolves to a `TcpListener` once the binding
    // is successful.
    let listener = TcpListener::bind("0.0.0.0:4004").await.unwrap();

    // Some fake relay nodes in the initial code.
    // `to_string()` converts string literals into owned `String` types.
    // For now the public keys are vectors of 32 zeroed bytes.
    // TODO: Implement `pub_key` as actual cryptographic keys.
    let relay_nodes = vec![
        RelayNode { address: "10.120.0.1:9000".to_string(), pub_key: vec![0; 32] },
        RelayNode { address: "10.120.0.2:9001".to_string(), pub_key: vec![0; 32] },
        RelayNode { address: "10.120.0.3:9002".to_string(), pub_key: vec![0; 32] },
    ];
    
    // This infinite loop continously accepts incoming TCP connections.
    loop {
        // `accept` method wait asynchronously for an incoming connection.
        // It returns a tuple: `TcpStream` and the client's socket address.
        let (stream, _) = listener.accept().await.unwrap();
        // Because of ownership rules, we clone the `relay_nodes` vector, so each connection
        // handler has its own copy. It is required, because ownership in Rust means only one
        // part of the code can own the data at a time.
        let nodes_clone = relay_nodes.clone();

        // Spawn an asynchronous task to handle the client connection.
        // This allows the main loop to continue accepting new connections concurrently.
        tokio::spawn(async move {
            handle_client(stream, nodes_clone).await;
        });
    }
}
