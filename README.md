# Custom Tor-like Proxy

This project implements a custom Tor-like proxy with the goal routing mechanism as follows:

1. **Client:** Sends `Enc1(Enc2(Enc3(message)))` to `node1`.
2. **Node1:** Decrypts `Enc1`, forwards `Enc2(Enc3(message))` to `node2`.
3. **Node2:** Decrypts `Enc2`, forwards `Enc3(message)` to `node3`.
4. **Node3:** Decrypts `Enc3`, retrieves the original message, sends a response (e.g., to a server), receives a reply, encrypts it with its key `Enc3(reply)`, and sends it back to `node2`.
5. **Node2:** Encrypts the reply with its key `Enc2(Enc3(reply))` and sends it to `node1`.
6. **Node1:** Encrypts the reply with its key `Enc1(Enc2(Enc3(reply)))` and sends it to the client.
7. **Client:** Decrypts `Enc1`, `Enc2`, and `Enc3` to obtain the reply.
