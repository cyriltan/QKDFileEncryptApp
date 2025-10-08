import oqs

def pqc_key_exchange():
    # Choose a PQC KEM algorithm (e.g., Kyber1024)
    kem_algorithm = "Kyber1024"

    # Party A (server) generates a key pair
    with oqs.KeyEncapsulation(kem_algorithm) as server_kem:
        # Generate the key pair
        public_key = server_kem.generate_keypair()
        print(f"[Server] Public Key: {public_key.hex()}")

        # Party B (client) generates a shared secret and encapsulates it
        with oqs.KeyEncapsulation(kem_algorithm) as client_kem:
            # Client encapsulates using the server's public key
            ciphertext, shared_secret_client = client_kem.encap_secret(public_key)
            print(f"[Client] Ciphertext: {ciphertext.hex()}")
            print(f"[Client] Shared Secret (Client): {shared_secret_client.hex()}")

        # Server decapsulates the ciphertext to derive the shared secret
        shared_secret_server = server_kem.decap_secret(ciphertext)
        print(f"[Server] Shared Secret (Server): {shared_secret_server.hex()}")

        # Verify that both parties have the same shared secret
        assert shared_secret_client == shared_secret_server, "Key exchange failed!"
        print("Key exchange successful! Both parties have the same shared secret.")

        # Extract the shared secret key for further use
        shared_key = shared_secret_server  # or shared_secret_client, both are the same
        print(f"Extracted Shared PQC Key: {shared_key.hex()}")

if __name__ == "__main__":
    pqc_key_exchange()
