def xor_encrypt_decrypt(message_bytes, key_bytes):
    repeated_key = (key_bytes * (len(message_bytes) // len(key_bytes) + 1))[:len(message_bytes)]
    result_bytes = bytes([message_byte ^ key_byte
                         for message_byte, key_byte
                         in zip(message_bytes, repeated_key)])
    return result_bytes


def encrypt_message():
    print("\n=== ENCRYPTION MODE ===")
    user_message = input("Enter your secret message: ")
    encryption_key = input("Enter your encryption key: ")
   
    message_bytes = user_message.encode('utf-8')
    key_bytes = encryption_key.encode('utf-8')
   
    encrypted_bytes = xor_encrypt_decrypt(message_bytes, key_bytes)
   
    key_hex = key_bytes.hex()
   
    print("\n--- ENCRYPTION RESULTS ---")
    print(f"Original message: {user_message}")S
    print(f"Key used: {encryption_key}")
    print(f"Key (hex): {key_hex}")
    print(f"Encrypted data (hex): {encrypted_bytes.hex()}")


    filename = "encrypted_message.txt"
    with open(filename, "w") as file:
        file.write(encrypted_bytes.hex())
    print(f"Encrypted message saved to '{filename}' as hex string")


    print(f"\n*** COPY THIS KEY (HEX) FOR DECRYPTION: {key_hex} ***")


def decrypt_message():
    print("\n=== DECRYPTION MODE ===")
   
    print("1. Enter hex data manually")
    hex_data = input("Enter encrypted hex data: ").strip()
   
    try:
        encrypted_bytes = bytes.fromhex(hex_data)
    except ValueError:
        print("Error: Invalid hex data!")
        return
   
    decryption_key_hex = input("Enter your decryption key (hex): ")
    try:
        key_bytes = bytes.fromhex(decryption_key_hex)
    except ValueError:
        print("Error: Invalid hex key!")
        return
   
    try:
        decrypted_bytes = xor_encrypt_decrypt(encrypted_bytes, key_bytes)
        decrypted_message = decrypted_bytes.decode('utf-8')
       
        print("\n--- DECRYPTION RESULTS ---")
        print(f"Key used (hex): {decryption_key_hex}")
        print(f"Decrypted message: {decrypted_message}")
       
    except UnicodeDecodeError:
        print("Error: Failed to decrypt. Check if the key is correct.")


def main():
    print("XOR Encryption/Decryption Tool")
    print("=" * 35)
   
    while True:
        print("\nChoose an option:")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Exit")
       
        choice = input("Enter your choice (1-3): ").strip()
       
        if choice == "1":
            encrypt_message()
        elif choice == "2":
            decrypt_message()
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice! Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()

