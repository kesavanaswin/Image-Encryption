from PIL import Image
import numpy as np
import hashlib
import os

# ==================== YOUR PATH ADDED HERE ====================
DEFAULT_SAVE_FOLDER = r"D:\Internship\Image"  # Your requested path
# ==============================================================

# Automatically create the folder if it doesn't exist
os.makedirs(DEFAULT_SAVE_FOLDER, exist_ok=True)
print(f"Default save folder created/verified: {DEFAULT_SAVE_FOLDER}")

def get_full_path(filename):
    """Combine default folder with filename and ensure .png extension."""
    if not filename.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp')):
        filename += ".png"
    return os.path.join(DEFAULT_SAVE_FOLDER, filename)

def generate_key_array(image_array, password):
    """Generate reproducible pseudo-random key array from password."""
    seed_bytes = hashlib.sha256(password.encode('utf-8')).digest()
    seed_int = int.from_bytes(seed_bytes, 'big')
    rng = np.random.RandomState(seed_int % (2**32))
    key_array = rng.randint(0, 256, size=image_array.shape, dtype=np.uint8)
    return key_array

def encrypt_image(image_path, password, custom_output=None):
    """Encrypt image and save to D:\Internship\Image by default."""
    if not os.path.isfile(image_path):
        print(f"Error: File not found:\n   '{image_path}'")
        print("Tip: Include full path and file extension (e.g., D:\\Internship\\Image\\photo.jpg)")
        return False
    
    try:
        img = Image.open(image_path)
        img_array = np.array(img)
        print(f"Image loaded: {img.size[0]}x{img.size[1]} pixels ({img.mode})")
        
        key_array = generate_key_array(img_array, password)
        encrypted_array = np.bitwise_xor(img_array, key_array)
        encrypted_img = Image.fromarray(encrypted_array.astype(np.uint8))
        
        # Use custom path if provided, else your default folder
        if custom_output and custom_output.strip():
            save_path = custom_output.strip().strip('"')
            if not save_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp')):
                save_path += ".png"
        else:
            save_path = get_full_path("encrypted_image.png")
        
        encrypted_img.save(save_path)
        
        print(f"\n✅ Encryption successful!")
        print(f"Encrypted image saved to:\n   {os.path.abspath(save_path)}")
        print(f"🔑 Password: '{password}' → Save this for decryption!")
        return True
        
    except Exception as e:
        print(f"Error during encryption: {e}")
        return False

def decrypt_image(encrypted_path, password, custom_output=None):
    """Decrypt image and save to D:\Internship\Image by default."""
    if not os.path.isfile(encrypted_path):
        print(f"Error: Encrypted file not found:\n   '{encrypted_path}'")
        return False
    
    try:
        encrypted_img = Image.open(encrypted_path)
        encrypted_array = np.array(encrypted_img)
        
        key_array = generate_key_array(encrypted_array, password)
        decrypted_array = np.bitwise_xor(encrypted_array, key_array)
        decrypted_img = Image.fromarray(decrypted_array.astype(np.uint8))
        
        # Use custom path if provided, else your default folder
        if custom_output and custom_output.strip():
            save_path = custom_output.strip().strip('"')
            if not save_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp')):
                save_path += ".png"
        else:
            save_path = get_full_path("decrypted_image.png")
        
        decrypted_img.save(save_path)
        
        print(f"\n✅ Decryption successful!")
        print(f"Original image recovered and saved to:\n   {os.path.abspath(save_path)}")
        return True
        
    except Exception as e:
        print(f"Error during decryption: {e}")
        print("💡 Hint: Check if password matches the encryption password.")
        return False

def main():
    print("=" * 70)
    print("     🎨 Image Encryption & Decryption Tool (Pixel XOR)")
    print(f"     📁 Default Save Folder: {DEFAULT_SAVE_FOLDER}")
    print("=" * 70)
    
    while True:
        print("\nOptions:")
        print("1. Encrypt Image")
        print("2. Decrypt Image") 
        print("3. Exit")
        
        choice = input("\nEnter choice (1/2/3): ").strip()
        
        if choice == "1":
            print("\n--- 🔐 ENCRYPTION ---")
            image_path = input("Enter full path to original image\n(e.g., D:\\Internship\\Image\\photo.jpg): ").strip().strip('"')
            password = input("Enter strong password: ").strip()
            if not password:
                password = "prodigy2025"
                print("Using default password: 'prodigy2025'")
            
            custom_save = input(f"Custom save path (Enter for default {DEFAULT_SAVE_FOLDER}): ").strip().strip('"')
            print("\nEncrypting image...")
            encrypt_image(image_path, password, custom_save or None)
            
        elif choice == "2":
            print("\n--- 🔓 DECRYPTION ---")
            encrypted_path = input("Enter path to encrypted image: ").strip().strip('"')
            password = input("Enter decryption password: ").strip()
            
            custom_save = input(f"Custom save path (Enter for default {DEFAULT_SAVE_FOLDER}): ").strip().strip('"')
            print("\nDecrypting image...")
            decrypt_image(encrypted_path, password, custom_save or None)
            
        elif choice == "3":
            print("\n👋 Thanks for using the tool! Files saved in your folder.")
            break
            
        else:
            print("❌ Invalid choice. Enter 1, 2, or 3.")

if __name__ == "__main__":
    main()