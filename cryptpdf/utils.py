import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import uuid

def generate_key():
    return get_random_bytes(16)  # Clé AES 128 bits

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes  # IV concaténé au début

def aes_decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    ct = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

def save_encrypted_file(file, key):
    """
    Chiffre et sauvegarde un fichier
    """
    try:
        # Lire le contenu du fichier
        data = file.read()
        
        # Chiffrer les données
        encrypted_data = aes_encrypt(data, key)
        
        # Créer un nom de fichier unique pour éviter les conflits
        base_name = os.path.basename(file.name)
        unique_filename = f"encrypted_{uuid.uuid4().hex}_{base_name}"
        
        # Utiliser un chemin relatif à MEDIA_ROOT
        from django.conf import settings
        relative_path = os.path.join("encrypted", unique_filename)
        absolute_path = os.path.join(settings.MEDIA_ROOT, relative_path)
        
        # S'assurer que le répertoire existe
        os.makedirs(os.path.dirname(absolute_path), exist_ok=True)
        
        # Écrire les données chiffrées
        with open(absolute_path, "wb") as f:
            f.write(encrypted_data)
        
        # Retourner le chemin relatif et la clé
        return relative_path, key
        
    except Exception as e:
        # Journaliser l'erreur pour le débogage
        print(f"Erreur lors du chiffrement du fichier: {str(e)}")
        raise e