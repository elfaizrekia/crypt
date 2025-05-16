import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
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

def generate_rsa_key_pair(key_size=2048):
    """
    Génère une paire de clés RSA
    """
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(data, public_key):
    """
    Chiffre des données avec une clé publique RSA
    Note: RSA a une limite de taille de données, donc nous utilisons une approche hybride 
    avec une clé AES chiffrée par RSA
    """
    # Charger la clé publique
    recipient_key = RSA.import_key(public_key)
    
    # Générer une clé de session aléatoire
    session_key = get_random_bytes(16)
    
    # Chiffrer la clé de session avec la clé publique RSA
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    
    # Chiffrer les données avec AES et la clé de session
    cipher_aes = AES.new(session_key, AES.MODE_CBC)
    ciphertext = cipher_aes.encrypt(pad(data, AES.block_size))
    
    # Combiner le tout (taille de la clé de session chiffrée + clé de session chiffrée + IV + données chiffrées)
    key_len = len(enc_session_key).to_bytes(2, byteorder='big')
    return key_len + enc_session_key + cipher_aes.iv + ciphertext

def rsa_decrypt(ciphertext, private_key):
    """
    Déchiffre des données avec une clé privée RSA
    """
    # Charger la clé privée
    key = RSA.import_key(private_key)
    
    # Extraire les composants
    key_len = int.from_bytes(ciphertext[:2], byteorder='big')
    enc_session_key = ciphertext[2:2+key_len]
    iv = ciphertext[2+key_len:2+key_len+16]
    encrypted_data = ciphertext[2+key_len+16:]
    
    # Déchiffrer la clé de session avec la clé privée RSA
    cipher_rsa = PKCS1_OAEP.new(key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    
    # Déchiffrer les données avec AES et la clé de session
    cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
    return unpad(cipher_aes.decrypt(encrypted_data), AES.block_size)

def save_encrypted_file(file, key, method='aes'):
    """
    Chiffre et sauvegarde un fichier
    """
    try:
        # Lire le contenu du fichier
        data = file.read()
        
        # Chiffrer les données selon la méthode choisie
        if method == 'aes':
            encrypted_data = aes_encrypt(data, key)
        elif method == 'rsa':
            # Dans ce cas, key est la clé publique RSA
            encrypted_data = rsa_encrypt(data, key)
        else:
            raise ValueError(f"Méthode de chiffrement non prise en charge: {method}")
        
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