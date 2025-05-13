from django.shortcuts import render
from django.core.files.storage import FileSystemStorage
from .utils import generate_key, aes_encrypt, save_encrypted_file
import uuid
import os
from django.http import FileResponse, Http404
from django.conf import settings
from .forms import ChiffrementForm
from django.urls import reverse

def chiffrement_view(request):
    download_url = None
    key = None

    if request.method == 'POST':
        form = ChiffrementForm(request.POST, request.FILES)
        if form.is_valid():
            method = form.cleaned_data['method']
            input_type = form.cleaned_data['input_type']

            if method == 'aes':
                key = generate_key()
                if input_type == 'text':
                    text = form.cleaned_data['text'].encode()
                    encrypted_data = aes_encrypt(text, key)
                    filename = "encrypted_text.aes"
                    path = os.path.join(settings.MEDIA_ROOT, "encrypted", filename)
                    os.makedirs(os.path.join(settings.MEDIA_ROOT, "encrypted"), exist_ok=True)
                    with open(path, "wb") as f:
                        f.write(encrypted_data)
                    download_url = f"/download/encrypted_text.aes"
                elif input_type == 'file':
                    # Vérifier si un fichier PDF a été téléchargé
                    if 'pdf_file' in request.FILES:
                        pdf_file = request.FILES['pdf_file']
                        # Générer un nom de fichier unique pour éviter les conflits
                        unique_filename = f"encrypted_{uuid.uuid4().hex}_{pdf_file.name}"
                        # Chiffrer et sauvegarder le fichier
                        file_path, _ = save_encrypted_file(pdf_file, key)
                        # Créer l'URL pour le téléchargement
                        download_url = reverse('download_file', args=[f"{os.path.basename(file_path)}.aes"])
    else:
        form = ChiffrementForm()

    return render(request, "cryptpdf/index.html", {
        'form': form,
        'download_url': download_url,
        'key': key.hex() if key else None
    })

def save_encrypted_file(file, key):
    # Lire le contenu du fichier
    file_content = file.read()
    
    # Chiffrer le contenu
    encrypted_content = aes_encrypt(file_content, key)
    
    # Générer un nom de fichier unique avec extension .aes
    original_name = os.path.splitext(file.name)[0]  # Remove original extension
    filename = f"encrypted_{uuid.uuid4().hex}_{original_name}.aes"
    path = os.path.join(settings.MEDIA_ROOT, "encrypted", filename)
    
    # Sauvegarder
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(encrypted_content)
    
    return path, filename  # Return both path and the final filename

def download_file(request, filename):
    full_path = os.path.join(settings.MEDIA_ROOT, "encrypted", filename)
    print(f"Looking for file at: {full_path}")  # Debug output
    
    if os.path.exists(full_path):
        response = FileResponse(open(full_path, 'rb'), as_attachment=True, filename=filename)
        return response
    else:
        print(f"File not found at: {full_path}")  # Debug output
        raise Http404(f"File {filename} not found in encrypted directory")