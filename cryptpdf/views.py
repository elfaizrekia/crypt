from django.shortcuts import render
from django.core.files.storage import FileSystemStorage
from .utils import generate_key, aes_encrypt, save_encrypted_file, generate_rsa_key_pair, rsa_encrypt
import uuid
import os
from django.http import FileResponse, Http404, HttpResponse, JsonResponse
from django.conf import settings
from .forms import ChiffrementForm
from django.urls import reverse
import json
import base64
from .utils import generate_key, aes_encrypt, save_encrypted_file, generate_rsa_key_pair, rsa_encrypt, encrypt_3des, decrypt_3des


def chiffrement_view(request):
    download_url = None
    key = None
    private_key = None
    public_key = None
    method = None
    input_type = None
    filename = None

    if request.method == 'POST':
        form = ChiffrementForm(request.POST, request.FILES)
        if form.is_valid():
            method = form.cleaned_data['method']
            input_type = form.cleaned_data['input_type']
            
            # Traitement AES
            if method == 'aes':
                key = generate_key()
                if input_type == 'text':
                    text = form.cleaned_data['text'].encode('utf-8')  # Encodage explicite en UTF-8
                    encrypted_data = aes_encrypt(text, key)
                    filename = f"encrypted_text_{uuid.uuid4().hex}.aes"
                    path = os.path.join(settings.MEDIA_ROOT, "encrypted", filename)
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "wb") as f:
                        f.write(encrypted_data)
                    download_url = reverse('download_file', args=[filename])
                elif input_type == 'file' and 'pdf_file' in request.FILES:
                    pdf_file = request.FILES['pdf_file']
                    file_path, _ = save_encrypted_file(pdf_file, key, method='aes')
                    download_url = reverse('download_file', args=[os.path.basename(file_path)])
            
            # Traitement RSA
            elif method == 'rsa':
                private_key, public_key = generate_rsa_key_pair()
                if input_type == 'text':
                    text = form.cleaned_data['text'].encode('utf-8')  # Encodage explicite en UTF-8
                    encrypted_data = rsa_encrypt(text, public_key)
                    filename = f"encrypted_text_{uuid.uuid4().hex}.rsa"
                    path = os.path.join(settings.MEDIA_ROOT, "encrypted", filename)
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "wb") as f:
                        f.write(encrypted_data)
                    download_url = reverse('download_file', args=[filename])
                elif input_type == 'file' and 'pdf_file' in request.FILES:
                    pdf_file = request.FILES['pdf_file']
                    file_path, _ = save_encrypted_file(pdf_file, public_key, method='rsa')
                    filename = os.path.basename(file_path)
                    download_url = reverse('download_file', args=[filename])

            #Traitement 3DES
            elif method == '3des':
                if input_type == 'text':
                    text = form.cleaned_data['text'].encode('utf-8')
                    encrypted_data, key, iv = encrypt_3des(text)
                    filename = f"encrypted_text_{uuid.uuid4().hex}.3des"
                    path = os.path.join(settings.MEDIA_ROOT, "encrypted", filename)
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "wb") as f:
                        f.write(encrypted_data)
                    download_url = reverse('download_file', args=[filename])
                elif input_type == 'file' and 'pdf_file' in request.FILES:
                    pdf_file = request.FILES['pdf_file']
                    file_path, _ = save_encrypted_file(pdf_file, (key, iv), method='3des')
                    filename = os.path.basename(file_path)
                    download_url = reverse('download_file', args=[filename])
    
    else:
        form = ChiffrementForm()

    # Préparer les données à envoyer au template
    context = {
        'form': form,
        'download_url': download_url,
        'filename': filename,
    }

    # Ajouter les clés/chiffres selon la méthode
    if method == 'aes' and key:
        context['key'] = key.hex()
    elif method == 'rsa':
        if private_key and public_key:
            context['private_key'] = private_key.decode('utf-8')
            context['public_key'] = public_key.decode('utf-8')
    
    elif method == '3des' and key and iv:
        context['key'] = key.hex()
        context['iv'] = iv.hex()


    return render(request, "cryptpdf/index.html", context)


def save_encrypted_file(file, key, method='aes'):
    """
    Fonction dédiée pour chiffrer et sauvegarder un fichier
    """
    file_content = file.read()
    
    if method == 'aes':
        encrypted_content = aes_encrypt(file_content, key)
        ext = '.aes'
    elif method == 'rsa':
        encrypted_content = rsa_encrypt(file_content, key)
        ext = '.rsa'
    elif method == '3des':
        key, iv = key  # tuple
        encrypted_content, _, _ = encrypt_3des(file_content, key, iv)
        ext = '.3des'

    else:
        raise ValueError(f"Méthode de chiffrement non prise en charge: {method}")
    
    original_name = os.path.splitext(file.name)[0]
    filename = f"encrypted_{uuid.uuid4().hex}_{original_name}{ext}"
    path = os.path.join(settings.MEDIA_ROOT, "encrypted", filename)
    
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(encrypted_content)
    
    return path, filename


def download_file(request, filename):
    """
    Vue pour télécharger le fichier chiffré
    """
    full_path = os.path.join(settings.MEDIA_ROOT, "encrypted", filename)
    
    if os.path.exists(full_path):
        response = FileResponse(open(full_path, 'rb'), as_attachment=True)
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
    else:
        raise Http404(f"File {filename} not found in encrypted directory")


def download_key(request):
    """
    Vue améliorée pour télécharger les clés
    """
    if request.method == 'POST':
        key_type = request.POST.get('key_type')
        key_data = request.POST.get('key_data')
        
        if key_type and key_data:
            filename = f"{key_type}_key.pem" if key_type in ['private', 'public'] else f"{key_type}.key"
            
            response = HttpResponse(key_data, content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            return response
    
    raise Http404("Invalid request")


def preview_encrypt(request):
    """
    API pour générer un aperçu du chiffrement côté serveur
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            text = data.get('text', '')
            method = data.get('method', 'aes')
            
            if not text:
                return JsonResponse({'error': 'Texte requis'}, status=400)
            
            result = None
            if method == 'aes':
                key = generate_key()
                encrypted = aes_encrypt(text.encode('utf-8'), key)
                result = base64.b64encode(encrypted).decode('utf-8')
            elif method == 'rsa':
                _, public_key = generate_rsa_key_pair()
                encrypted = rsa_encrypt(text.encode('utf-8'), public_key)
                result = base64.b64encode(encrypted).decode('utf-8')
                
            return JsonResponse({'encrypted': result})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
            
    return JsonResponse({'error': 'Méthode non autorisée'}, status=405)