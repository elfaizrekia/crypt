from django import forms

class ChiffrementForm(forms.Form):
    INPUT_CHOICES = [
        ('text', 'Texte'),
        ('file', 'Fichier'),
    ]
    
    METHOD_CHOICES = [
        ('aes', 'AES'),
        ('rsa', 'RSA'),
        ('3des', '3DES'),
    ]
    
    input_type = forms.ChoiceField(choices=INPUT_CHOICES, initial='text')
    method = forms.ChoiceField(choices=METHOD_CHOICES, initial='aes')
    text = forms.CharField(widget=forms.Textarea, required=False)
    pdf_file = forms.FileField(required=False)
    
    def clean(self):
        cleaned_data = super().clean()
        input_type = cleaned_data.get('input_type')
        
        # Valider que le champ approprié est rempli selon le type d'entrée
        if input_type == 'text' and not cleaned_data.get('text'):
            self.add_error('text', 'Veuillez entrer un texte à chiffrer.')
        elif input_type == 'file' and not cleaned_data.get('pdf_file'):
            self.add_error('pdf_file', 'Veuillez sélectionner un fichier PDF à chiffrer.')
            
        return cleaned_data