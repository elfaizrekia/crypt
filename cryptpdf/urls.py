# cryptpdf/urls.py

from django.urls import path
from . import views
from django.conf.urls.static import static
from django.conf import settings


urlpatterns = [
    
    path('', views.chiffrement_view, name='chiffrement_view'),
    path('download/<str:filename>/', views.download_file, name='download_file'), 
     

]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
