from django.urls import path
from . import views

app_name = 'app'

urlpatterns = [
    path('', views.index, name='index'),
    path('port-scan/', views.port_scan, name='port_scan'),
    path('run-nmap-scan/', views.run_nmap_scan, name='run_nmap_scan'),
    path('help/', views.help, name='help'),
]
