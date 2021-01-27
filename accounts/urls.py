from django.urls import path

from . import views

urlpatterns = [
    path('new', views.create, name='create'),
    path('<int:account_id>/save', views.save, name='save'),
    path('<int:account_id>/delete', views.delete, name='delete'),
    path('<int:account_id>/read', views.account_read, name='account_read'),
    path('<int:account_id>/edit', views.account_edit, name='account_edit'),
    path('<int:account_id>/share/<int:appuser_id>', views.share, name='share'),
    path('undo/<int:activity_id>', views.undo, name='undo'),
]