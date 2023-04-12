from django.urls import path
from .views import *

urlpatterns = [
    path('generate_token/', GenerateToken.as_view(), name='generate_token'),
    path('create-user/', InsertUserView.as_view(), name='create_user'),

]
