from django.contrib import admin
from django.urls import path, include
from . import views  # Ensure this import is present
from django.core.exceptions import ValidationError
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path('', views.home, name='home'),
    path('index', views.home, name='home'),

    path('predict', views.predict_liver_disease, name='predict'),
    path('results', views.liver_results, name='liver_results'),
    path('predict_heart', views.predict_heart_disease, name='predict_heart'),
    path('predict/result', views.predict_result, name='predict_result'),
    path('predict_diabetes', views.predict_diabetes, name='predict_diabetes'),
    path('diabetes_results', views.diabetes_results, name='diabetes_results'),
    
    path('register' , views.register , name = 'register') ,
    path('login', views.user_login, name='login'),  # Updated to use 'user_login'
    path('logout', views.custom_logout, name='logout'),

    path('dashboard/dashboard', views.dashboard, name='dashboard'),
    
    path('dashboard/diabetes_prediction', views.dashboard_diabetes_prediction, name='dashboard_diabetes_prediction'),
    path('dashboard/diabetes_prediction/diabetes_results', views.dashboard_diabetes_results, name='dashboard_diabetes_results'),
    path('dashboard/liver_prediction', views.dashboard_liver_prediction, name='dashboard_liver_prediction'),
    path('dashboard/liver_prediction/liver_results', views.dashboard_liver_results, name='dashboard_liver_results'),
    path('dashboard/heart_prediction', views.dashboard_heart_prediction, name='dashboard_heart_prediction'),
    path('dashboard/heart_prediction/heart_results', views.dashboard_heart_results, name='dashboard_heart_results'),

    path('dashboard/track_medication', views.dashboard_track_medication, name='dashboard_track_medication'),

    # path('dashboard/', views.dashboard_track_medication, name='dashboard_track_medication'),
    path('dashboard/add-medication/', views.add_medication, name='add_medication'),
    path('dashboard/mark-dose/<int:log_id>/<str:status>/', views.mark_dose, name='mark_dose'),

    path('googleapi', views.googleapi, name='googleapi'),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)