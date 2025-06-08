from django.urls import path
from . import views
from . import auth_views

urlpatterns = [
    path('',views.login_view,name="login"),
    path('register',views.register_view,name="register"),
    path('accounts/registration-pending/', views.registration_pending, name='registration_pending'),
    path('home',views.homepage,name="homepage"),
    path('password-reset/', auth_views.CustomPasswordResetView.as_view(), name='password_reset'),
    path('password-reset/done/', auth_views.CustomPasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', auth_views.CustomPasswordResetCompleteView.as_view(), name='password_reset_complete'),
    path('verify-otp/', views.verify_otp_view, name='verify_otp'),
    path('activate/<uidb64>/<token>/', views.activate_view, name='activate'),

]
