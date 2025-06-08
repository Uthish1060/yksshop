from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
import random

from .models import Profile, PendingUser
from .tokens import account_activation_token  # Ensure this is defined correctly
from django.contrib.auth.hashers import make_password

# Delete expired PendingUser entries (older than 5 minutes)
def delete_expired_pending_users():
    expiry = timezone.now() - timedelta(minutes=5)
    PendingUser.objects.filter(otp_created_at__lt=expiry).delete()


def homepage(request):
    return render(request, 'shop/home.html')


def register_view(request):
    delete_expired_pending_users()

    if request.method == 'POST':
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        phone = request.POST.get('phone', '').strip()
        email = request.POST.get('email', '').strip().lower()
        password1 = request.POST.get('password1', '')
        password2 = request.POST.get('password2', '')

        if password1 != password2:
            return render(request, 'shop/register.html', {'error': 'Passwords do not match'})

        if User.objects.filter(email=email).exists() or PendingUser.objects.filter(email=email).exists():
            return render(request, 'shop/register.html', {'error': 'Email is already registered or pending verification'})

        otp = str(random.randint(100000, 999999))
        hashed_password = make_password(password1)

        PendingUser.objects.create(
            email=email,
            first_name=first_name,
            last_name=last_name,
            phone=phone,
            otp=otp,
            password_hash=hashed_password
        )

        # Send OTP email
        html_content = render_to_string('shop/send_otp_email.html', {
            'first_name': first_name,
            'otp': otp,
        })

        msg = EmailMultiAlternatives(
            subject='Verify your YKS Shop account with OTP',
            body='',
            from_email='no-reply@yks.com',
            to=[email]
        )
        msg.attach_alternative(html_content, 'text/html')
        msg.send()

        return render(request, 'shop/enter_otp.html', {'email': email})

    return render(request, 'shop/register.html')


def verify_otp_view(request):
    delete_expired_pending_users()

    if request.method == 'POST':
        email = request.POST.get('email')
        otp_input = request.POST.get('otp')

        try:
            pending_user = PendingUser.objects.get(email=email)

            if pending_user.otp == otp_input:
                pending_user.is_email_verified = True
                pending_user.save()

                # Generate fake user to sign token
                fake_user = User(username=pending_user.email, email=pending_user.email, is_active=False)
                fake_user.pk = hash(pending_user.email) % (10 ** 8)

                uid = urlsafe_base64_encode(force_bytes(fake_user.pk))
                token = account_activation_token.make_token(fake_user)

                activation_link = request.build_absolute_uri(
                    reverse('activate', kwargs={'uidb64': uid, 'token': token})
                )

                html_content = render_to_string('shop/activation_email.html', {
                    'activation_link': activation_link,
                    'user': pending_user,
                })

                msg = EmailMultiAlternatives(
                    subject='Activate your YKS Shop account',
                    body='',
                    from_email='no-reply@yks.com',
                    to=[email]
                )
                msg.attach_alternative(html_content, 'text/html')
                msg.send()

                return render(request, 'shop/registration_pending.html')

            else:
                return render(request, 'shop/enter_otp.html', {'error': 'Invalid OTP', 'email': email})

        except PendingUser.DoesNotExist:
            return redirect('register')

    return redirect('register')


def activate_view(request, uidb64, token):
    delete_expired_pending_users()

    try:
        for pending_user in PendingUser.objects.filter(is_email_verified=True):
            fake_user = User(username=pending_user.email, email=pending_user.email, is_active=False)
            fake_user.pk = hash(pending_user.email) % (10 ** 8)

            if urlsafe_base64_encode(force_bytes(fake_user.pk)) == uidb64:
                if account_activation_token.check_token(fake_user, token):
                    if User.objects.filter(email=pending_user.email).exists():
                        return render(request, 'shop/activation_invalid.html')

                    real_user = User.objects.create_user(
                        username=pending_user.email,
                        email=pending_user.email,
                        first_name=pending_user.first_name,
                        last_name=pending_user.last_name,
                        password=None  # set manually
                    )
                    real_user.password = pending_user.password_hash
                    real_user.is_active = True
                    real_user.save()

                    Profile.objects.update_or_create(user=real_user, defaults={'phone': pending_user.phone})
                    pending_user.delete()

                    return render(request, 'shop/activation_success.html')

        return render(request, 'shop/activation_invalid.html')
    except Exception as e:
        print("Activation error:", e)
        return render(request, 'shop/activation_invalid.html')


def login_view(request):
    error_message = None

    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            user_obj = User.objects.get(email=email)
            user = authenticate(request, username=user_obj.username, password=password)
            if user:
                login(request, user)
                return redirect('homepage')
            else:
                error_message = 'Invalid password'
        except User.DoesNotExist:
            error_message = 'No user with this email'

    return render(request, 'shop/login.html', {'error_message': error_message})


def registration_pending(request):
    return render(request, 'shop/registration_pending.html')
