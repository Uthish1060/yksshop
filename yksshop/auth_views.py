from django.contrib.auth import views as auth_views
from django.urls import reverse_lazy

class CustomPasswordResetView(auth_views.PasswordResetView):
    template_name = 'shop/password_reset.html'
    email_template_name = 'shop/password_reset_email.html'
    success_url = reverse_lazy('password_reset_done')
    extra_email_context = {'site_name': 'YKS Shop'}

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['reset_step'] = 'password_reset'  # Step 1: Email form
        return context

class CustomPasswordResetDoneView(auth_views.PasswordResetDoneView):
    template_name = 'shop/password_reset.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['reset_step'] = 'password_reset_done'  # Step 2: Email sent confirmation
        return context

class CustomPasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    template_name = 'shop/password_reset.html'
    success_url = reverse_lazy('password_reset_complete')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['reset_step'] = 'password_reset_confirm'  # Step 3: Set new password form
        return context

class CustomPasswordResetCompleteView(auth_views.PasswordResetCompleteView):
    template_name = 'shop/password_reset.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['reset_step'] = 'password_reset_complete'  # Step 4: Password reset complete confirmation
        return context
