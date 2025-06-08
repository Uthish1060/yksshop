from django.contrib import admin
from .models import Profile, PendingUser

admin.site.register(Profile)
admin.site.register(PendingUser)
