from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, UsernameField
from django.forms import TextInput
from django import forms


class CustomResetPSWForm(AuthenticationForm):
    email = UsernameField(widget=forms.TextInput(attrs={'autofocus': True, 'class': "form-control"}))
    password = forms.CharField(
        label="Password",
        strip=False,
        widget=forms.PasswordInput(attrs={'autocomplete': 'current-password', 'class': "form-control"}),
    )
