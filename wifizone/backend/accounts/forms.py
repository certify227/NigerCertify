from django import forms
from django.contrib.auth.forms import UserCreationForm

from .models import User


class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True, label="Email")
    company_name = forms.CharField(max_length=200, required=False, label="Nom de la zone WiFi")
    phone = forms.CharField(max_length=30, required=False, label="Téléphone")
    city = forms.CharField(max_length=100, required=False, label="Ville")

    class Meta:
        model = User
        fields = ("username", "email", "company_name", "phone", "city", "password1", "password2")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            if not isinstance(field.widget, forms.CheckboxInput):
                field.widget.attrs.setdefault("class", "form-control")

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user


class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ("first_name", "last_name", "email", "company_name", "phone", "city", "country")
        labels = {
            "first_name": "Prénom",
            "last_name": "Nom",
            "email": "Email",
            "company_name": "Zone WiFi / entreprise",
            "phone": "Téléphone",
            "city": "Ville",
            "country": "Pays",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.setdefault("class", "form-control")
