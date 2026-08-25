from django import forms

from .models import Router


class RouterForm(forms.ModelForm):
    password = forms.CharField(
        label="Mot de passe API",
        widget=forms.PasswordInput(attrs={"placeholder": "Mot de passe API MikroTik"}),
        required=True,
    )

    class Meta:
        model = Router
        fields = ("name", "host", "port", "username", "hotspot_server", "is_active")
        labels = {
            "name": "Nom du routeur",
            "host": "Adresse IP / hostname",
            "port": "Port API",
            "username": "Utilisateur API",
            "hotspot_server": "Serveur hotspot",
            "is_active": "Actif",
        }
        widgets = {
            "host": forms.TextInput(attrs={"placeholder": "192.168.88.1"}),
            "port": forms.NumberInput(attrs={"placeholder": "8728"}),
            "username": forms.TextInput(attrs={"placeholder": "admin"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            self.fields["password"].required = False
            self.fields["password"].help_text = "Laisser vide pour ne pas changer"
        for field in self.fields.values():
            if isinstance(field.widget, forms.CheckboxInput):
                field.widget.attrs.setdefault("class", "form-check-input")
            else:
                field.widget.attrs.setdefault("class", "form-control")

    def save(self, commit=True):
        router = super().save(commit=False)
        password = self.cleaned_data.get("password")
        if password:
            router.set_password(password)
        if commit:
            router.save()
        return router
