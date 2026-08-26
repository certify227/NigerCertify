from django import forms

from hotspots.models import HotspotLoginTemplate

from .models import Router


class RouterForm(forms.ModelForm):
    password = forms.CharField(
        label="Mot de passe API",
        widget=forms.PasswordInput(attrs={"placeholder": "Mot de passe API MikroTik"}),
        required=True,
    )

    class Meta:
        model = Router
        fields = ("name", "host", "port", "username", "hotspot_server", "login_template", "is_active", "snmp_enabled", "snmp_community")
        labels = {
            "name": "Nom du routeur",
            "host": "Adresse IP / hostname",
            "port": "Port API",
            "username": "Utilisateur API",
            "hotspot_server": "Serveur hotspot",
            "login_template": "Template login hotspot",
            "is_active": "Actif",
            "snmp_enabled": "SNMP activé",
            "snmp_community": "Communauté SNMP",
        }
        widgets = {
            "host": forms.TextInput(attrs={"placeholder": "192.168.88.1"}),
            "port": forms.NumberInput(attrs={"placeholder": "8728"}),
            "username": forms.TextInput(attrs={"placeholder": "admin"}),
        }

    def __init__(self, owner=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if owner:
            from django.db.models import Q

            self.fields["login_template"].queryset = HotspotLoginTemplate.objects.filter(
                Q(owner=owner) | Q(is_system=True),
                is_active=True,
            )
            self.fields["login_template"].required = False
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


class RadiusServerForm(forms.ModelForm):
    secret = forms.CharField(
        label="Secret RADIUS",
        widget=forms.PasswordInput,
        required=True,
    )

    class Meta:
        from .models import RadiusServer

        model = RadiusServer
        fields = ("name", "host", "auth_port", "acct_port", "nas_identifier", "is_enabled")
        labels = {
            "name": "Nom",
            "host": "Serveur RADIUS",
            "auth_port": "Port auth",
            "acct_port": "Port accounting",
            "nas_identifier": "NAS identifier",
            "is_enabled": "Actif",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            self.fields["secret"].required = False
        for field in self.fields.values():
            if isinstance(field.widget, forms.CheckboxInput):
                field.widget.attrs.setdefault("class", "form-check-input")
            else:
                field.widget.attrs.setdefault("class", "form-control")

    def save(self, commit=True):
        server = super().save(commit=False)
        secret = self.cleaned_data.get("secret")
        if secret:
            server.set_secret(secret)
        if commit:
            server.save()
        return server
