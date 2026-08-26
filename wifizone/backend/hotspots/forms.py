from django import forms

from routers.models import Router

from .models import HotspotLoginTemplate, HotspotProfile, Voucher


class HotspotProfileForm(forms.ModelForm):
    class Meta:
        model = HotspotProfile
        fields = (
            "router",
            "name",
            "mikrotik_profile",
            "validity_seconds",
            "data_limit_bytes",
            "shared_users",
            "price",
            "is_active",
        )
        labels = {
            "router": "Routeur",
            "name": "Nom affiché",
            "mikrotik_profile": "Profil MikroTik",
            "validity_seconds": "Validité (secondes)",
            "data_limit_bytes": "Limite data (octets)",
            "shared_users": "Utilisateurs partagés",
            "price": "Prix (FCFA)",
            "is_active": "Actif",
        }
        widgets = {
            "validity_seconds": forms.NumberInput(attrs={"placeholder": "3600 = 1h, 86400 = 1j"}),
            "data_limit_bytes": forms.NumberInput(attrs={"placeholder": "Vide = illimité"}),
            "price": forms.NumberInput(attrs={"placeholder": "500"}),
        }

    def __init__(self, user=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if user:
            self.fields["router"].queryset = Router.objects.filter(owner=user)
        for field in self.fields.values():
            if isinstance(field.widget, forms.CheckboxInput):
                field.widget.attrs.setdefault("class", "form-check-input")
            else:
                field.widget.attrs.setdefault("class", "form-control")


class HotspotLoginTemplateForm(forms.ModelForm):
    class Meta:
        model = HotspotLoginTemplate
        fields = (
            "name",
            "slug",
            "description",
            "html_body",
            "primary_color",
            "background_color",
            "wifi_name",
            "logo_url",
            "login_delay_seconds",
            "is_marketplace_public",
            "is_active",
        )
        labels = {
            "name": "Nom",
            "slug": "Identifiant (slug)",
            "description": "Description",
            "html_body": "HTML (variables: {{wifi_name}}, {{company_name}}, {{primary_color}})",
            "primary_color": "Couleur principale",
            "background_color": "Couleur de fond",
            "wifi_name": "Nom du WiFi affiché",
            "logo_url": "URL du logo",
            "login_delay_seconds": "Délai cyber café (secondes)",
            "is_marketplace_public": "Publier sur la marketplace",
            "is_active": "Actif",
        }
        widgets = {
            "html_body": forms.Textarea(attrs={"rows": 12, "class": "form-control font-monospace"}),
            "description": forms.Textarea(attrs={"rows": 2}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            if isinstance(field.widget, forms.CheckboxInput):
                field.widget.attrs.setdefault("class", "form-check-input")
            elif field.name != "html_body":
                field.widget.attrs.setdefault("class", "form-control")


class GenerateVoucherForm(forms.Form):
    router = forms.ModelChoiceField(
        queryset=Router.objects.none(),
        label="Routeur",
        empty_label=None,
    )
    profile = forms.ModelChoiceField(
        queryset=HotspotProfile.objects.none(),
        label="Profil",
        empty_label=None,
    )
    quantity = forms.IntegerField(
        min_value=1,
        max_value=500,
        initial=10,
        label="Quantité",
    )
    prefix = forms.CharField(
        max_length=10,
        required=False,
        label="Préfixe (optionnel)",
        widget=forms.TextInput(attrs={"placeholder": "WZ"}),
    )
    sync_mikrotik = forms.BooleanField(
        required=False,
        initial=True,
        label="Synchroniser sur MikroTik",
    )

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        routers = Router.objects.filter(owner=user, is_active=True)
        self.fields["router"].queryset = routers
        self.fields["profile"].queryset = HotspotProfile.objects.filter(
            router__owner=user,
            is_active=True,
        )
        for field in self.fields.values():
            if isinstance(field.widget, forms.CheckboxInput):
                field.widget.attrs.setdefault("class", "form-check-input")
            else:
                field.widget.attrs.setdefault("class", "form-control")


class VoucherFilterForm(forms.Form):
    q = forms.CharField(
        required=False,
        label="Rechercher",
        widget=forms.TextInput(attrs={"placeholder": "Code, username..."}),
    )
    status = forms.ChoiceField(
        required=False,
        label="Statut",
        choices=[("", "Tous")] + list(Voucher.Status.choices),
    )
    router = forms.ModelChoiceField(
        queryset=Router.objects.none(),
        required=False,
        label="Routeur",
        empty_label="Tous",
    )

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["router"].queryset = Router.objects.filter(owner=user)
        for field in self.fields.values():
            field.widget.attrs.setdefault("class", "form-control")
