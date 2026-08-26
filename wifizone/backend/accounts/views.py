from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView, LogoutView
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy
from django.utils import timezone
from datetime import timedelta
import secrets

from accounts.tenant import can_manage_team, get_operator, is_team_owner
from billing.services import activate_trial, get_user_subscription
from hotspots.services.qr import qr_code_base64

from .forms import ProfileForm, RegisterForm, TeamInviteForm, TeamMemberForm
from .models import TeamInvitation, TeamMembership
from .totp_utils import ensure_totp_secret, get_provisioning_uri, verify_totp_code


class UserLoginView(LoginView):
    template_name = "accounts/login.html"
    redirect_authenticated_user = True

    def form_valid(self, form):
        response = super().form_valid(form)
        user = self.request.user
        if user.totp_enabled:
            self.request.session["totp_verified"] = False
            return redirect("accounts:totp_verify")
        self.request.session["totp_verified"] = True
        return response


class UserLogoutView(LogoutView):
    next_page = reverse_lazy("dashboard:landing")

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            request.session.pop("totp_verified", None)
        return super().dispatch(request, *args, **kwargs)


def register(request):
    if request.user.is_authenticated:
        return redirect("dashboard:home")

    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            activate_trial(user)
            login(request, user)
            request.session["totp_verified"] = True
            return redirect("dashboard:home")
    else:
        form = RegisterForm()

    return render(request, "accounts/register.html", {"form": form})


@login_required
def profile(request):
    operator = get_operator(request.user)
    if request.method == "POST" and is_team_owner(request.user):
        form = ProfileForm(request.POST, instance=operator)
        if form.is_valid():
            form.save()
            return redirect("accounts:profile")
    else:
        form = ProfileForm(instance=operator if is_team_owner(request.user) else request.user)

    subscription = get_user_subscription(operator)
    return render(
        request,
        "accounts/profile.html",
        {"form": form, "subscription": subscription, "is_owner": is_team_owner(request.user)},
    )


@login_required
def team_list(request):
    operator = get_operator(request.user)
    members = TeamMembership.objects.filter(owner=operator).select_related("member", "point_of_sale")
    invitations = TeamInvitation.objects.filter(owner=operator, accepted=False)
    sub = get_user_subscription(operator)
    can_add = (
        can_manage_team(request.user)
        and sub
        and members.filter(is_active=True).count() < sub.plan.max_staff
    )
    return render(
        request,
        "accounts/team_list.html",
        {
            "members": members,
            "invitations": invitations,
            "subscription": sub,
            "can_manage": can_manage_team(request.user),
            "can_add": can_add,
            "is_owner": is_team_owner(request.user),
        },
    )


@login_required
def team_add(request):
    if not can_manage_team(request.user):
        messages.error(request, "Multi-utilisateurs disponible sur forfait Enterprise.")
        return redirect("accounts:team_list")

    operator = get_operator(request.user)
    sub = get_user_subscription(operator)
    count = TeamMembership.objects.filter(owner=operator, is_active=True).count()
    if sub and count >= sub.plan.max_staff:
        messages.error(request, f"Limite employés atteinte ({sub.plan.max_staff} max).")
        return redirect("accounts:team_list")

    if request.method == "POST":
        form = TeamMemberForm(request.POST, operator=operator)
        if form.is_valid():
            form.save(owner=operator)
            messages.success(request, "Employé ajouté.")
            return redirect("accounts:team_list")
    else:
        form = TeamMemberForm(operator=operator)

    return render(request, "accounts/team_form.html", {"form": form})


@login_required
def team_invite(request):
    if not can_manage_team(request.user):
        messages.error(request, "Permission refusée.")
        return redirect("accounts:team_list")

    operator = get_operator(request.user)
    if request.method == "POST":
        form = TeamInviteForm(request.POST)
        if form.is_valid():
            token = secrets.token_urlsafe(32)
            invite = TeamInvitation.objects.create(
                owner=operator,
                email=form.cleaned_data["email"],
                role=form.cleaned_data["role"],
                token=token,
                expires_at=timezone.now() + timedelta(days=7),
            )
            link = request.build_absolute_uri(
                reverse_lazy("accounts:accept_invite", kwargs={"token": invite.token})
            )
            send_mail(
                subject="Invitation équipe WiFiZone Pro",
                message=f"Vous êtes invité par {operator.display_name}. Lien : {link}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[invite.email],
                fail_silently=True,
            )
            messages.success(request, f"Invitation envoyée à {invite.email}")
            return redirect("accounts:team_list")
    else:
        form = TeamInviteForm()

    return render(request, "accounts/team_invite.html", {"form": form})


def accept_invite(request, token):
    invite = get_object_or_404(TeamInvitation, token=token, accepted=False)
    if invite.expires_at < timezone.now():
        messages.error(request, "Invitation expirée.")
        return redirect("accounts:login")

    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        if username and password:
            from accounts.models import User

            user = User.objects.create_user(username=username, password=password, email=invite.email)
            membership = TeamMembership(
                owner=invite.owner,
                member=user,
                role=invite.role,
                is_active=True,
            )
            membership.apply_role_defaults()
            membership.save()
            invite.accepted = True
            invite.save()
            login(request, user)
            request.session["totp_verified"] = True
            messages.success(request, "Compte créé. Bienvenue !")
            return redirect("dashboard:home")

    return render(request, "accounts/accept_invite.html", {"invite": invite})


@login_required
def team_toggle(request, pk):
    if not can_manage_team(request.user):
        messages.error(request, "Permission refusée.")
        return redirect("accounts:team_list")

    operator = get_operator(request.user)
    membership = get_object_or_404(TeamMembership, pk=pk, owner=operator)
    membership.is_active = not membership.is_active
    membership.save()
    messages.success(request, "Statut employé mis à jour.")
    return redirect("accounts:team_list")


@login_required
def team_remove(request, pk):
    if not can_manage_team(request.user):
        messages.error(request, "Permission refusée.")
        return redirect("accounts:team_list")

    operator = get_operator(request.user)
    membership = get_object_or_404(TeamMembership, pk=pk, owner=operator)
    if request.method == "POST":
        membership.delete()
        messages.success(request, "Employé retiré de l'équipe.")
        return redirect("accounts:team_list")
    return render(request, "accounts/team_remove.html", {"membership": membership})


@login_required
def totp_settings(request):
    user = request.user
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "enable":
            code = request.POST.get("code", "")
            if verify_totp_code(user, code):
                user.totp_enabled = True
                user.save(update_fields=["totp_enabled"])
                messages.success(request, "2FA activée.")
            else:
                messages.error(request, "Code invalide.")
        elif action == "disable":
            user.totp_enabled = False
            user.save(update_fields=["totp_enabled"])
            request.session["totp_verified"] = True
            messages.success(request, "2FA désactivée.")

    ensure_totp_secret(user)
    uri = get_provisioning_uri(user)
    qr = qr_code_base64(uri)
    return render(
        request,
        "accounts/totp_settings.html",
        {"user": user, "provisioning_uri": uri, "qr_base64": qr},
    )


@login_required
def totp_verify(request):
    if not request.user.totp_enabled:
        return redirect("dashboard:home")

    if request.method == "POST":
        code = request.POST.get("code", "")
        if verify_totp_code(request.user, code):
            request.session["totp_verified"] = True
            return redirect("dashboard:home")
        messages.error(request, "Code incorrect.")

    return render(request, "accounts/totp_verify.html")
