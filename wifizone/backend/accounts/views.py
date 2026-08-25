from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView, LogoutView
from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy

from accounts.tenant import can_manage_team, get_operator, is_team_owner
from billing.services import activate_trial, get_user_subscription

from .forms import ProfileForm, RegisterForm, TeamMemberForm
from .models import TeamMembership


class UserLoginView(LoginView):
    template_name = "accounts/login.html"
    redirect_authenticated_user = True


class UserLogoutView(LogoutView):
    next_page = reverse_lazy("dashboard:landing")


def register(request):
    if request.user.is_authenticated:
        return redirect("dashboard:home")

    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            activate_trial(user)
            login(request, user)
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
    members = TeamMembership.objects.filter(owner=operator).select_related("member")
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
        form = TeamMemberForm(request.POST)
        if form.is_valid():
            form.save(owner=operator)
            messages.success(request, "Employé ajouté.")
            return redirect("accounts:team_list")
    else:
        form = TeamMemberForm()

    return render(request, "accounts/team_form.html", {"form": form})


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
