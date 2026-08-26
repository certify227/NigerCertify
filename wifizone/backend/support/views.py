from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render, get_object_or_404
from django.contrib import messages

from accounts.tenant import get_operator
from support.models import SupportTicket, TicketReply


@login_required
def ticket_list(request):
    operator = get_operator(request.user)
    tickets = SupportTicket.objects.filter(operator=operator)
    return render(request, "support/ticket_list.html", {"tickets": tickets})


@login_required
def ticket_create(request):
    operator = get_operator(request.user)
    if request.method == "POST":
        SupportTicket.objects.create(
            operator=operator,
            subject=request.POST["subject"],
            message=request.POST["message"],
            priority=request.POST.get("priority", "normal"),
        )
        messages.success(request, "Ticket créé.")
        return redirect("support:list")
    return render(request, "support/ticket_form.html")


@login_required
def ticket_detail(request, pk):
    operator = get_operator(request.user)
    ticket = get_object_or_404(SupportTicket, pk=pk, operator=operator)
    if request.method == "POST":
        TicketReply.objects.create(
            ticket=ticket,
            author=request.user,
            message=request.POST["message"],
        )
        return redirect("support:detail", pk=pk)
    return render(request, "support/ticket_detail.html", {"ticket": ticket})
