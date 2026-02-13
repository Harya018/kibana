print(">>> LOADING audit/views.py <<<")

# ✅ ALL IMPORTS AT THE TOP
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required

# ----------------------------
# HOME (PUBLIC)
# ----------------------------
def home(request):
    return render(request, "audit/home.html")

# ----------------------------
# LOGIN
# ----------------------------
def user_login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect("dashboard")
        else:
            return render(request, "audit/login.html", {"error": True})

    return render(request, "audit/login.html")

# ----------------------------
# TRANSACTIONS & ALERTS
# ----------------------------
from .models import Transaction
import random

def generate_dummy_transactions():
    types = ['DEBIT', 'CREDIT', 'TRANSFER']
    locations = ['New York', 'London', 'Tokyo', 'Paris', 'Berlin']
    for i in range(20):
        amount = random.uniform(100.0, 15000.0) # Some will be over 10000
        Transaction.objects.create(
            account_number=f"ACC-{random.randint(1000,9999)}",
            amount=round(amount, 2),
            transaction_type=random.choice(types),
            location=random.choice(locations)
        )

@login_required
def transaction_list(request):
    transactions = Transaction.objects.all().order_by('-timestamp')
    
    # Auto-generate data if empty (for demo)
    if not transactions.exists():
        generate_dummy_transactions()
        transactions = Transaction.objects.all().order_by('-timestamp')

    return render(request, "audit/transaction_list.html", {"transactions": transactions})

@login_required
def fraud_alerts(request):
    alerts = Transaction.objects.filter(is_flagged=True).order_by('-timestamp')
    return render(request, "audit/fraud_alerts.html", {"alerts": alerts})

# ----------------------------
# DASHBOARD (AUTH REQUIRED)
# ----------------------------
@login_required
def dashboard(request):
    total_transactions = Transaction.objects.count()
    total_alerts = Transaction.objects.filter(is_flagged=True).count()
    context = {
        "total_transactions": total_transactions,
        "total_alerts": total_alerts
    }
    return render(request, "audit/dashboard.html", context)
