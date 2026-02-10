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
# DASHBOARD (AUTH REQUIRED)
# ----------------------------
@login_required
def dashboard(request):
    return render(request, "audit/dashboard.html")
