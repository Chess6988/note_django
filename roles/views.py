from django.shortcuts import render, redirect
from django.contrib.auth import login
from django.contrib import messages
from .models import User, SuperadminInvitation
from django.utils import timezone
from django.http import HttpResponseForbidden

# One-time Superadmin Setup
def initial_superadmin_setup(request):
    if User.objects.filter(is_superadmin=True).exists():
        return HttpResponseForbidden("Superadmin already exists.")
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = User.objects.create_superuser(username=username, password=password, is_superadmin=True)
        user.save()
        login(request, user)
        return redirect('dashboard')
    return render(request, 'roles/initial_setup.html')

# Superadmin Dashboard
def dashboard(request):
    if not request.user.is_superadmin:
        return HttpResponseForbidden("Access denied.")
    invitations = SuperadminInvitation.objects.filter(inviter=request.user, is_used=False)
    return render(request, 'roles/dashboard.html', {'invitations': invitations})

# Invite New Superadmin
def invite_superadmin(request):
    if not request.user.is_superadmin:
        return HttpResponseForbidden("Access denied.")
    if request.method == 'POST':
        recipient_name = request.POST['recipient_name']
        invitation = SuperadminInvitation.objects.create(inviter=request.user, recipient_name=recipient_name)
        invitation_url = request.build_absolute_uri(f'/accounts/verify-invitation/{invitation.token}/')
        messages.success(request, f"Invitation created! Link: {invitation_url} | PIN: {invitation.pin}")
        return redirect('dashboard')
    return render(request, 'roles/invite_superadmin.html')

# Verify Invitation
def verify_invitation(request, token):
    try:
        invitation = SuperadminInvitation.objects.get(token=token, is_used=False)
        if invitation.is_expired():
            messages.error(request, "This invitation has expired.")
            return redirect('initial_superadmin_setup')
        if request.method == 'POST':
            pin = request.POST['pin']
            if pin == invitation.pin:
                return redirect('superadmin_signup', token=token)
            else:
                messages.error(request, "Invalid PIN.")
        return render(request, 'roles/verify_invitation.html', {'token': token})
    except SuperadminInvitation.DoesNotExist:
        messages.error(request, "Invalid or used invitation link.")
        return redirect('initial_superadmin_setup')

# Superadmin Signup
def superadmin_signup(request, token):
    try:
        invitation = SuperadminInvitation.objects.get(token=token, is_used=False)
        if invitation.is_expired():
            messages.error(request, "This invitation has expired.")
            return redirect('initial_superadmin_setup')
        if request.method == 'POST':
            username = request.POST['username']
            password = request.POST['password']
            password_confirm = request.POST['password_confirm']
            if password == password_confirm:
                user = User.objects.create_user(username=username, password=password, is_superadmin=True)
                invitation.is_used = True
                invitation.save()
                login(request, user)
                messages.success(request, "Superadmin account created successfully!")
                return redirect('dashboard')
            else:
                messages.error(request, "Passwords do not match.")
        return render(request, 'roles/superadmin_signup.html', {'token': token})
    except SuperadminInvitation.DoesNotExist:
        messages.error(request, "Invalid or used invitation link.")
        return redirect('initial_superadmin_setup')