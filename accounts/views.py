from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User
import datetime

from users.models import AppUser
from .models import Account, Ownership
from activities.models import Activity
from security.aescipher import AESCipher

def create(request):
    if request.method == 'POST':
        # Get form values
        web_address = request.POST['web_address']
        login = request.POST['login']
        password = request.POST['password']
        description = request.POST['description']
        # Encrypt password
        password_hash = request.user.password
        cipher = AESCipher(password_hash)
        encrypted_password = cipher.encrypt(password)
        # Save 
        appuser = AppUser.objects.get(user=request.user)
        account = Account.objects.create(password=encrypted_password, web_address=web_address, description=description, login=login)
        account.save()
        ownership = Ownership.objects.create(appuser=appuser, account=account, is_owner=True)
        ownership.save()
        # Register activity
        curr_value = account.web_address + ';' + account.login + ';' + account.password + ';' + account.description
        activity = Activity.objects.create(appuser=AppUser.objects.get(user=request.user), account=account, previous_value='', current_value=curr_value, time=datetime.datetime.now(), action='Create')
        # Dedirect to wallet
        return redirect('wallet_edit')
    else:
        return render(request, 'accounts/account_new.html')

def account_edit(request, account_id):
    # Get account
    account = get_object_or_404(Account, pk=account_id)
    appusers = account.appusers.all()
    for appuser in appusers:
        ownership = Ownership.objects.get(appuser=appuser, account=account)
        if ownership.is_owner:
            password_hash = appuser.user.password
    # password_hash = request.user.password
    # Get available users
    user = User.objects.get(username=request.user.username)  
    appuser = AppUser.objects.get(user=user)
    available_users = AppUser.objects.all().exclude(user=user)
    # Check if owner
    ownership = Ownership.objects.get(appuser=appuser, account=account)
    if ownership.is_owner:
        owner = True
    else:
        owner = False
    # Decrypt password
    cipher = AESCipher(password_hash)
    clean_password = cipher.decrypt(account.password)
    # Get activities for account
    activities = Activity.objects.filter(account=account).order_by('-time')
    last_activity = activities.first()
    context = {
        'account': account,
        'clean_password': clean_password,
        'available_users': available_users,
        'owner': owner,
        'last_activity': last_activity,
        'activities': activities
    }
    return render(request, 'accounts/account_edit.html', context)

def account_read(request, account_id):
    # Get account
    account = get_object_or_404(Account, pk=account_id)
    appusers = account.appusers.all()
    for appuser in appusers:
        ownership = Ownership.objects.get(appuser=appuser, account=account)
        if ownership.is_owner:
            password_hash = appuser.user.password
    # password_hash = request.user.password
    # Get available users
    user = User.objects.get(username=request.user.username)  
    appuser = AppUser.objects.get(user=user)
    available_users = AppUser.objects.all().exclude(user=user)
    # Check if owner
    ownership = Ownership.objects.get(appuser=appuser, account=account)
    if ownership.is_owner:
        owner = True
    else:
        owner = False
    # Decrypt password
    cipher = AESCipher(password_hash)
    clean_password = cipher.decrypt(account.password)
    # Get activities for account
    activities = Activity.objects.filter(account=account).order_by('-time')
    last_activity = activities.first()
    context = {
        'account': account,
        'clean_password': clean_password,
        'available_users': available_users,
        'owner': owner,
        'last_activity': last_activity,
        'activities': activities
    }
    return render(request, 'accounts/account_read.html', context)

def save(request, account_id):
    if request.method == 'POST':
        # Get account
        account = Account.objects.get(pk=account_id)
        prev_account = Account.objects.create(web_address=account.web_address, login=account.login, password=account.password, description=account.description)
        # Get form values
        web_address = request.POST['web_address']
        login = request.POST['login']
        password = request.POST['password']
        description = request.POST['description']
        # Encrypt password
        password_hash = request.user.password
        cipher = AESCipher(password_hash)
        encrypted_password = cipher.encrypt(password)
        # Save 
        account.web_address = web_address
        account.login = login
        account.password = encrypted_password
        account.description = description
        account.save()
        # Get appuser
        user = User.objects.get(username=request.user.username)  
        appuser = AppUser.objects.get(user=user)
        # Register activity
        prev_value = prev_account.web_address + ';' + prev_account.login + ';' + prev_account.password + ';' + prev_account.description
        curr_value = account.web_address + ';' + account.login + ';' + account.password + ';' + account.description
        activity = Activity.objects.create(appuser=appuser, account=account, previous_value=prev_value, current_value=curr_value, time=datetime.datetime.now(), action='Update')
        # Dedirect to wallet
        return redirect('wallet_edit')
    else:
        return render(request, 'accounts/account_edit.html')

def delete(request, account_id):
    # Get appuser
    user = User.objects.get(username=request.user.username)  
    appuser = AppUser.objects.get(user=user)
    # Get account
    account = Account.objects.get(pk=account_id)
    account.deleted = True
    account.save()
    # Register activity
    prev_value = account.web_address + ';' + account.login + ';' + account.password + ';' + account.description
    activity = Activity.objects.create(appuser=appuser, account=account, previous_value=prev_value, current_value='', time=datetime.datetime.now(), action='Delete')
    return redirect('wallet_edit')

def share(request, account_id, appuser_id):
    account = Account.objects.get(pk=account_id)
    appuser = AppUser.objects.get(pk=appuser_id)
    current_user = request.user
    # Check if ownership already exists
    ownership = Ownership.objects.filter(appuser=appuser, account=account).first()
    if ownership is None:
        ownership = Ownership.objects.create(appuser=appuser, account=account, is_owner=False)
        ownership.save()
        activity = Activity.objects.create(appuser=appuser, account=account, previous_value=False, current_value=True, time=datetime.datetime.now(), action='Share with ' + appuser.user.username)
    return redirect('account_edit', account_id=account_id)

def undo(request, activity_id):
    activity = Activity.objects.get(pk=activity_id)
    if activity.action == 'Create':
        # Find account
        account = activity.account
        # Delete both activity and account
        activity.delete()
        account.delete()
        # Redirect
        return redirect('wallet_edit')
    elif activity.action == 'Update':
        # Find account
        account = activity.account
        # Restore previous values
        previous_value = activity.previous_value
        values = previous_value.split(';')
        account.web_address = values[0]
        account.login = values[1]
        account.password = values[2]
        account.description = values[3] 
        # Save account
        account.save()
        # Delete activity
        activity.delete()
        # Redirect
        return redirect('wallet_edit')
    elif activity.action == 'Delete':
        # Find account
        account = activity.account
        # Make account visible
        account.deleted = False
        # Save account
        account.save()
        # Delete activity
        activity.delete()
        return redirect('wallet_edit')
    elif activity.action.startswith('Share'):
        # Find account
        account = activity.account
        # Find specified appuser
        username_string = activity.action.split(' ', 2)
        user_shared_with = User.objects.get(username=username_string[2])
        appuser_shared_with = AppUser.objects.get(user=user_shared_with)
        # Find and delete ownership
        ownership = Ownership.objects.get(appuser=appuser_shared_with, account=account)
        ownership.delete()
        # Delete activity
        activity.delete()
        return redirect('wallet_edit')
    else: 
        return redirect('wallet_edit')