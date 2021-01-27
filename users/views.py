from django.shortcuts import render, redirect
from django.contrib import auth
from django.contrib.auth.models import User

from .models import AppUser
from accounts.models import Account, Ownership
from logs.models import Log
from security.aescipher import AESCipher
from activities.models import Activity

import hashlib, secrets, hmac
import datetime, time

def register(request):
    if request.method == 'POST':
        # Get form values
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        username = request.POST['username']
        password = request.POST['password']
        password2 = request.POST['password2']
        method = request.POST['method']
        # Validation
        # Password match
        if password == password2:
            # Username
            if User.objects.filter(username=username).exists():
                return redirect('register')
            else:
                # Encrypt password
                if method is None:
                    method = 'hash'
                if method == 'hash':
                    # Generate salt
                    salt = secrets.token_hex(8)
                    # Generate hash
                    password_hash = hashlib.sha512((salt+password).encode('ascii')).hexdigest()
                    # Create and save user
                    user = User.objects.create_user(username=username, first_name=first_name, last_name=last_name, password=password_hash)
                    user.save()
                    appuser = AppUser.objects.create(user=user, salt=salt, kept_in_hash=True)
                    appuser.save()
                elif method == 'hmac':
                    # Generate salt
                    salt = secrets.token_hex(8)
                    # Generate HMAC
                    password_hash = hmac.new(salt.encode('ascii'), password.encode('ascii'), hashlib.sha512).hexdigest()
                    # Create and save user
                    user = User.objects.create_user(username=username, first_name=first_name, last_name=last_name, password=password_hash)
                    user.save()
                    appuser = AppUser.objects.create(user=user, salt=salt, kept_in_hash=False)
                    appuser.save()
                # Redirect to login
                return redirect('login')
    else:
        return render(request, 'users/register.html')

def login(request):
    if request.method == 'POST':
        # Get form values
        username = request.POST['username']
        password = request.POST['password']
        # mode = request.POST.get('mode', False)
        # print(mode)
        # Get user ip
        ip_address = get_ip_address(request=request)
        # Find user
        user_search = User.objects.get(username=username)
        salt = user_search.appuser.salt
        kept_in_hash = user_search.appuser.kept_in_hash
        # Get fail count
        last_login_attempt = Log.objects.filter(ip_address=ip_address).last()
        if last_login_attempt is not None:
            fail_count = last_login_attempt.fail_count
        else:
            fail_count = 0
        # Prepare password
        if kept_in_hash is True:
            password_hash = hashlib.sha512((salt+password).encode('ascii')).hexdigest()
        else:
            password_hash = hmac.new(salt.encode('ascii'), password.encode('ascii'), hashlib.sha512).hexdigest()
        # Authenticate user
        user = auth.authenticate(username=username, password=password_hash)
        # Set pause
        if fail_count >= 4:
            return render(request, 'users/login.html')
        elif fail_count == 3:
            time.sleep(10.0)
        elif fail_count == 2:
            time.sleep(5.0)
        else:
            pass
        if user is not None:
            # Successful login
            # Create log
            log = Log.objects.create(user=user_search, ip_address=ip_address, login_time=datetime.datetime.now(), login_result=True, fail_count=0)
            log.save()
            # Log user in
            auth.login(request, user)
            # Redirect to wallet
            return redirect('wallet_read')
        else:
            # Failed login
            fail_count = fail_count + 1
            # Create log
            log = Log.objects.create(user=user, ip_address=ip_address, login_time=datetime.datetime.now(), login_result=True, fail_count=fail_count)
            log.save()
            # Redirect back to login
            return render(request, 'users/login.html')
    else:
        return render(request, 'users/login.html')

def logout(request):
    auth.logout(request)
    return redirect('login')

def changepassword(request):
    if request.method == 'POST':
        # Get form values
        new_password = request.POST['new_password']
        conf_password = request.POST['conf_password']
        # Find user
        user = User.objects.filter(pk=request.user.id).first()
        user_password = request.user.password
        salt = user.appuser.salt
        kept_in_hash = user.appuser.kept_in_hash
        # Validation
        # New passwords match 
        if new_password == conf_password:
            # Initialise cipher object for decryption
            cipher_decrypt = AESCipher(user_password)
            # Get and decrypt all passwords for user 
            accounts = Account.objects.filter(appuser=user.appuser)
            account_passwords = list()
            for account in accounts:
                account_password = cipher_decrypt.decrypt(account.password)
                account_passwords.append(account_password)
            # Generate new salt
            new_salt = secrets.token_hex(8)
            # Encrypt new password
            if kept_in_hash:
                # Generate hash
                password_hash = hashlib.sha512((new_salt+new_password).encode('ascii')).hexdigest()
            else:
                # Generate HMAC
                password_hash = hmac.new(new_salt.encode('ascii'), new_password.encode('ascii'), hashlib.sha512).hexdigest()
            # Change password for user
            user.appuser.salt = new_salt
            user.appuser.save()
            user.set_password(password_hash)
            user.save()
            # Redo encryption for account passwords related to user
            cipher_encrypt = AESCipher(user.password)
            for account in accounts:
                encrypted_password = cipher_encrypt.encrypt(account_passwords[0])
                del account_passwords[0]
                account.password = encrypted_password
                account.save()
            # Log user out
            auth.logout(request)
            return render(request, 'users/login.html')
        else:
            return render(request, 'users/changepassword.html')
    else:
        return render(request, 'users/changepassword.html')

def wallet_read(request):
    # Find user
    user = User.objects.get(username=request.user.username)  
    appuser = AppUser.objects.get(user=user)
    available_users = AppUser.objects.all().exclude(user=user)
    # Gey users ip address
    ip_address = get_ip_address(request=request)
    # Get all account for user
    user_accounts = list()
    shared_accounts = list()
    for account in appuser.account_set.all():
        ownership = Ownership.objects.get(appuser=appuser, account=account)
        if ownership.is_owner:
            user_accounts.append(account)
        else:
            shared_accounts.append(account)
    # Get activities
    activities = Activity.objects.filter(appuser=appuser).order_by('-time')
    last_activity = activities.first()
    context = {
        'user_accounts': user_accounts,
        'shared_accounts': shared_accounts,
        'user': user,
        'appuser': appuser,
        'ip_address': ip_address,
        'last_activity': last_activity,
        'activities': activities
    }
    return render(request, 'accounts/wallet_read.html', context)

def wallet_edit(request):
    # Find user
    user = User.objects.get(username=request.user.username)  
    appuser = AppUser.objects.get(user=user)
    available_users = AppUser.objects.all().exclude(user=user)
    # Gey users ip address
    ip_address = get_ip_address(request=request)
    # Get all account for user
    user_accounts = list()
    shared_accounts = list()
    for account in appuser.account_set.all():
        ownership = Ownership.objects.get(appuser=appuser, account=account)
        if ownership.is_owner:
            user_accounts.append(account)
        else:
            shared_accounts.append(account)
    # Get activities
    activities = Activity.objects.filter(appuser=appuser).order_by('-time')
    last_activity = activities.first()
    context = {
        'user_accounts': user_accounts,
        'shared_accounts': shared_accounts,
        'user': user,
        'appuser': appuser,
        'ip_address': ip_address,
        'last_activity': last_activity,
        'activities': activities
    }
    return render(request, 'accounts/wallet_edit.html', context)

def unlock(request):
    ip_address = get_ip_address(request=request)
    log = Log.objects.create(user=None, ip_address=ip_address, login_time=datetime.datetime.now(), login_result=True, fail_count=0)
    log.save()
    return redirect('login')

def hash_password(self, password, salt):
    return hashlib.sha512((salt+password).encode('ascii')).hexdigest()

def hmac_password(self, password, salt):
    return hmac.new(salt.encode('ascii'), password.encode('ascii'), hashlib.sha512).hexdigest()

def get_ip_address(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
