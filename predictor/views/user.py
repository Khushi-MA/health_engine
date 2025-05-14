from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db.models import Q, Prefetch  # Add this import
from django.utils import timezone
from django.contrib.auth import get_user_model

from predictor.models import NewUser, Medication, MedicationLog, MedicationTime

import numpy as np
import os
import logging

from datetime import datetime, date, time, timedelta

logger = logging.getLogger(__name__)


def home(request):
    return render(request , 'index.html')
def user_login(request):  # Renamed from 'login' to 'user_login'
    try:
        if request.user.is_authenticated:
            if request.user.user_type == 'admin':
                return redirect('home')
            elif request.user.user_type == 'customer':
                return redirect('home')

        if request.method == 'POST':
            email = request.POST.get('email')
            password = request.POST.get('password')

            if email:
                email = email.strip().lower()

            # Get user by email (use get_user_model)
            try:
                user = User.objects.get(email=email)
                username = user.username  # Get the actual username
            except User.DoesNotExist:
                return render(request, 'login.html', {'error_message': 'Invalid email or password'})

            # Authenticate using the retrieved username
            user = authenticate(request, username=username, password=password)

            if user:
                login(request, user)  # Use Django's built-in login function
                return redirect('home')
            else:
                return render(request, 'login.html', {'error_message': 'Invalid email or password'})

        return render(request, 'login.html')

    except Exception as e:
        print(e)  # Debugging
        return render(request, 'login.html', {'error_message': 'An unexpected error occurred'})




def register(request):
    if request.method == 'POST':
        try:
            form_data = request.POST

            # Validate required fields
            required_fields = ['name', 'email', 'password', 'repeat_password']
            missing_fields = [field for field in required_fields if field not in form_data or not form_data[field]]
            if missing_fields:
                raise ValidationError(f"Missing fields: {', '.join(missing_fields)}")

            # Validate passwords match
            password = form_data['password']
            repeat_password = form_data['repeat_password']
            if password != repeat_password:
                raise ValidationError("Passwords do not match.")

            # Check for unique email and username
            email = form_data['email']
            username = form_data['email']  # Using email as username
            if NewUser.objects.filter(Q(email=email) | Q(username=username)).exists():
                raise ValidationError("An account with this email or username already exists.")

            # Create user
            user_profile = NewUser(
                first_name=form_data['name'],
                last_name=form_data['last_name'],  # Use 'last_name' from form
                username=username,
                email=email,
                user_type='customer',  # Default to 'customer'
                password=make_password(password),  # Secure hashed password
            )
            user_profile.save()

            messages.success(request, 'Registration successful!')
            return redirect('login')

        except ValidationError as e:
            messages.error(request, str(e))
            return render(request, 'customer_register.html', {'form_data': form_data})

        except Exception as e:
            logger.error("Error in save_customer", exc_info=True)
            messages.error(request, "An unexpected error occurred. Please try again later.")
            return render(request, 'register.html', {'form_data': form_data})

    return render(request, 'register.html')


User = get_user_model()  # Get the swapped user model



def custom_logout(request):
    # Logout the user
    logout(request)

    # Redirect to the homepage or any other page after logout
    return redirect('home')  # Replace 'index' with your desired redirect URL name

