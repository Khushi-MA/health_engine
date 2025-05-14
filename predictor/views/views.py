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


@login_required
def dashboard(request):
    # Simplified - notifications come from context processor
    return render(request, 'dashboardfiles/dashboard.html')




@login_required
def dashboard_track_medication(request):
    user = request.user
    medications = Medication.objects.filter(user=user).prefetch_related(
        'times', 
        Prefetch('logs', queryset=MedicationLog.objects.order_by('date', 'time_to_take'))
    )

    # Auto-update missed logs
    now = timezone.localtime()  # Timezone-aware current time
    for log in MedicationLog.objects.filter(status='pending'):
        log_datetime = timezone.make_aware(datetime.combine(log.date, log.time_to_take), timezone.get_current_timezone())
        if now > log_datetime + timedelta(hours=2):
            log.status = 'missed'
            log.save()
    
    # Check for medications due now and send email reminders
    today = now.date()
    for log in MedicationLog.objects.filter(
        medication__user=user,
        status='pending',
        date=today,
        reminder_sent=False  # Only send if not already sent
    ).select_related('medication'):
        log_time = timezone.make_aware(datetime.combine(log.date, log.time_to_take), timezone.get_current_timezone())
        
        # If medication is due within the last 2 hours or next hour
        time_diff = (now - log_time).total_seconds() / 3600  # Convert to hours
        
        if -1 <= time_diff <= 2:  # From 1 hour before to 2 hours after
            # Send email reminder
            if send_medication_reminder(
                user,
                log.medication.name,
                log.time_to_take.strftime('%I:%M %p')
            ):
                # Mark as sent to avoid duplicate emails
                log.reminder_sent = True
                log.save()

    # Pass medications and their times to the template
    return render(request, 'dashboardfiles/track_medication.html', {'medications': medications})


@login_required
def add_medication(request):
    if request.method == 'POST':
        name = request.POST['name']
        times_per_day = int(request.POST['times_per_day'])  # Number of times per day
        start_date = request.POST['start_date']
        end_date = request.POST['end_date']
        times = request.POST.getlist('times')  # List of user-input times

        if len(times) != times_per_day:
            messages.error(request, f"Please provide exactly {times_per_day} times.")
            return redirect('dashboard_track_medication')

        medication = Medication.objects.create(
            user=request.user,
            name=name,
            times_per_day=times_per_day,
            start_date=start_date,
            end_date=end_date
        )

        # Save user-input times and create logs
        for t in times:
            MedicationTime.objects.create(medication=medication, time=t)

            # Create logs for each day in the range
            current_date = datetime.strptime(start_date, "%Y-%m-%d").date()
            end = datetime.strptime(end_date, "%Y-%m-%d").date()
            while current_date <= end:
                MedicationLog.objects.create(
                    medication=medication,
                    date=current_date,
                    time_to_take=t,
                    status='pending'
                )
                current_date += timedelta(days=1)

        return redirect('dashboard_track_medication')
    return redirect('dashboard_track_medication')


@login_required
def mark_dose(request, log_id, status):
    try:
        log = MedicationLog.objects.get(id=log_id, medication__user=request.user)
        if log.status == 'pending':
            log.status = status
            log.save()
    except MedicationLog.DoesNotExist:
        pass
    return redirect('dashboard_track_medication')


@login_required
def googleapi(request):
    # Simplified - notifications come from context processor
    return render(request, 'googleapi.html')

from django.core.mail import send_mail
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

def send_medication_reminder(user, medication_name, time_str):
    """
    Send medication reminder email to a user
    
    Args:
        user: User object with an email attribute
        medication_name: Name of the medication
        time_str: Formatted time string
    
    Returns:
        Boolean indicating success or failure
    """
    if not user.email:
        logger.warning(f"Cannot send reminder to user {user.username}: No email address")
        return False
    
    subject = "Medication Reminder"
    message = f"⚠️ It's time to take {medication_name}! (Due at {time_str})"
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [user.email]
    
    try:
        send_mail(
            subject,
            message, 
            from_email,
            recipient_list,
            fail_silently=False,
        )
        logger.info(f"Sent medication reminder to {user.email} for {medication_name}")
        return True
    except Exception as e:
        logger.error(f"Failed to send medication reminder: {str(e)}")
        return False