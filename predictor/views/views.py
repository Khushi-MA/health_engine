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
    


import google.generativeai as genai

# configure Gemini once
genai.configure(api_key="AIzaSyANgsIFgSreJAOvVhCxGkBvpORU3sFq-4s")  # Replace with your API key
model = genai.GenerativeModel('gemini-1.5-flash')

@login_required
def diet_plan(request):
    if request.method == 'POST':
        dietary_restrictions = request.POST['dietary_restrictions']
        preferred_cuisine = request.POST['preferred_cuisine']
        meal_frequency = request.POST['meal_frequency']
        allergies = request.POST['allergies']
        health_goals = request.POST['health_goals']
        other_info = request.POST['other_info']

        prompt = f"""Based on the following dietary preferences and restrictions, provide a personalized diet plan:

Dietary Restrictions: {dietary_restrictions}
Preferred Cuisine: {preferred_cuisine}
Meal Frequency: {meal_frequency}
Allergies: {allergies}
Health Goals: {health_goals}
Other Information: {other_info}
"""

        try:
            response = model.generate_content(prompt)
            diet_plan = response.text

            # Save to DB (if a model for dietary preferences exists)
            # Example:
            # DietSubmission.objects.create(
            #     user=request.user,
            #     dietary_restrictions=dietary_restrictions,
            #     preferred_cuisine=preferred_cuisine,
            #     meal_frequency=meal_frequency,
            #     allergies=allergies,
            #     health_goals=health_goals,
            #     other_info=other_info,
            #     diet_plan=diet_plan
            # )

            return render(request, 'dashboardfiles/diet_plan.html', {
                'diet_plan': diet_plan,
                'success': True
            })

        except Exception as e:
            return render(request, 'dashboardfiles/diet_plan.html', {
                'error': f"Failed to generate diet plan: {e}"
            })

    return render(request, 'dashboardfiles/diet_plan.html')