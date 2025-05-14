from django.utils import timezone
from datetime import datetime, timedelta
from .models import MedicationLog

def medication_notifications(request):
    """Context processor that adds medication notifications to all template contexts."""
    
    # Only process for authenticated users
    if not request.user.is_authenticated:
        return {'notifications': []}
    
    user = request.user
    now = timezone.localtime()  # Current time (timezone-aware)
    upcoming_notifications = []

    # Check for medications that are due now (or within the past 2 hours)
    for log in MedicationLog.objects.filter(
        medication__user=user, 
        status='pending', 
        date=now.date()
    ).select_related('medication').order_by('time_to_take'):
        log_time = timezone.make_aware(datetime.combine(log.date, log.time_to_take), timezone.get_current_timezone())
        
        # If the medication is due within the last 2 hours or the next hour
        time_diff = (now - log_time).total_seconds() / 3600  # Convert to hours
        
        if -1 <= time_diff <= 2:  # From 1 hour before to 2 hours after
            if time_diff < 0:
                # Upcoming in the next hour
                upcoming_notifications.append(f"You need to take {log.medication.name} soon at {log.time_to_take.strftime('%I:%M %p')}")
            else:
                # Currently due or overdue within last 2 hours
                upcoming_notifications.append(f"⚠️ It's time to take {log.medication.name}! (Due at {log.time_to_take.strftime('%I:%M %p')})")
    
    return {'notifications': upcoming_notifications}
