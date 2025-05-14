from django.db import models
from django.contrib.auth.models import AbstractUser
from datetime import time

class NewUser(AbstractUser):
    USER_TYPE_CHOICES = (
        ("admin", "Admin"),
        ("customer", "Customer"),
    )
    user_type = models.CharField(
        max_length=300, choices=USER_TYPE_CHOICES, default="admin"
    )
    current_date = models.DateField(auto_now_add=True)

    def __str__(self):
        return self.username

class Medication(models.Model):
    user = models.ForeignKey(
        NewUser, on_delete=models.CASCADE, related_name="medications"
    )
    name = models.CharField(max_length=200)
    times_per_day = models.IntegerField(default=1)
    start_date = models.DateField()
    end_date = models.DateField()

    def __str__(self):
        return f"{self.name} for {self.user.username}"

class MedicationTime(models.Model):
    medication = models.ForeignKey(
        Medication, on_delete=models.CASCADE, related_name="times"
    )
    time = models.TimeField()

    def __str__(self):
        return f"{self.time} for {self.medication.name}"

class MedicationLog(models.Model):
    STATUS_CHOICES = (
        ("taken", "Taken"),
        ("missed", "Missed"),
        ("pending", "Pending"),
    )

    medication = models.ForeignKey(
        Medication, on_delete=models.CASCADE, related_name="logs"
    )
    date = models.DateField()
    time_to_take = models.TimeField()
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="pending")
    reminder_sent = models.BooleanField(default=False)  # Add this field

    def __str__(self):
        return f"{self.medication.name} on {self.date} at {self.time_to_take}: {self.status}"
