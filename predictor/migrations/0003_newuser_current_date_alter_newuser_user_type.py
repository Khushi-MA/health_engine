# Generated by Django 5.1.3 on 2025-03-10 10:37

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('predictor', '0002_alter_newuser_groups_alter_newuser_user_permissions'),
    ]

    operations = [
        migrations.AddField(
            model_name='newuser',
            name='current_date',
            field=models.DateField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='newuser',
            name='user_type',
            field=models.CharField(choices=[('admin', 'Admin'), ('customer', 'Customer')], default='admin', max_length=300),
        ),
    ]
