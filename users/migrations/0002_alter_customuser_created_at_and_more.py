# Generated by Django 5.2 on 2025-04-14 12:50

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='created_at',
            field=models.DateField(verbose_name=datetime.datetime(2025, 4, 14, 12, 50, 42, 525765)),
        ),
        migrations.AlterField(
            model_name='customuser',
            name='updated_at',
            field=models.DateTimeField(verbose_name=datetime.datetime(2025, 4, 14, 12, 50, 42, 525786)),
        ),
    ]
