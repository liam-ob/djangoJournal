# Generated by Django 4.0.3 on 2022-03-04 04:52

import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('entries', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='entry',
            name='date_created',
            field=models.DateTimeField(default=datetime.datetime(2022, 3, 4, 4, 52, 42, 45027, tzinfo=utc)),
        ),
    ]
