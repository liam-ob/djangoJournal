from django.db import models
from django.utils import timezone

# Create your models here.
class Login(models.Model):
    last_user = models.CharField(max_length=200)
    def __str__(self):
        return self.last_user


class Entry(models.Model):
    title = models.CharField(max_length=200)
    content = models.TextField()
    date_created = models.DateTimeField(default=timezone.now())

    def __str__(self):
        return self.title

    class Meta():
        verbose_name_plural = "Entries"
