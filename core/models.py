from django.db import models
from django.contrib.auth.models import AbstractUser
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from datetime import timedelta
import random

class CustomUser(AbstractUser):
    GENDER_CHOICES = [
        ('N', 'None'),
        ('M', 'Male'),
        ('F', 'Female'),
    ]
    MARITAL_STATUS_CHOICES = [
        ('S', 'Single'),
        ('M', 'Married'),
        ('D', 'Divorced'),
        ('W', 'Widowed'),
    ]
    USER_ROLE_CHOICES = [
        ('N', 'None'),
        ('T', 'Teacher'),
        ('S', 'Student'),
        ('A', 'Administrator'),
    ]

    first_name = models.CharField(max_length=50,)
    last_name = models.CharField(max_length=50,)
    username = models.CharField(unique=True, max_length=50)
    email = models.EmailField(unique=True)
    age = models.PositiveIntegerField(default=0)
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES, default='S')  # Example default
    marital_status = models.CharField(max_length=1, choices=MARITAL_STATUS_CHOICES, default='N')  # Example default
    user_role = models.CharField(max_length=10, choices=USER_ROLE_CHOICES, default='N')
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)
    
    USERNAME_FIELD = "username"    
    
    def set_password(self, raw_password):
        return super().set_password(raw_password)

    def check_password(self, raw_password):
        return super().check_password(raw_password)
    
    @property
    def get_full_name(self):
        return f"{self.first_name.title()} {self.last_name.title()}"
    
class OneTimePassword(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    is_used = models.BooleanField(default=False) 

    def is_expired(self):
        # OTP is valid for 1 day
        if timezone.now() > self.created_at + timedelta(days=1):
            self.otp = None
            self.save(update_fields=['otp'])
            return True
        return False

    def regenerate_otp(self):
        # Generate a new OTP if the current one is expired
        if not self.is_used and self.is_expired():
            self.otp = ''.join(random.choices('0123456789', k=6))
            self.created_at = timezone.now()
            self.save(update_fields=['otp', 'created_at'])

    def __str__(self):
        return f"OTP for {self.user.username}"
          
class SchoolClass(models.Model):
    name = models.CharField(max_length=50)
    def __str__(self):
        return self.name    
    
class Subject(models.Model):
    school_class = models.ForeignKey(SchoolClass, on_delete=models.CASCADE)
    name = models.CharField(max_length=50)

    def __str__(self):
        return self.name

class Assignment(models.Model):
    subject = models.ForeignKey(Subject, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    description = models.TextField()
    due_date = models.DateField()

    def __str__(self):
        return self.subject.name

class Examination(models.Model):
    subject = models.ForeignKey(Subject, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    exam_date = models.DateField()
    pass_mark = models.FloatField()

    def __str__(self) -> str:
        return self.subject

class Question(models.Model):
    name = models.CharField(max_length=1000)
    assignment = models.ForeignKey(Assignment, on_delete=models.CASCADE, null=True, blank=True)
    examination = models.ForeignKey(Examination, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return self.name

class Answer(models.Model):       
    name = models.CharField(max_length=255)
    is_correct = models.BooleanField(default=False)
    question = models.ForeignKey(Question, on_delete=models.CASCADE)

    def __str__(self):
        return self.name

class Results(models.Model):     
    examination =  models.ForeignKey(Examination, on_delete=models.CASCADE, null=True, blank=True)
    assignment = models.ForeignKey(Assignment, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self) -> str:
        return self.examination
    
    def __str__(self) -> str:
        return self.assignment