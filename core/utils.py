from django.core.mail import EmailMessage, get_connection, BadHeaderError
import random
from django.conf import settings
from .models import CustomUser, OneTimePassword
from django.contrib.sites.shortcuts import get_current_site
from django.http import HttpResponse
from rest_framework.response import Response
from rest_framework import status

def send_generated_otp_to_email(email, request): 
    subject = "One time passcode for Email verification"
    otp=random.randint(1000, 9999) 
    current_site=get_current_site(request).domain
    user = CustomUser.objects.get(email=email)
    email_body=f"Hi {user.first_name} thanks for signing up on {current_site} please verify your email with the \n one time passcode {otp}"
    otp_obj=OneTimePassword()
    otp_obj.user = user
    otp_obj.otp = otp
    otp_obj.is_used = True
    otp_obj.save()
    recipient_email = email
    try:
        with get_connection(
            host=settings.EMAIL_HOST,
            port=settings.EMAIL_PORT,
            username=settings.EMAIL_HOST_USER,
            password=settings.EMAIL_HOST_PASSWORD,
            use_tls=settings.EMAIL_USE_TLS
        ) as connection:
            subject = subject
            email_from = settings.EMAIL_HOST_USER
            message = email_body
            email = EmailMessage(subject, message, email_from, [recipient_email,], connection=connection)
            email.content_subtype = 'html'
            email.send()                
    except Exception as e:
        return Response({'error': e}, status=status.HTTP_400_BAD_REQUEST)


def send_normal_email(data):
    email=EmailMessage(
        subject=data['email_subject'],
        body=data['email_body'],
        from_email=settings.EMAIL_HOST_USER,
        to=[data['to_email']]
    )
    email.send()