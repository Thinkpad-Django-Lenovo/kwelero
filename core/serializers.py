from rest_framework import serializers
from core import models
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import send_normal_email

#Serializer classes listed below
    
class CustomeUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.CustomUser
        fields = [
            'pk',
            'first_name',
            'last_name',
            'username',
            'email',
            'age',
            'gender',
            'marital_status',
            'user_role',
        ] # Ensure to replace 'your_app' with your actual app name

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.CustomUser
        fields = ('first_name', 'last_name', 'username', 'email', 'age', 'gender', 'marital_status', 'user_role')

    def validate_email(self, value):
        if models.CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already in use")
        return value
    
    def create(self, validated_data):
        default_password = "user_password" 
        user_data = {
            'username': validated_data['username'],
            'email': validated_data['email'],
            'user_role': validated_data['user_role'],
            'first_name': validated_data['first_name'],
            'last_name': validated_data['last_name'],
            'age': validated_data['age'],
            'marital_status': validated_data['marital_status'],
        }
        if validated_data['user_role'] == "A":
            return models.CustomUser.objects.create_superuser(password=default_password, **user_data)
        else:
            user = models.CustomUser.objects.create_user(**user_data)
            user.set_password(default_password)
            user.save()
            return user

class LoginSerializer(serializers.Serializer):  # Using Serializer instead of ModelSerializer
    username = serializers.CharField(max_length=155)
    password = serializers.CharField(max_length=68, write_only=True)

    class Meta:
        fields = ['username', 'password']

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')
        request = self.context.get('request')
        user = authenticate(request, username=username, password=password)        
        if not user:
            raise AuthenticationFailed("Invalid credentials, try again")
        if user.user_role in ['A', 'T'] and not user.is_email_verified:
            raise AuthenticationFailed('You need to verify you email to get access')
        return {
            'user': user,
        }
    
    def tokens(self, user):
        refresh = RefreshToken.for_user(user)
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "user": user.username,
            'user_role': user.user_role
        }
    
class PasswordResetRequestSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=255, required=True)

    class Meta:
        fields = ['username']
   
class SetNewPasswordSerializer(serializers.Serializer):
    old_password=serializers.CharField(max_length=100, min_length=6, write_only=True)
    password=serializers.CharField(max_length=100, min_length=6, write_only=True)
    confirm_password=serializers.CharField(max_length=100, min_length=6, write_only=True)
    uidb64=serializers.CharField(min_length=1, write_only=True)
    token=serializers.CharField(min_length=3, write_only=True)

    class Meta:
        fields = ['old_password','password', 'confirm_password', 'uidb64', 'token']

    def validate(self, attrs):
        try:
            token=attrs.get('token')
            uidb64=attrs.get('uidb64')
            old_password = attrs.get('old_password')
            password=attrs.get('password')
            confirm_password=attrs.get('confirm_password')

            user_id=force_str(urlsafe_base64_decode(uidb64))
            user= models.CustomUser.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed("reset link is invalid or has expired", 401)
            if password != confirm_password:
                raise AuthenticationFailed("passwords do not match")
            if user.check_password(old_password):
                user.set_password(password)
                user.save()
            else:
                raise AuthenticationFailed('The old password does not match with the stored password')    
            return user
        except Exception as e:
            return AuthenticationFailed("link is invalid or has expired")

class ChangeDefaultPasswordSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=155, required=True)
    password=serializers.CharField(max_length=100, min_length=6, write_only=True)
    confirm_password=serializers.CharField(max_length=100, min_length=6, write_only=True)

    class Meta:
        fields = ['username', 'password', 'confirm_password']
            
class SubjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Subject
        fields = ('school_class','name')

class SchoolClassSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.SchoolClass
        fields = ['pk','name']            

class AssignmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Assignment
        fields = ('subject', 'title', 'description', 'due_date')  
        
class  ExaminationSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Examination
        fields = ('subject', 'title', 'exam_date', 'pass_mark')

class QuestionSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Question
        fields = ('name', 'assignment', 'examination')

class AnswerSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Answer
        fields = ('name', 'is_correct', 'question')

class ResultsSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Results
        fields = ('examination', 'assignment')       

