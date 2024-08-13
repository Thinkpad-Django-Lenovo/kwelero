from rest_framework import status, viewsets
from rest_framework.response import Response
from rest_framework.decorators import action
from django.shortcuts import get_object_or_404
from core import serializers, models
from rest_framework.generics import GenericAPIView
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.core.mail import EmailMessage, get_connection, send_mail
from django.conf import settings
from .utils import send_generated_otp_to_email
from django.template.loader import render_to_string

#Class based views

class Registration(viewsets.ViewSet):
    serializer_class = serializers.RegisterSerializer
    permission_classes = [AllowAny]

    def create(self, request):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        serializer.save()
        user_data = serializer.data
        user_role = user_data.get('user_role')
        recipient_email = user_data.get('email')
        
        if user_role in ['A', 'T']:
            send_generated_otp_to_email(email=recipient_email, request=request)
            return Response({'message': 'Email has been sent successfully'})
        
        self._send_welcome_email(request, user_data, recipient_email)        
        return Response({
            'data': user_data,
            'message': 'User created successfully'
        }, status=status.HTTP_201_CREATED)

    def _send_welcome_email(self, request, user_data, recipient_email):
        try:
            subject = 'Welcoming Message'
            current_site = get_current_site(request)
            message = render_to_string('messages/account_creation.html', {
                'first_name': user_data['first_name'],
                'last_name': user_data['last_name'],
                'default_password': user_data.get('default_password'),
                'domain': current_site.domain,
            })            
            with get_connection(
                host=settings.EMAIL_HOST,
                port=settings.EMAIL_PORT,
                username=settings.EMAIL_HOST_USER,
                password=settings.EMAIL_HOST_PASSWORD,
                use_tls=settings.EMAIL_USE_TLS
            ) as connection:
                email = EmailMessage(
                    subject=subject,
                    body=message,
                    from_email=settings.EMAIL_HOST_USER,
                    to=[recipient_email],
                    connection=connection
                )
                email.content_subtype = 'html'
                email.send()
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class ChangeDefaultPasswordView(APIView):
    serializer_class=serializers.ChangeDefaultPasswordSerializer
    permission_classes = [IsAuthenticated]
    def patch(self, request):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = models.CustomUser.objects.get(pk=request.user.id)
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        confirm_password = serializer.validated_data['confirm_password']

        if user.username != username:
            return Response({
                'error': 'Username does not match the authenticated user'
            }, status=status.HTTP_401_UNAUTHORIZED)
        if password != confirm_password:
            return Response({
                'error': 'Passwords do not match'
            }, status=status.HTTP_400_BAD_REQUEST)
        else:
            user.set_password(password)
            user.save()
            try:
                recipient_email = user.email
                subject = 'Default Password Change'
                current_site = get_current_site(request)
                message = render_to_string('messages/password_change.html', {
                    'username': user.username.capitalize(),
                    'new_password': password,
                    'domain': current_site.domain,
                })            
                with get_connection(
                    host=settings.EMAIL_HOST,
                    port=settings.EMAIL_PORT,
                    username=settings.EMAIL_HOST_USER,
                    password=settings.EMAIL_HOST_PASSWORD,
                    use_tls=settings.EMAIL_USE_TLS
                ) as connection:
                    email = EmailMessage(
                        subject=subject,
                        body=message,
                        from_email=settings.EMAIL_HOST_USER,
                        to=[recipient_email],
                        connection=connection
                    )
                    email.content_subtype = 'html'
                    email.send()
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response({'success':True, 'message':"password change was a succesful"}, status=status.HTTP_200_OK)
      
class VerifyUserEmail(GenericAPIView):
    def post(self, request):
        try:
            passcode = request.data.get('otp')
            user_pass_obj=models.OneTimePassword.objects.get(otp=passcode)
            user=user_pass_obj.user
            if not user.is_email_verified:
                user.is_email_verified=True
                user.save()
                return Response({
                    'message':'account email verified successfully'
                }, status=status.HTTP_200_OK)
            return Response({'message':'passcode is invalid user is already verified'}, status=status.HTTP_204_NO_CONTENT)
        except models.OneTimePassword.DoesNotExist as identifier:
            return Response({'message':'passcode not provided'}, status=status.HTTP_400_BAD_REQUEST)
      
class Login(viewsets.ViewSet):
    permission_classes = [AllowAny]

    def create(self, request):
        serializer = serializers.LoginSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        tokens = serializer.tokens(user)
        return Response(tokens, status=status.HTTP_200_OK)

class PasswordResetRequestView(GenericAPIView):
    serializer_class = serializers.PasswordResetRequestSerializer
    queryset = models.CustomUser.objects.all()
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        username = serializer.data.get('username')
        user = request.user        
        username_model = user.username
        email_model = user.email        
        if username != username_model:
            return Response({
                'Error': 'Usernames do not match, please authenticate first'
            }, status=status.HTTP_401_UNAUTHORIZED)        
        if username_model == username:
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request).domain
            relative_link = reverse('reset-password-confirm', kwargs={'uidb64': uidb64, 'token': token})
            abslink = f"http://{current_site}{relative_link}"
            email_body = f"Hi {user.first_name}, use the link below to reset your password: {abslink}"
            subject = "Reset your Password"
            recipient_email = email_model            
            try:
                email = EmailMessage(subject=subject, body=email_body, from_email=None, to=[recipient_email])
                email.content_subtype = 'html'
                email.send(fail_silently=False)                
                return Response({'message': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({'error': str(e), 'user': user.username, 'email': recipient_email}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)        
        return Response({'message': 'User with that username does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
class PasswordResetConfirm(GenericAPIView):

    def get(self, request, uidb64, token):
        try:
            user_id=smart_str(urlsafe_base64_decode(uidb64))
            user=models.CustomUser.objects.get(id=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'message':'token is invalid or has expired'}, status=status.HTTP_401_UNAUTHORIZED)
            return Response({'success':True, 'message':'credentials is valid', 'uidb64':uidb64, 'token':token}, status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            return Response({'message':'token is invalid or has expired'}, status=status.HTTP_401_UNAUTHORIZED)

class SetNewPasswordView(GenericAPIView):
    serializer_class=serializers.SetNewPasswordSerializer
    permission_classes = [IsAuthenticated]
    def patch(self, request):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success':True, 'message':"password reset is succesful"}, status=status.HTTP_200_OK)
    
class Users(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = models.CustomUser.objects.all()

    def list(self, request):
        serializer = serializers.CustomeUserSerializer(self.queryset, many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        user = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.CustomeUserSerializer(user)
        return Response(serializer.data)

    def update(self, request, pk=None):
        user = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.CustomeUserSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        user = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.CustomeUserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(methods=['GET'], detail=True)
    def get_single_user(self, request, pk=None):
        user= get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.CustomeUserSerializer(user)
        return Response({
            'user': serializer.data, 
        },status=status.HTTP_200_OK)
    
    def destroy(self, request, pk=None):
        user = get_object_or_404(self.queryset, pk=pk)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
class GetAuthenticatedUser(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user.id
        user_role = models.CustomUser.objects.get(id=user)
        return Response({
            'Success_Message': f'User Found Successfully with a user role of {user_role.user_role}'
        },status= status.HTTP_200_OK)
    
class SchoolClass(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = models.SchoolClass.objects.all()

    def list(self, request):
        serializer = serializers.SchoolClassSerializer(self.queryset, many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        school_class = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.SchoolClassSerializer(school_class)
        return Response(serializer.data)

    def update(self, request, pk=None):
        school_class = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.SchoolClassSerializer(school_class, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        school_class = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.SchoolClassSerializer(school_class, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(methods=['GET'], detail=True)
    def get_single_school_class(self, request, pk=None):
        school_class= get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.SchoolClassSerializer(school_class)
        return Response({
            'school_class': serializer.data, 
        },status=status.HTTP_200_OK)
    
    def destroy(self, request, pk=None):
        school_class = get_object_or_404(self.queryset, pk=pk)
        school_class.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)    
    
class Subject(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = models.Subject.objects.all()

    def list(self, request):
        serializer = serializers.SubjectSerializer(self.queryset, many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        subject = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.SubjectSerializer(subject)
        return Response(serializer.data)

    def update(self, request, pk=None):
        subject = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.SubjectSerializer(subject, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        subject = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.SubjectSerializer(subject, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(methods=['GET'], detail=True)
    def get_single_subject(self, request, pk=None):
        subject= get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.SubjectSerializer(subject)
        return Response({
            'user': serializer.data, 
        },status=status.HTTP_200_OK)
    
    def destroy(self, request, pk=None):
        subject = get_object_or_404(self.queryset, pk=pk)
        subject.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)        
    
class Assignments(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = models.Assignment.objects.all()

    def list(self, request):
        serializer = serializers.AssignmentSerializer(self.queryset, many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        assignment = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.AssignmentSerializer(assignment)
        return Response(serializer.data)

    def update(self, request, pk=None):
        assignment = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.AssignmentSerializer(assignment, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        assignment = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.AssignmentSerializer(assignment, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(methods=['GET'], detail=True)
    def get_single_assignment(self, request, pk=None):
        assignment= get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.AssignmentSerializer(assignment)
        return Response({
            'assignment': serializer.data, 
        },status=status.HTTP_200_OK)
    
    def destroy(self, request, pk=None):
        assignment = get_object_or_404(self.queryset, pk=pk)
        assignment.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)         

class Examinations(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = models.Examination.objects.all()

    def list(self, request):
        serializer = serializers.ExaminationSerializer(self.queryset, many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        examination = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.ExaminationSerializer(examination)
        return Response(serializer.data)

    def update(self, request, pk=None):
        examination = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.ExaminationSerializer(examination, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        examination = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.ExaminationSerializer(examination, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(methods=['GET'], detail=True)
    def get_single_examination(self, request, pk=None):
        examination= get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.ExaminationSerializer(examination)
        return Response({
            'examination': serializer.data, 
        },status=status.HTTP_200_OK)
    
    def destroy(self, request, pk=None):
        examination = get_object_or_404(self.queryset, pk=pk)
        examination.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)                   
    
class Questions(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = models.Question.objects.all()

    def list(self, request):
        serializer = serializers.QuestionSerializer(self.queryset, many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        question = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.QuestionSerializer(question)
        return Response(serializer.data)

    def update(self, request, pk=None):
        question = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.QuestionSerializer(question, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        question = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.QuestionSerializer(question, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(methods=['GET'], detail=True)
    def get_single_question(self, request, pk=None):
        question= get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.QuestionSerializer(question)
        return Response({
            'question': serializer.data, 
        },status=status.HTTP_200_OK)
    
    def destroy(self, request, pk=None):
        question = get_object_or_404(self.queryset, pk=pk)
        question.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)                       
    
class Answers(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = models.Answer.objects.all()

    def list(self, request):
        serializer = serializers.AnswerSerializer(self.queryset, many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        answer = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.AnswerSerializer(answer)
        return Response(serializer.data)

    def update(self, request, pk=None):
        answer = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.AnswerSerializer(answer, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        answer = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.AnswerSerializer(answer, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(methods=['GET'], detail=True)
    def get_single_answer(self, request, pk=None):
        answer= get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.AnswerSerializer(answer)
        return Response({
            'answer': serializer.data, 
        },status=status.HTTP_200_OK)
    
    def destroy(self, request, pk=None):
        answer = get_object_or_404(self.queryset, pk=pk)
        answer.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)                           
    
class Resultss(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = models.Results.objects.all()

    def list(self, request):
        serializer = serializers.ResultsSerializer(self.queryset, many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        result = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.ResultsSerializer(result)
        return Response(serializer.data)

    def update(self, request, pk=None):
        result = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.ResultsSerializer(result, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        result = get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.ResultsSerializer(result, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(methods=['GET'], detail=True)
    def get_single_result(self, request, pk=None):
        result= get_object_or_404(self.queryset, pk=pk)
        serializer = serializers.ResultsSerializer(result)
        return Response({
            'result': serializer.data, 
        },status=status.HTTP_200_OK)
    
    def destroy(self, request, pk=None):
        result = get_object_or_404(self.queryset, pk=pk)
        result.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)                               