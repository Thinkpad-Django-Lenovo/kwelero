from rest_framework.routers import  DefaultRouter
from core import views

#rest api routes 

router = DefaultRouter()
router.register(r'register', views.Registration, basename='register')
router.register(r'login', views.Login, basename='login')
router.register(r'users', views.Users, basename='users')
router.register(r'class', views.SchoolClass, basename='class')
router.register(r'subject', views.Subject, basename='subject')
router.register(r'assignments', views.Assignments, basename='assignments')
router.register(r'examinations', views.Examinations, basename='examinations')
router.register(r'questions', views.Questions, basename='questions')
router.register(r'answers', views.Answers, basename='answers')
router.register(r'results', views.Resultss, basename='results')