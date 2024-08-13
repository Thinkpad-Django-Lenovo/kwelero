from rest_framework import permissions

class IsAdminOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        return request.user and request.user.is_staff
    
class IsTeacherOrStudent(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            if request.user.is_authenticated:
                if request.user.user_role in ["A", "T"]:
                    return True
                elif request.user.user_role in ["S"]:
                    return False
        return request.user and request.user.is_authenticated