from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Scholarship, Student, Admin
from .permissions import IsAdmin, IsSuperAdmin, IsAdminOrReadOnly
from .serializers import (
    ScholarshipSerializer,
    StudentSerializer,
    AdminSerializer,
    UserSerializer,
    LoginSerializer,
)
from django.db import transaction
from datetime import datetime, timedelta


# Scholarship Views
class ScholarshipListCreateView(generics.ListCreateAPIView):
    queryset = Scholarship.objects.filter(is_active=True)
    serializer_class = ScholarshipSerializer
    permission_classes = [IsAdminOrReadOnly]


class ScholarshipDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Scholarship.objects.all()
    serializer_class = ScholarshipSerializer
    permission_classes = [IsAdminOrReadOnly]


# Authentication Views
@api_view(["POST"])
@permission_classes([AllowAny])
def student_register(request):
    serializer = StudentSerializer(data=request.data)
    if serializer.is_valid():
        student = serializer.save()
        return Response(
            {"message": "Student registered successfully", "student_id": student.id},
            status=status.HTTP_201_CREATED,
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([AllowAny])
def admin_register(request):
    serializer = AdminSerializer(data=request.data)
    if serializer.is_valid():
        admin = serializer.save()
        return Response(
            {"message": "Admin registered successfully", "admin_id": admin.id},
            status=status.HTTP_201_CREATED,
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Helper function to get tokens for user
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }


@api_view(["POST"])
@permission_classes([AllowAny])
def user_login(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        username = serializer.validated_data["username"]
        password = serializer.validated_data["password"]

        # Try to authenticate with username first, then with email
        user = authenticate(username=username, password=password)
        if not user:
            # Try to find user by email and authenticate
            try:
                user_obj = User.objects.get(email=username)
                user = authenticate(username=user_obj.username, password=password)
            except User.DoesNotExist:
                pass

        if user:
            # Generate JWT tokens
            tokens = get_tokens_for_user(user)

            # Check if user is admin or student
            user_type = "student"
            user_profile = None
            is_staff_or_admin = user.is_staff or user.is_superuser

            try:
                admin_profile = Admin.objects.get(user=user)
                user_type = "admin"
                user_profile = {
                    "id": admin_profile.id,
                    "is_super_admin": admin_profile.is_super_admin,
                }
            except Admin.DoesNotExist:
                # Check if user is Django staff/admin even without Admin profile
                if is_staff_or_admin:
                    user_type = "admin"
                    user_profile = {"id": None, "is_super_admin": user.is_superuser}
                else:
                    try:
                        student_profile = Student.objects.get(user=user)
                        user_profile = {
                            "id": student_profile.id,
                            "phone": student_profile.phone,
                            "country": student_profile.country,
                        }
                    except Student.DoesNotExist:
                        pass

            return Response(
                {
                    "message": "Login successful",
                    "tokens": tokens,
                    "user": {
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                        "first_name": user.first_name,
                        "last_name": user.last_name,
                        "user_type": user_type,
                        "profile": user_profile,
                        "is_staff": user.is_staff,
                        "is_superuser": user.is_superuser,
                    },
                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED
            )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def user_logout(request):
    try:
        refresh_token = request.data["refresh"]
        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_profile(request):
    user = request.user
    user_data = UserSerializer(user).data

    # Get user profile based on type
    try:
        admin_profile = Admin.objects.get(user=user)
        user_data["user_type"] = "admin"
        user_data["profile"] = AdminSerializer(admin_profile).data
    except Admin.DoesNotExist:
        try:
            student_profile = Student.objects.get(user=user)
            user_data["user_type"] = "student"
            user_data["profile"] = StudentSerializer(student_profile).data
        except Student.DoesNotExist:
            user_data["user_type"] = "user"
            user_data["profile"] = None

    return Response(user_data, status=status.HTTP_200_OK)


# Admin Views
@api_view(["GET", "POST"])
@permission_classes([IsAdmin])
def admin_scholarships(request):
    if request.method == "GET":
        scholarships = Scholarship.objects.all()
        serializer = ScholarshipSerializer(scholarships, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    elif request.method == "POST":
        serializer = ScholarshipSerializer(data=request.data)
        if serializer.is_valid():
            scholarship = serializer.save()
            return Response(
                ScholarshipSerializer(scholarship).data, status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET", "PUT", "DELETE"])
@permission_classes([IsAdmin])
def admin_scholarship_detail(request, pk):
    try:
        scholarship = Scholarship.objects.get(pk=pk)
    except Scholarship.DoesNotExist:
        return Response(
            {"error": "Scholarship not found"}, status=status.HTTP_404_NOT_FOUND
        )

    if request.method == "GET":
        serializer = ScholarshipSerializer(scholarship)
        return Response(serializer.data, status=status.HTTP_200_OK)

    elif request.method == "PUT":
        serializer = ScholarshipSerializer(scholarship, data=request.data)
        if serializer.is_valid():
            updated_scholarship = serializer.save()
            return Response(
                ScholarshipSerializer(updated_scholarship).data,
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == "DELETE":
        scholarship.delete()
        return Response(
            {"message": "Scholarship deleted successfully"},
            status=status.HTTP_204_NO_CONTENT,
        )


# Admin User Management Endpoints
@api_view(["GET", "POST"])
@permission_classes([IsAdmin])
def admin_users(request):
    if request.method == "GET":
        # List all admin users (custom Admin model + Django staff/superusers)
        admin_profiles = Admin.objects.select_related("user").all()
        admin_list = []
        for admin in admin_profiles:
            admin_list.append(
                {
                    "admin_id": admin.id,  # ID from Admin profile
                    "user_id": admin.user.id,  # Django auth User ID
                    "username": admin.user.username,
                    "email": admin.user.email,
                    "first_name": admin.user.first_name,
                    "last_name": admin.user.last_name,
                    "is_super_admin": admin.is_super_admin,
                    "is_staff": admin.user.is_staff,
                    "is_superuser": admin.user.is_superuser,
                }
            )
        # Add Django staff/superusers not in Admin model
        staff_users = User.objects.filter(is_staff=True)
        for user in staff_users:
            if not Admin.objects.filter(user=user).exists():
                admin_list.append(
                    {
                        "admin_id": None,
                        "user_id": user.id,
                        "username": user.username,
                        "email": user.email,
                        "first_name": user.first_name,
                        "last_name": user.last_name,
                        "is_super_admin": user.is_superuser,
                        "is_staff": user.is_staff,
                        "is_superuser": user.is_superuser,
                    }
                )
        return Response(admin_list, status=status.HTTP_200_OK)

    elif request.method == "POST":
        # Create or promote a user to admin; only super admins may create super admins
        data = request.data.copy()
        user_data = data.get("user")
        is_super_admin = data.get("is_super_admin", False)
        if not user_data:
            return Response(
                {"error": "User data required"}, status=status.HTTP_400_BAD_REQUEST
            )
        # Detect if requester is super admin
        requester_is_super_admin = request.user.is_superuser
        if not requester_is_super_admin:
            try:
                requester_admin = Admin.objects.get(user=request.user)
                requester_is_super_admin = requester_admin.is_super_admin
            except Admin.DoesNotExist:
                requester_is_super_admin = False
        # If trying to create a super admin while requester is not super admin -> forbidden
        if is_super_admin in [True, "true", "True", "1", 1]:
            if not requester_is_super_admin:
                return Response(
                    {"error": "Only super admins can create super admins"},
                    status=status.HTTP_403_FORBIDDEN,
                )
        try:
            with transaction.atomic():
                # Attempt to find existing user by username or email
                existing_user = None
                username = None
                email = None
                if isinstance(user_data, dict):
                    username = user_data.get("username")
                    email = user_data.get("email")
                # Prefer lookup by username
                if username:
                    try:
                        existing_user = User.objects.get(username=username)
                    except User.DoesNotExist:
                        existing_user = None
                # Fallback lookup by email
                if not existing_user and email:
                    try:
                        existing_user = User.objects.get(email=email)
                    except User.DoesNotExist:
                        existing_user = None

                # If user already exists, do not add; return 409 so frontend can show a nice message
                if existing_user:
                    return Response(
                        {"error": "User with this username or email already exists"},
                        status=status.HTTP_409_CONFLICT,
                    )

                # Determine super admin flag
                is_super_flag = bool(is_super_admin)
                if isinstance(is_super_admin, str):
                    is_super_flag = is_super_admin.lower() in ["true", "1", "yes"]

                # Create a brand new user
                user_serializer = UserSerializer(data=user_data)
                user_serializer.is_valid(raise_exception=True)
                user = user_serializer.save()
                user.is_staff = True
                if is_super_flag and requester_is_super_admin:
                    user.is_superuser = True
                user.save()
                admin = Admin.objects.create(
                    user=user,
                    is_super_admin=is_super_flag if requester_is_super_admin else False,
                )
                return Response(
                    {
                        "id": admin.id,
                        "username": user.username,
                        "email": user.email,
                        "first_name": user.first_name,
                        "last_name": user.last_name,
                        "is_super_admin": admin.is_super_admin,
                        "is_staff": user.is_staff,
                        "is_superuser": user.is_superuser,
                    },
                    status=status.HTTP_201_CREATED,
                )
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["PATCH", "DELETE"])
@permission_classes([IsAdmin])
def delete_admin_user(request, user_id):
    try:
        user = User.objects.get(id=user_id)

        # Only super admins can edit or delete admins
        acting_is_super_admin = request.user.is_superuser
        if not acting_is_super_admin:
            try:
                acting_admin = Admin.objects.get(user=request.user)
                acting_is_super_admin = acting_admin.is_super_admin
            except Admin.DoesNotExist:
                acting_is_super_admin = False

        if request.method == "PATCH":
            if not acting_is_super_admin:
                return Response(
                    {"error": "Only super admins can edit admins"},
                    status=status.HTTP_403_FORBIDDEN,
                )
            # Update basic user fields and super admin flag
            first_name = request.data.get("first_name")
            last_name = request.data.get("last_name")
            email = request.data.get("email")
            is_super_admin = request.data.get("is_super_admin")

            if first_name is not None:
                user.first_name = first_name
            if last_name is not None:
                user.last_name = last_name
            if email is not None:
                user.email = email

            # Ensure user remains staff
            user.is_staff = True

            # Update superuser flag if provided
            if is_super_admin is not None:
                # Coerce to boolean from potential string values
                if isinstance(is_super_admin, str):
                    is_super_admin = is_super_admin.lower() in ["true", "1", "yes"]
                user.is_superuser = bool(is_super_admin)
                # Update or create Admin profile accordingly
                admin_profile, _created = Admin.objects.get_or_create(user=user)
                admin_profile.is_super_admin = bool(is_super_admin)
                admin_profile.save()
            else:
                # Ensure Admin profile exists even if not toggling super flag
                Admin.objects.get_or_create(user=user)

            user.save()
            return Response(
                {
                    "message": "Admin user updated successfully",
                    "user_id": user.id,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "email": user.email,
                    "is_superuser": user.is_superuser,
                    "is_staff": user.is_staff,
                },
                status=status.HTTP_200_OK,
            )

        # DELETE branch
        if request.method == "DELETE" and not acting_is_super_admin:
            return Response(
                {"error": "Only super admins can delete admins"},
                status=status.HTTP_403_FORBIDDEN,
            )
        # Prevent deletion of super admin
        try:
            admin_profile = Admin.objects.get(user=user)
            if admin_profile.is_super_admin or user.is_superuser:
                return Response(
                    {"error": "Cannot delete super admin user"},
                    status=status.HTTP_403_FORBIDDEN,
                )
        except Admin.DoesNotExist:
            if user.is_superuser:
                return Response(
                    {"error": "Cannot delete super admin user"},
                    status=status.HTTP_403_FORBIDDEN,
                )

        # By default perform a hard delete, unless soft=true is explicitly provided
        soft = request.query_params.get("soft") or request.data.get("soft")
        if isinstance(soft, str):
            soft = soft.lower() in ["true", "1", "yes"]
        soft = bool(soft)

        if not soft:
            # Fully delete the user and related profiles
            Admin.objects.filter(user=user).delete()
            Student.objects.filter(user=user).delete()
            username = user.username
            email = user.email
            user.delete()
            return Response(
                {
                    "message": "Admin user hard-deleted successfully",
                    "username": username,
                    "email": email,
                },
                status=status.HTTP_200_OK,
            )
        else:
            # Demote and remove admin profile (soft delete)
            Admin.objects.filter(user=user).delete()
            user.is_staff = False
            user.is_superuser = False
            user.save()
            return Response(
                {"message": "Admin user deleted/demoted successfully"},
                status=status.HTTP_200_OK,
            )
    except User.DoesNotExist:
        return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)


@api_view(["GET"])
@permission_classes([IsAdmin])
def admin_statistics(request):
    """
    Get admin statistics including total scholarships, users, etc.
    """
    try:
        # Get total counts
        total_scholarships = Scholarship.objects.count()
        active_scholarships = Scholarship.objects.filter(is_active=True).count()
        total_users = User.objects.count()
        total_students = Student.objects.count()
        total_admins = Admin.objects.count()

        # Get recent scholarships (last 30 days)
        thirty_days_ago = datetime.now() - timedelta(days=30)
        recent_scholarships = Scholarship.objects.filter(
            created_at__gte=thirty_days_ago
        ).count()

        # Get scholarships by degree level (top 5)
        from django.db.models import Count

        scholarships_by_degree = list(
            Scholarship.objects.values("degree_level")
            .annotate(count=Count("id"))
            .order_by("-count")[:5]
        )

        statistics = {
            "total_scholarships": total_scholarships,
            "active_scholarships": active_scholarships,
            "total_users": total_users,
            "total_students": total_students,
            "total_admins": total_admins,
            "recent_scholarships": recent_scholarships,
            "scholarships_by_degree": scholarships_by_degree,
        }

        return Response(statistics, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(["GET"])
@permission_classes([IsAdmin])
def export_users_csv(request):
    """
    Export all users to CSV format
    """
    try:
        import csv
        from django.http import HttpResponse

        # Create the HttpResponse object with CSV header
        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = (
            f'attachment; filename="users_export_{datetime.now().strftime("%Y-%m-%d")}.csv"'
        )

        writer = csv.writer(response)

        # Write CSV header
        writer.writerow(
            [
                "ID",
                "Username",
                "First Name",
                "Last Name",
                "Email",
                "User Type",
                "Date Joined",
                "Last Login",
                "Is Active",
            ]
        )

        # Get all users with their related student/admin info
        users = User.objects.select_related("student", "admin").all()

        for user in users:
            # Determine user type
            user_type = "User"
            if hasattr(user, "student"):
                user_type = "Student"
            elif hasattr(user, "admin"):
                user_type = "Admin"
                if user.admin.is_super_admin:
                    user_type = "Super Admin"

            writer.writerow(
                [
                    user.id,
                    user.username,
                    user.first_name,
                    user.last_name,
                    user.email,
                    user_type,
                    user.date_joined.strftime("%Y-%m-%d %H:%M:%S")
                    if user.date_joined
                    else "",
                    user.last_login.strftime("%Y-%m-%d %H:%M:%S")
                    if user.last_login
                    else "",
                    "Yes" if user.is_active else "No",
                ]
            )

        return response

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


from django.http import HttpResponse


@api_view(["GET"])
@permission_classes([AllowAny])
def home(request):
    """
    Home route providing API information and available endpoints
    """
    # Check if request is from browser (HTML) or API client (JSON)
    accept_header = request.META.get("HTTP_ACCEPT", "")
    wants_html = (
        "text/html" in accept_header and "application/json" not in accept_header
    )

    api_info = {
        "message": "Welcome to the Scholarships Board API",
        "version": "1.0",
        "description": "A Django REST API for managing scholarships and users",
        "endpoints": {
            "authentication": {
                "login": "/api/auth/login/",
                "logout": "/api/auth/logout/",
                "register_student": "/api/auth/student/register/",
                "register_admin": "/api/auth/admin/register/",
                "profile": "/api/auth/profile/",
                "token_refresh": "/api/auth/token/refresh/",
            },
            "scholarships": {
                "list": "/api/scholarships/",
                "detail": "/api/scholarships/{id}/",
                "admin_list": "/api/admin/scholarships/",
                "admin_detail": "/api/admin/scholarships/{id}/",
                "delete": "/api/admin/scholarships/{id}/delete/",
            },
            "admin": {
                "statistics": "/api/admin/statistics/",
                "users": "/api/admins/",
                "user_detail": "/api/admins/{user_id}/",
                "export_users": "/api/admin/users/export/",
            },
        },
        "status": "operational",
        "documentation": "Contact admin for API documentation",
    }

    if wants_html:
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Scholarships Board API</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 15px; box-shadow: 0 20px 40px rgba(0,0,0,0.1); overflow: hidden; }}
                .header {{ background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); padding: 40px; text-align: center; color: white; }}
                .header h1 {{ margin: 0; font-size: 2.5em; font-weight: 300; }}
                .header p {{ margin: 10px 0 0 0; opacity: 0.9; font-size: 1.2em; }}
                .content {{ padding: 40px; }}
                .status {{ display: inline-block; background: #10b981; color: white; padding: 8px 16px; border-radius: 20px; font-weight: bold; font-size: 0.9em; }}
                .endpoints {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 30px; margin-top: 40px; }}
                .endpoint-group {{ background: #f8fafc; border-radius: 12px; padding: 25px; border-left: 4px solid #4facfe; }}
                .endpoint-group h3 {{ margin: 0 0 20px 0; color: #1e293b; font-size: 1.3em; }}
                .endpoint-list {{ list-style: none; padding: 0; margin: 0; }}
                .endpoint-list li {{ margin: 12px 0; }}
                .endpoint-list a {{ color: #3b82f6; text-decoration: none; font-family: 'Courier New', monospace; font-size: 0.9em; padding: 8px 12px; background: #eff6ff; border-radius: 6px; display: inline-block; transition: all 0.2s; }}
                .endpoint-list a:hover {{ background: #dbeafe; transform: translateX(5px); }}
                .footer {{ background: #f1f5f9; padding: 20px 40px; text-align: center; color: #64748b; border-top: 1px solid #e2e8f0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🎓 Scholarships Board API</h1>
                    <p>A comprehensive REST API for managing scholarships and users</p>
                    <div style="margin-top: 20px;">
                        <span class="status">● {api_info["status"].upper()}</span>
                    </div>
                </div>

                <div class="content">
                    <div class="endpoints">
                        <div class="endpoint-group">
                            <h3>🔐 Authentication</h3>
                            <ul class="endpoint-list">
                                <li><a href="/api/auth/login/">POST /api/auth/login/</a></li>
                                <li><a href="/api/auth/logout/">POST /api/auth/logout/</a></li>
                                <li><a href="/api/auth/student/register/">POST /api/auth/student/register/</a></li>
                                <li><a href="/api/auth/admin/register/">POST /api/auth/admin/register/</a></li>
                                <li><a href="/api/auth/profile/">GET /api/auth/profile/</a></li>
                                <li><a href="/api/auth/token/refresh/">POST /api/auth/token/refresh/</a></li>
                            </ul>
                        </div>

                        <div class="endpoint-group">
                            <h3>📚 Scholarships</h3>
                            <ul class="endpoint-list">
                                <li><a href="/api/scholarships/">GET /api/scholarships/</a></li>
                                <li><a href="/api/scholarships/">POST /api/scholarships/</a></li>
                                <li><a href="#">GET /api/scholarships/{{id}}/</a></li>
                                <li><a href="/api/admin/scholarships/">GET /api/admin/scholarships/</a></li>
                                <li><a href="#">DELETE /api/admin/scholarships/{{id}}/delete/</a></li>
                            </ul>
                        </div>

                        <div class="endpoint-group">
                            <h3>👥 Admin Management</h3>
                            <ul class="endpoint-list">
                                <li><a href="/api/admin/statistics/">GET /api/admin/statistics/</a></li>
                                <li><a href="/api/admins/">GET /api/admins/</a></li>
                                <li><a href="/api/admins/">POST /api/admins/</a></li>
                                <li><a href="#">DELETE /api/admins/{{user_id}}/</a></li>
                                <li><a href="/api/admin/users/export/">GET /api/admin/users/export/</a></li>
                            </ul>
                        </div>
                    </div>
                </div>

                <div class="footer">
                    <p>API Version {api_info["version"]} | Built with Django REST Framework</p>
                </div>
            </div>
        </body>
        </html>
        """
        return HttpResponse(html_content, content_type="text/html")
    else:
        return Response(api_info, status=status.HTTP_200_OK)
