from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Scholarship, Student, Admin

class ScholarshipSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scholarship
        fields = '__all__'

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 'password')
    
    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()
        return user

class StudentSerializer(serializers.ModelSerializer):
    user = UserSerializer()
    
    class Meta:
        model = Student
        fields = '__all__'
    
    def create(self, validated_data):
        user_data = validated_data.pop('user')
        user = UserSerializer.create(UserSerializer(), validated_data=user_data)
        student = Student.objects.create(user=user, **validated_data)
        return student

class AdminSerializer(serializers.ModelSerializer):
    user = UserSerializer()
    
    class Meta:
        model = Admin
        fields = '__all__'
    
    def create(self, validated_data):
        user_data = validated_data.pop('user')
        user = UserSerializer.create(UserSerializer(), validated_data=user_data)
        admin = Admin.objects.create(user=user, **validated_data)
        return admin

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

