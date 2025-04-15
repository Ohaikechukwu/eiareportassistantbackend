from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

User = get_user_model()

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    passwordConfirm = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    
    class Meta:
        model = User
        fields = [
            'first_name', 
            'last_name',
            'other_name',
            'email',
            'phone',
            'department',
            'division',
            'password',
            'passwordConfirm'
        ]
        extra_kwargs = {
            'first_name': {'required': True, 'allow_blank': False},
            'last_name': {'required': True, 'allow_blank': False},
            'email': {'required': True},
            'phone': {'required': True},
            'department': {'required': True, 'allow_blank': False},
        }
        
    def validate(self, attrs):
        if attrs['password'] != attrs['passwordConfirm']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        
        if len(attrs['password']) < 8:
            raise serializers.ValidationError({"password": "Password must be at least 8 characters long."})
            
        return attrs
    
    def create(self, validated_data):
        # Remove passwordConfirm from validated_data
        validated_data.pop('passwordConfirm')
        
        username = validated_data['email'].split('@')[0]
        
        # Don't set username explicitly - the model will handle it
        user = User.objects.create_user(
            username=username,
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            other_name=validated_data.get('other_name', ''),
            phone=validated_data['phone'],
            department=validated_data['department'],
            division=validated_data.get('division', ''),
            password=validated_data['password']  # create_user handles password hashing
        )
        
        return user


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = self.get_token(self.user)
        
        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)
        
        # Add user details to response
        data['user'] = {
            'id': str(self.user.id),  # Convert UUID to string
            'email': self.user.email,
            'first_name': self.user.first_name,
            'last_name': self.user.last_name,
            'other_name': self.user.other_name,
            'phone': self.user.phone,
            'department': self.user.department,
            'division': self.user.division,
        }
        return data