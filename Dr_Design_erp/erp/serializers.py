from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

User = get_user_model()


class SignupSerializer(serializers.ModelSerializer):

    password = serializers.CharField(
        write_only=True,
        validators=[validate_password]
    )

    confirm_password = serializers.CharField(write_only=True)

    role = serializers.ChoiceField(
        choices=[
            ("LEAD_GEN", "Lead Generation"),
            ("INSIDE_SALES", "Inside Sales"),
            ("CRM", "CRM"),
            ("TECH", "Tech"),
            ("ACCOUNTS", "Accounts"),
        ]
    )

    class Meta:
        model = User

        fields = [
            "id",
            "first_name",
            "last_name",
            "email",
            "password",
            "confirm_password",
            "role",
        ]

        read_only_fields = ["id"]

    def validate(self, data):

        if data["password"] != data["confirm_password"]:
            raise serializers.ValidationError({
                "confirm_password": "Passwords do not match."
            })

        return data

    def create(self, validated_data):

        validated_data.pop("confirm_password")

        user = User.objects.create_user(
            **validated_data
        )

        return user