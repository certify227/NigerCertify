from django.contrib.auth import get_user_model
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView

from accounts.serializers import LeaderboardSerializer, RegisterSerializer, ReminderSettingsSerializer, UserSerializer

User = get_user_model()


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]


class ProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user


class LeaderboardView(generics.ListAPIView):
    serializer_class = LeaderboardSerializer
    queryset = User.objects.order_by("-xp")[:50]


class RefillHeartsView(APIView):
    """Recharge les cœurs (pour le MVP, gratuit — en prod : pub ou attente)."""

    def post(self, request):
        from progress.services import refill_hearts

        refill_hearts(request.user)
        return Response({"hearts": request.user.hearts})


class ReminderSettingsView(generics.RetrieveUpdateAPIView):
    serializer_class = ReminderSettingsSerializer

    def get_object(self):
        return self.request.user
