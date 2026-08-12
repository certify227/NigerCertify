from django.contrib.auth import get_user_model
from rest_framework import generics, permissions
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import RegisterSerializer, UserSerializer

User = get_user_model()


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]


class MeView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user


class LeaderboardView(APIView):
    def get(self, request):
        top = User.objects.order_by("-xp")[:50]
        data = [
            {
                "rank": i + 1,
                "username": u.username,
                "avatar": u.avatar,
                "xp": u.xp,
                "streak_count": u.streak_count,
            }
            for i, u in enumerate(top)
        ]
        return Response(data)
