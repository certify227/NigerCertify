"""Vues d'API pour l'app courses."""
from django.db.models import Count, Prefetch
from rest_framework import generics, permissions

from progress.models import LessonCompletion

from .models import Course, Lesson, Module
from .serializers import (
    CourseDetailSerializer,
    CourseListSerializer,
    LessonDetailSerializer,
)


class CourseListView(generics.ListAPIView):
    """Liste tous les cours avec quelques compteurs utiles."""

    serializer_class = CourseListSerializer
    permission_classes = [permissions.AllowAny]
    pagination_class = None

    def get_queryset(self):
        return Course.objects.annotate(
            module_count=Count("modules", distinct=True),
            lesson_count=Count("modules__lessons", distinct=True),
        ).order_by("order", "id")


class CourseDetailView(generics.RetrieveAPIView):
    """Détail d'un cours avec modules + leçons + progression utilisateur."""

    serializer_class = CourseDetailSerializer
    permission_classes = [permissions.AllowAny]
    lookup_field = "slug"

    def get_queryset(self):
        lessons_qs = Lesson.objects.annotate(exercise_count=Count("exercises"))
        modules_qs = Module.objects.prefetch_related(
            Prefetch("lessons", queryset=lessons_qs)
        )
        return Course.objects.annotate(
            module_count=Count("modules", distinct=True),
            lesson_count=Count("modules__lessons", distinct=True),
        ).prefetch_related(Prefetch("modules", queryset=modules_qs))

    def get_serializer_context(self):
        ctx = super().get_serializer_context()
        user = self.request.user
        if user.is_authenticated:
            ctx["completed_lesson_ids"] = set(
                LessonCompletion.objects.filter(user=user).values_list(
                    "lesson_id", flat=True
                )
            )
        else:
            ctx["completed_lesson_ids"] = set()
        return ctx


class LessonDetailView(generics.RetrieveAPIView):
    """Détail d'une leçon avec ses exercices (sans les réponses correctes)."""

    serializer_class = LessonDetailSerializer

    def get_queryset(self):
        return Lesson.objects.prefetch_related("exercises__choices").annotate(
            exercise_count=Count("exercises")
        )

    def get_serializer_context(self):
        ctx = super().get_serializer_context()
        user = self.request.user
        if user.is_authenticated:
            ctx["completed_lesson_ids"] = set(
                LessonCompletion.objects.filter(user=user, lesson_id=self.kwargs["pk"])
                .values_list("lesson_id", flat=True)
            )
        return ctx
