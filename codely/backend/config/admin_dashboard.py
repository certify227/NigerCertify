from django.contrib import admin
from django.db.models import Count
from django.template.response import TemplateResponse
from django.urls import path

from courses.models import Exercise, Lesson, Track, Unit
from progress.models import UserLessonProgress


def admin_dashboard(request):
  """Tableau de bord enrichi pour la création de contenu."""
  stats = {
      "tracks": Track.objects.count(),
      "units": Unit.objects.count(),
      "lessons": Lesson.objects.count(),
      "exercises": Exercise.objects.count(),
      "completions": UserLessonProgress.objects.filter(completed=True).count(),
      "exercise_types": Exercise.objects.values("exercise_type").annotate(count=Count("id")),
      "recent_tracks": Track.objects.annotate(
          lesson_count=Count("units__lessons"),
          exercise_count=Count("units__lessons__exercises"),
      ).order_by("-id")[:5],
  }
  context = {
      **admin.site.each_context(request),
      "title": "Tableau de bord CodeQuest",
      "stats": stats,
  }
  return TemplateResponse(request, "admin/dashboard.html", context)


_original_get_urls = admin.site.get_urls


def get_urls():
    urls = _original_get_urls()
    custom = [
        path("dashboard/", admin.site.admin_view(admin_dashboard), name="codequest_dashboard"),
    ]
    return custom + urls


admin.site.get_urls = get_urls

# Personnalisation du site admin
admin.site.site_header = "CodeQuest — Administration"
admin.site.site_title = "CodeQuest Admin"
admin.site.index_title = "Gestion du contenu pédagogique"
