from django.test import TestCase
from django.urls import reverse

from .models import Exercise, LearnerProfile, Lesson, LessonProgress, Track


class LearningApiTests(TestCase):
    def setUp(self):
        self.profile = LearnerProfile.objects.create(
            display_name="Fatou",
            target_role="DevOps junior",
            daily_goal_minutes=15,
            streak_days=3,
            total_xp=90,
            hearts=4,
        )
        self.track = Track.objects.create(
            title="Python",
            slug="python",
            description="Bases du langage et automatisation.",
            difficulty=Track.beginner,
            sort_order=1,
        )
        self.lesson = Lesson.objects.create(
            track=self.track,
            title="Variables",
            slug="variables-python",
            summary="Comprendre les types et l'affectation.",
            estimated_minutes=6,
            xp_reward=10,
            challenge_count=3,
            sort_order=1,
        )
        Exercise.objects.create(
            lesson=self.lesson,
            prompt="Quel type renvoie len('abc') ?",
            exercise_type=Exercise.multiple_choice,
            options=["str", "int", "bool"],
            correct_answer="int",
            explanation="len retourne un entier.",
            sort_order=1,
        )
        LessonProgress.objects.create(
            profile=self.profile,
            lesson=self.lesson,
            status=LessonProgress.completed,
            score=100,
        )

    def test_dashboard_returns_profile_and_tracks(self):
        response = self.client.get(reverse("dashboard"))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("profile", payload)
        self.assertEqual(payload["tracks"][0]["slug"], "python")
        self.assertEqual(payload["tracks"][0]["progress_percent"], 100)

    def test_lesson_detail_returns_exercises(self):
        response = self.client.get(reverse("lesson-detail", args=["variables-python"]))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["track_title"], "Python")
        self.assertEqual(len(payload["exercises"]), 1)
