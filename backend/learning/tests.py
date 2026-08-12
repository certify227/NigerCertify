from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from .models import Challenge, LearnerProfile, Lesson, LessonProgress, Track, Unit


class LearningApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = get_user_model().objects.create_user(username="amina", password="strong-pass-123")
        self.track = Track.objects.create(
            slug="python-fundamentals",
            title="Fondamentaux Python",
            description="Bases de Python",
            order=1,
        )
        self.unit = Unit.objects.create(track=self.track, title="Premiers pas", order=1)
        self.lesson = Lesson.objects.create(
            unit=self.unit,
            title="Variables",
            summary="Comprendre les variables",
            xp_reward=15,
            order=1,
        )
        self.challenge_one = Challenge.objects.create(
            lesson=self.lesson,
            type=Challenge.ChallengeType.MULTIPLE_CHOICE,
            prompt="Quel type représente True ?",
            choices=["str", "bool"],
            correct_answer="bool",
            explanation="True est un booléen.",
            order=1,
        )
        self.challenge_two = Challenge.objects.create(
            lesson=self.lesson,
            type=Challenge.ChallengeType.CODE_ORDER,
            prompt="Réordonne le code.",
            choices=["name = 'Ada'", "print(name)"],
            correct_answer=["name = 'Ada'", "print(name)"],
            explanation="On assigne avant d’afficher.",
            order=2,
        )

    def test_tracks_include_nested_learning_content(self):
        response = self.client.get("/api/tracks/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data[0]["slug"], "python-fundamentals")
        self.assertEqual(response.data[0]["units"][0]["lessons"][0]["challenge_count"], 2)

    def test_lesson_detail_hides_correct_answers(self):
        response = self.client.get(f"/api/lessons/{self.lesson.id}/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("challenges", response.data)
        self.assertNotIn("correct_answer", response.data["challenges"][0])

    def test_submit_answers_records_progress_and_xp(self):
        self.client.force_authenticate(user=self.user)

        first = self.client.post(
            f"/api/challenges/{self.challenge_one.id}/submit/",
            {"answer": "bool"},
            format="json",
        )
        second = self.client.post(
            f"/api/challenges/{self.challenge_two.id}/submit/",
            {"answer": ["name = 'Ada'", "print(name)"]},
            format="json",
        )

        self.assertEqual(first.status_code, 201)
        self.assertTrue(first.data["is_correct"])
        self.assertEqual(first.data["earned_xp"], 1)
        self.assertFalse(first.data["lesson_completed"])
        self.assertEqual(second.status_code, 201)
        self.assertTrue(second.data["lesson_completed"])
        self.assertEqual(second.data["earned_xp"], 15)
        self.assertEqual(LessonProgress.objects.get(user=self.user, lesson=self.lesson).earned_xp, 16)
        self.assertEqual(LearnerProfile.objects.get(user=self.user).total_xp, 16)
