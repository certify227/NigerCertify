from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from .models import Challenge, Lesson, Module, Track


class LearningApiTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.track = Track.objects.create(
            title="Python Foundations",
            slug="python-foundations",
            summary="Learn Python basics through short exercises.",
            level=Track.BEGINNER,
            estimated_minutes=12,
            color_theme="#4C9AFF",
            icon="code",
            order=1,
        )
        module = Module.objects.create(
            track=cls.track,
            title="Intro",
            slug="intro",
            description="Syntax and variables.",
            xp_reward=20,
            order=1,
        )
        Lesson.objects.create(
            module=module,
            title="Variables",
            slug="variables",
            lesson_type=Lesson.THEORY,
            theory="Variables hold values.",
            instructions="Identify the types.",
            starter_code="name = 'Ada'",
            solution_hint="Use str.",
            xp_reward=10,
            order=1,
        )
        Lesson.objects.create(
            module=module,
            title="Conditions",
            slug="conditions",
            lesson_type=Lesson.CODE_QUIZ,
            theory="if/else branches based on expressions.",
            instructions="Complete the if statement.",
            starter_code="age = 17",
            solution_hint="Use 18.",
            xp_reward=15,
            order=2,
        )
        Challenge.objects.create(
            track=cls.track,
            title="Daily loop challenge",
            prompt="Print even numbers from 2 to 10.",
            answer_format="python",
            difficulty=Challenge.EASY,
            estimated_minutes=4,
            is_daily_featured=True,
            reference_solution="for number in range(2, 11, 2):\n    print(number)",
        )

    def setUp(self):
        self.client = APIClient()

    def test_health_endpoint(self):
        response = self.client.get(reverse("health"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")

    def test_track_list_endpoint(self):
        response = self.client.get(reverse("track-list"))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0]["slug"], "python-foundations")
        self.assertEqual(payload[0]["module_count"], 1)
        self.assertEqual(payload[0]["lesson_count"], 2)

    def test_track_detail_endpoint_returns_nested_modules(self):
        response = self.client.get(reverse("track-detail", kwargs={"slug": self.track.slug}))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["slug"], self.track.slug)
        self.assertEqual(len(payload["modules"]), 1)
        self.assertEqual(len(payload["modules"][0]["lessons"]), 2)

    def test_daily_challenge_endpoint(self):
        response = self.client.get(reverse("daily-challenge"))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["answer_format"], "python")
        self.assertTrue(payload["is_daily_featured"])

    def test_dashboard_endpoint_aggregates_home_data(self):
        response = self.client.get(reverse("dashboard"))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["streak_goal"], 20)
        self.assertEqual(payload["daily_xp_target"], 50)
        self.assertEqual(len(payload["tracks"]), 1)
        self.assertEqual(payload["daily_challenge"]["title"], "Daily loop challenge")
