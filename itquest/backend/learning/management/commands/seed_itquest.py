from django.core.management.base import BaseCommand

from learning.models import AnswerOption, Lesson, Question, Track


COURSES = [
    {
        "title": "Python débutant",
        "slug": "python-debutant",
        "description": "Apprends les bases de Python avec des mini-défis quotidiens.",
        "icon": "terminal",
        "lessons": [
            {
                "title": "Variables et types",
                "summary": "Comprendre comment stocker une information dans un programme.",
                "xp_reward": 20,
                "questions": [
                    {
                        "prompt": "Quelle instruction crée une variable appelée age ?",
                        "explanation": "En Python, une variable est créée lors de l'affectation avec =.",
                        "options": [
                            ("let age = 20", False),
                            ("age = 20", True),
                            ("int age = 20", False),
                        ],
                    },
                    {
                        "prompt": "Quel type représente le texte \"hello\" ?",
                        "explanation": "Les chaînes de caractères Python utilisent le type str.",
                        "options": [
                            ("bool", False),
                            ("str", True),
                            ("list", False),
                        ],
                    },
                ],
            }
        ],
    },
    {
        "title": "Réseaux essentiels",
        "slug": "reseaux-essentiels",
        "description": "Découvre IP, DNS, ports et protocoles avec des quiz courts.",
        "icon": "router",
        "lessons": [
            {
                "title": "DNS et ports",
                "summary": "Identifier les services courants et leur rôle.",
                "xp_reward": 25,
                "questions": [
                    {
                        "prompt": "Quel service traduit un nom de domaine en adresse IP ?",
                        "explanation": "DNS associe les noms lisibles aux adresses IP utilisées par les machines.",
                        "options": [
                            ("DNS", True),
                            ("SSH", False),
                            ("SMTP", False),
                        ],
                    },
                    {
                        "prompt": "Quel port est généralement utilisé par HTTPS ?",
                        "explanation": "HTTPS utilise généralement le port TCP 443.",
                        "options": [
                            ("22", False),
                            ("80", False),
                            ("443", True),
                        ],
                    },
                ],
            }
        ],
    },
    {
        "title": "Sécurité web",
        "slug": "securite-web",
        "description": "Progresse sur les vulnérabilités web avec une approche défensive.",
        "icon": "shield",
        "lessons": [
            {
                "title": "XSS côté défense",
                "summary": "Reconnaître les risques XSS et les bonnes protections.",
                "xp_reward": 30,
                "questions": [
                    {
                        "prompt": "Quelle défense réduit le risque XSS dans du HTML dynamique ?",
                        "explanation": "L'échappement de sortie empêche le navigateur d'interpréter du texte utilisateur comme du code.",
                        "options": [
                            ("Échapper les sorties utilisateur", True),
                            ("Désactiver les logs", False),
                            ("Changer le port HTTP", False),
                        ],
                    }
                ],
            }
        ],
    },
]


class Command(BaseCommand):
    help = "Seed demo tracks, lessons and questions for the IT learning app."

    def handle(self, *args, **options):
        created_tracks = 0
        for track_order, course in enumerate(COURSES, start=1):
            track, created = Track.objects.update_or_create(
                slug=course["slug"],
                defaults={
                    "title": course["title"],
                    "description": course["description"],
                    "icon": course["icon"],
                    "order": track_order,
                },
            )
            created_tracks += int(created)

            for lesson_order, lesson_data in enumerate(course["lessons"], start=1):
                lesson, _ = Lesson.objects.update_or_create(
                    track=track,
                    order=lesson_order,
                    defaults={
                        "title": lesson_data["title"],
                        "summary": lesson_data["summary"],
                        "xp_reward": lesson_data["xp_reward"],
                    },
                )

                lesson.questions.all().delete()
                for question_order, question_data in enumerate(lesson_data["questions"], start=1):
                    question = Question.objects.create(
                        lesson=lesson,
                        prompt=question_data["prompt"],
                        explanation=question_data["explanation"],
                        order=question_order,
                    )
                    for option_order, (text, is_correct) in enumerate(
                        question_data["options"],
                        start=1,
                    ):
                        AnswerOption.objects.create(
                            question=question,
                            text=text,
                            is_correct=is_correct,
                            order=option_order,
                        )

        self.stdout.write(
            self.style.SUCCESS(
                f"Seed terminé : {len(COURSES)} parcours synchronisés, {created_tracks} nouveau(x)."
            )
        )
