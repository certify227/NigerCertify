from django.core.management.base import BaseCommand

from learning.models import Exercise, LearnerProfile, Lesson, LessonProgress, Track


class Command(BaseCommand):
    help = "Charge des donnees de demonstration pour le MVP DevLingo."

    def handle(self, *args, **options):
        profile, _ = LearnerProfile.objects.get_or_create(
            id=1,
            defaults={
                "display_name": "Aicha",
                "target_role": "Developpeuse mobile et cloud",
                "daily_goal_minutes": 25,
                "streak_days": 7,
                "total_xp": 320,
                "hearts": 5,
            },
        )

        python_track, _ = Track.objects.get_or_create(
            slug="python-fondamentaux",
            defaults={
                "title": "Python",
                "description": "Variables, fonctions et automatisation.",
                "icon": "code",
                "difficulty": Track.beginner,
                "color_start": "#2563EB",
                "color_end": "#7C3AED",
                "sort_order": 1,
            },
        )
        git_track, _ = Track.objects.get_or_create(
            slug="git-collaboration",
            defaults={
                "title": "Git & collaboration",
                "description": "Commits, branches et revues de code.",
                "icon": "source",
                "difficulty": Track.beginner,
                "color_start": "#EA580C",
                "color_end": "#DC2626",
                "sort_order": 2,
            },
        )
        linux_track, _ = Track.objects.get_or_create(
            slug="linux-terminal",
            defaults={
                "title": "Linux & terminal",
                "description": "Navigation shell et commandes clefs.",
                "icon": "terminal",
                "difficulty": Track.intermediate,
                "color_start": "#059669",
                "color_end": "#0F766E",
                "sort_order": 3,
            },
        )

        lessons = [
            (
                python_track,
                {
                    "slug": "python-variables",
                    "title": "Variables et types",
                    "summary": "Manipuler des chaines, entiers et listes.",
                    "estimated_minutes": 7,
                    "xp_reward": 15,
                    "challenge_count": 3,
                    "sort_order": 1,
                },
                [
                    {
                        "prompt": "Quel type renvoie len([1, 2, 3]) ?",
                        "exercise_type": Exercise.multiple_choice,
                        "options": ["str", "int", "list"],
                        "correct_answer": "int",
                        "explanation": "len renvoie toujours un entier.",
                        "sort_order": 1,
                    },
                    {
                        "prompt": "Quelle syntaxe affecte 42 a la variable age ?",
                        "exercise_type": Exercise.code_order,
                        "options": ["age == 42", "age = 42", "42 -> age"],
                        "correct_answer": "age = 42",
                        "explanation": "L'operateur d'affectation en Python est =.",
                        "sort_order": 2,
                    },
                ],
                LessonProgress.completed,
            ),
            (
                git_track,
                {
                    "slug": "git-premier-commit",
                    "title": "Premier commit",
                    "summary": "Initialiser un repo et sauvegarder son travail.",
                    "estimated_minutes": 6,
                    "xp_reward": 12,
                    "challenge_count": 3,
                    "sort_order": 1,
                },
                [
                    {
                        "prompt": "Quelle commande affiche l'etat du depot ?",
                        "exercise_type": Exercise.terminal,
                        "options": ["git push", "git status", "git merge"],
                        "correct_answer": "git status",
                        "explanation": "git status donne une vue rapide des changements.",
                        "sort_order": 1,
                    }
                ],
                LessonProgress.available,
            ),
            (
                linux_track,
                {
                    "slug": "linux-navigation",
                    "title": "Navigation shell",
                    "summary": "Se deplacer entre repertoires et lister des fichiers.",
                    "estimated_minutes": 8,
                    "xp_reward": 18,
                    "challenge_count": 4,
                    "sort_order": 1,
                },
                [
                    {
                        "prompt": "Quelle commande affiche le repertoire courant ?",
                        "exercise_type": Exercise.terminal,
                        "options": ["pwd", "ls", "cd"],
                        "correct_answer": "pwd",
                        "explanation": "pwd signifie print working directory.",
                        "sort_order": 1,
                    }
                ],
                LessonProgress.locked,
            ),
        ]

        for track, lesson_defaults, exercises, status in lessons:
            lesson, _ = Lesson.objects.get_or_create(
                slug=lesson_defaults["slug"],
                defaults={"track": track, **lesson_defaults},
            )
            if lesson.track_id != track.id:
                lesson.track = track
                lesson.save(update_fields=["track"])

            for exercise_defaults in exercises:
                Exercise.objects.get_or_create(
                    lesson=lesson,
                    sort_order=exercise_defaults["sort_order"],
                    defaults=exercise_defaults,
                )

            LessonProgress.objects.get_or_create(
                profile=profile,
                lesson=lesson,
                defaults={"status": status, "score": 100 if status == LessonProgress.completed else 0},
            )

        self.stdout.write(self.style.SUCCESS("Donnees de demonstration chargees."))
