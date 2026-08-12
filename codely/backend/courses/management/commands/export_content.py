"""Exporte le contenu pédagogique en JSON."""

import json

from django.core.management.base import BaseCommand

from courses.models import Choice, Exercise, Lesson, Track, Unit


class Command(BaseCommand):
    help = "Exporte tous les parcours en JSON"

    def add_arguments(self, parser):
        parser.add_argument("--output", default="content_export.json")

    def handle(self, *args, **options):
        data = []
        for track in Track.objects.prefetch_related("units__lessons__exercises__choices"):
            track_data = {
                "title": track.title,
                "slug": track.slug,
                "description": track.description,
                "icon": track.icon,
                "color": track.color,
                "order": track.order,
                "is_published": track.is_published,
                "units": [],
            }
            for unit in track.units.all():
                unit_data = {
                    "title": unit.title,
                    "description": unit.description,
                    "order": unit.order,
                    "lessons": [],
                }
                for lesson in unit.lessons.all():
                    lesson_data = {
                        "title": lesson.title,
                        "description": lesson.description,
                        "order": lesson.order,
                        "xp_reward": lesson.xp_reward,
                        "exercises": [],
                    }
                    for ex in lesson.exercises.all():
                        ex_data = {
                            "question": ex.question,
                            "exercise_type": ex.exercise_type,
                            "hint": ex.hint,
                            "explanation": ex.explanation,
                            "order": ex.order,
                            "correct_answer": ex.correct_answer,
                            "starter_code": ex.starter_code,
                            "choices": [
                                {"text": c.text, "is_correct": c.is_correct, "order": c.order}
                                for c in ex.choices.all()
                            ],
                        }
                        lesson_data["exercises"].append(ex_data)
                    unit_data["lessons"].append(lesson_data)
                track_data["units"].append(unit_data)
            data.append(track_data)

        with open(options["output"], "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        self.stdout.write(self.style.SUCCESS(f"Exporté vers {options['output']} ({len(data)} parcours)"))
