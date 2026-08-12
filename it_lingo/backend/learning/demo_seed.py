from .models import Challenge, Lesson, Module, Track


def seed_demo_data() -> dict[str, int]:
    python_track, _ = Track.objects.get_or_create(
        slug="python-foundations",
        defaults={
            "title": "Fondamentaux Python",
            "summary": "Variables, conditions, boucles et fonctions en micro-lecons.",
            "level": Track.BEGINNER,
            "estimated_minutes": 12,
            "color_theme": "#4C9AFF",
            "icon": "code",
            "order": 1,
        },
    )
    algo_track, _ = Track.objects.get_or_create(
        slug="algorithms",
        defaults={
            "title": "Algorithmes",
            "summary": "Raisonnement, complexite et structures de donnees de base.",
            "level": Track.INTERMEDIATE,
            "estimated_minutes": 18,
            "color_theme": "#FF9600",
            "icon": "memory",
            "order": 2,
        },
    )

    intro_module, _ = Module.objects.get_or_create(
        track=python_track,
        slug="intro",
        defaults={
            "title": "Introduction",
            "description": "Prendre en main la syntaxe Python et les types primitifs.",
            "xp_reward": 20,
            "order": 1,
        },
    )
    control_module, _ = Module.objects.get_or_create(
        track=python_track,
        slug="control-flow",
        defaults={
            "title": "Controle du flux",
            "description": "Maîtriser if/else, boucles et petites fonctions.",
            "xp_reward": 25,
            "order": 2,
        },
    )
    algo_module, _ = Module.objects.get_or_create(
        track=algo_track,
        slug="searching",
        defaults={
            "title": "Recherche et tri",
            "description": "Comparer la recherche lineaire, binaire et les tris usuels.",
            "xp_reward": 30,
            "order": 1,
        },
    )

    lessons = [
        {
            "module": intro_module,
            "slug": "variables",
            "title": "Variables et types",
            "lesson_type": Lesson.THEORY,
            "theory": "Une variable reference une valeur. Python infere le type dynamiquement.",
            "instructions": "Lis les exemples et identifie le type de chaque variable.",
            "starter_code": "username = 'Ada'\nscore = 120\nis_active = True",
            "solution_hint": "Repere str, int et bool.",
            "xp_reward": 10,
            "order": 1,
        },
        {
            "module": intro_module,
            "slug": "print-debug",
            "title": "Afficher et deboguer",
            "lesson_type": Lesson.DEBUG,
            "theory": "print() aide a verifier le contenu des variables pendant l'apprentissage.",
            "instructions": "Corrige le code pour afficher chaque valeur sur une ligne distincte.",
            "starter_code": "name = 'Linus'\nscore = 99\nprint(name, score)",
            "solution_hint": "Tu peux utiliser sep='\\n' ou plusieurs appels a print.",
            "xp_reward": 12,
            "order": 2,
        },
        {
            "module": control_module,
            "slug": "conditions",
            "title": "Conditions",
            "lesson_type": Lesson.CODE_QUIZ,
            "theory": "if/elif/else permet de brancher le programme selon une condition.",
            "instructions": "Complete la condition pour distinguer majeur et mineur.",
            "starter_code": "age = 17\nif age >= ?:\n    print('majeur')\nelse:\n    print('mineur')",
            "solution_hint": "En France et dans beaucoup de pays, la majorite civile est 18.",
            "xp_reward": 15,
            "order": 1,
        },
        {
            "module": algo_module,
            "slug": "binary-search",
            "title": "Recherche binaire",
            "lesson_type": Lesson.PROJECT,
            "theory": "La recherche binaire coupe l'espace de recherche en deux a chaque etape.",
            "instructions": "Implemente une recherche binaire et compare-la a la recherche lineaire.",
            "starter_code": "def binary_search(values, target):\n    left, right = 0, len(values) - 1\n    # TODO\n",
            "solution_hint": "Utilise mid = (left + right) // 2 et reduis la fenetre.",
            "xp_reward": 25,
            "order": 1,
        },
    ]

    for payload in lessons:
        Lesson.objects.get_or_create(
            module=payload["module"],
            slug=payload["slug"],
            defaults={k: v for k, v in payload.items() if k not in {"module", "slug"}},
        )

    Challenge.objects.update_or_create(
        title="Challenge du jour: boucle Python",
        defaults={
            "track": python_track,
            "prompt": "Ecris une boucle qui affiche les nombres pairs de 2 a 10.",
            "answer_format": "python",
            "difficulty": Challenge.EASY,
            "estimated_minutes": 4,
            "is_daily_featured": True,
            "reference_solution": "for number in range(2, 11, 2):\n    print(number)",
        },
    )
    Challenge.objects.filter(is_daily_featured=True).exclude(
        title="Challenge du jour: boucle Python"
    ).update(is_daily_featured=False)

    return {
        "tracks": Track.objects.count(),
        "modules": Module.objects.count(),
        "lessons": Lesson.objects.count(),
        "challenges": Challenge.objects.count(),
    }
