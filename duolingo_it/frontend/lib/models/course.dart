class Course {
  final int id;
  final String title;
  final String slug;
  final String description;
  final String language;
  final String icon;
  final String color;
  final int moduleCount;
  final int lessonCount;
  final List<Module> modules;

  const Course({
    required this.id,
    required this.title,
    required this.slug,
    required this.description,
    required this.language,
    required this.icon,
    required this.color,
    required this.moduleCount,
    required this.lessonCount,
    this.modules = const [],
  });

  factory Course.fromJson(Map<String, dynamic> json) => Course(
        id: json['id'] as int,
        title: json['title'] as String? ?? '',
        slug: json['slug'] as String? ?? '',
        description: json['description'] as String? ?? '',
        language: json['language'] as String? ?? '',
        icon: json['icon'] as String? ?? '📘',
        color: json['color'] as String? ?? '#58CC02',
        moduleCount: json['module_count'] as int? ?? 0,
        lessonCount: json['lesson_count'] as int? ?? 0,
        modules: (json['modules'] as List<dynamic>? ?? const [])
            .map((m) => Module.fromJson(m as Map<String, dynamic>))
            .toList(),
      );
}

class Module {
  final int id;
  final String title;
  final String description;
  final int order;
  final List<LessonSummary> lessons;

  const Module({
    required this.id,
    required this.title,
    required this.description,
    required this.order,
    required this.lessons,
  });

  factory Module.fromJson(Map<String, dynamic> json) => Module(
        id: json['id'] as int,
        title: json['title'] as String? ?? '',
        description: json['description'] as String? ?? '',
        order: json['order'] as int? ?? 0,
        lessons: (json['lessons'] as List<dynamic>? ?? const [])
            .map((l) => LessonSummary.fromJson(l as Map<String, dynamic>))
            .toList(),
      );
}

class LessonSummary {
  final int id;
  final String title;
  final String description;
  final int order;
  final int xpReward;
  final int exerciseCount;
  final bool isCompleted;

  const LessonSummary({
    required this.id,
    required this.title,
    required this.description,
    required this.order,
    required this.xpReward,
    required this.exerciseCount,
    required this.isCompleted,
  });

  factory LessonSummary.fromJson(Map<String, dynamic> json) => LessonSummary(
        id: json['id'] as int,
        title: json['title'] as String? ?? '',
        description: json['description'] as String? ?? '',
        order: json['order'] as int? ?? 0,
        xpReward: json['xp_reward'] as int? ?? 0,
        exerciseCount: json['exercise_count'] as int? ?? 0,
        isCompleted: json['is_completed'] as bool? ?? false,
      );
}
