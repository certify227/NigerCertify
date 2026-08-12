enum ExerciseKind { mcq, trueFalse, fillBlank, codeOutput, unknown }

ExerciseKind exerciseKindFromString(String value) {
  switch (value) {
    case 'mcq':
      return ExerciseKind.mcq;
    case 'true_false':
      return ExerciseKind.trueFalse;
    case 'fill_blank':
      return ExerciseKind.fillBlank;
    case 'code_output':
      return ExerciseKind.codeOutput;
    default:
      return ExerciseKind.unknown;
  }
}

class Choice {
  final int id;
  final String text;
  final int order;

  const Choice({required this.id, required this.text, required this.order});

  factory Choice.fromJson(Map<String, dynamic> json) => Choice(
        id: json['id'] as int,
        text: json['text'] as String? ?? '',
        order: json['order'] as int? ?? 0,
      );
}

class Exercise {
  final int id;
  final ExerciseKind kind;
  final String prompt;
  final String codeSnippet;
  final int order;
  final List<Choice> choices;

  const Exercise({
    required this.id,
    required this.kind,
    required this.prompt,
    required this.codeSnippet,
    required this.order,
    required this.choices,
  });

  factory Exercise.fromJson(Map<String, dynamic> json) => Exercise(
        id: json['id'] as int,
        kind: exerciseKindFromString(json['kind'] as String? ?? ''),
        prompt: json['prompt'] as String? ?? '',
        codeSnippet: json['code_snippet'] as String? ?? '',
        order: json['order'] as int? ?? 0,
        choices: (json['choices'] as List<dynamic>? ?? const [])
            .map((c) => Choice.fromJson(c as Map<String, dynamic>))
            .toList(),
      );
}

class LessonDetail {
  final int id;
  final String title;
  final String description;
  final int xpReward;
  final bool isCompleted;
  final List<Exercise> exercises;

  const LessonDetail({
    required this.id,
    required this.title,
    required this.description,
    required this.xpReward,
    required this.isCompleted,
    required this.exercises,
  });

  factory LessonDetail.fromJson(Map<String, dynamic> json) => LessonDetail(
        id: json['id'] as int,
        title: json['title'] as String? ?? '',
        description: json['description'] as String? ?? '',
        xpReward: json['xp_reward'] as int? ?? 0,
        isCompleted: json['is_completed'] as bool? ?? false,
        exercises: (json['exercises'] as List<dynamic>? ?? const [])
            .map((e) => Exercise.fromJson(e as Map<String, dynamic>))
            .toList(),
      );
}

class ExerciseResult {
  final int exerciseId;
  final bool isCorrect;
  final String explanation;

  const ExerciseResult({
    required this.exerciseId,
    required this.isCorrect,
    required this.explanation,
  });

  factory ExerciseResult.fromJson(Map<String, dynamic> json) => ExerciseResult(
        exerciseId: json['exercise_id'] as int,
        isCorrect: json['is_correct'] as bool? ?? false,
        explanation: json['explanation'] as String? ?? '',
      );
}

class SubmissionResult {
  final bool passed;
  final int correctCount;
  final int totalCount;
  final int xpEarned;
  final int heartsLost;
  final List<ExerciseResult> results;

  const SubmissionResult({
    required this.passed,
    required this.correctCount,
    required this.totalCount,
    required this.xpEarned,
    required this.heartsLost,
    required this.results,
  });

  factory SubmissionResult.fromJson(Map<String, dynamic> json) => SubmissionResult(
        passed: json['passed'] as bool? ?? false,
        correctCount: json['correct_count'] as int? ?? 0,
        totalCount: json['total_count'] as int? ?? 0,
        xpEarned: json['xp_earned'] as int? ?? 0,
        heartsLost: json['hearts_lost'] as int? ?? 0,
        results: (json['results'] as List<dynamic>? ?? const [])
            .map((r) => ExerciseResult.fromJson(r as Map<String, dynamic>))
            .toList(),
      );
}
