import 'package:flutter/material.dart';

import '../models/lesson.dart';
import '../theme/app_theme.dart';

class LessonResultScreen extends StatelessWidget {
  const LessonResultScreen({
    super.key,
    required this.lesson,
    required this.result,
  });

  final LessonDetail lesson;
  final SubmissionResult result;

  @override
  Widget build(BuildContext context) {
    final passed = result.passed;
    final color = passed ? AppColors.primary : AppColors.danger;
    final title = passed ? 'Bravo !' : 'Presque !';
    final subtitle = passed
        ? '+${result.xpEarned} XP · leçon terminée'
        : '${result.correctCount}/${result.totalCount} bonnes réponses';

    return Scaffold(
      appBar: AppBar(
        automaticallyImplyLeading: false,
        title: Text(lesson.title),
      ),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.all(24),
            decoration: BoxDecoration(
              color: color.withOpacity(0.1),
              borderRadius: BorderRadius.circular(16),
            ),
            child: Column(
              children: [
                Icon(
                  passed ? Icons.emoji_events : Icons.sentiment_neutral,
                  size: 64,
                  color: color,
                ),
                const SizedBox(height: 12),
                Text(
                  title,
                  style: TextStyle(
                    fontSize: 28,
                    fontWeight: FontWeight.w900,
                    color: color,
                  ),
                ),
                const SizedBox(height: 6),
                Text(subtitle,
                    style: const TextStyle(fontSize: 16),
                    textAlign: TextAlign.center),
              ],
            ),
          ),
          const SizedBox(height: 24),
          const Text(
            'Correction',
            style: TextStyle(fontSize: 18, fontWeight: FontWeight.w800),
          ),
          const SizedBox(height: 12),
          ...result.results.map((r) {
            final ex = lesson.exercises.firstWhere(
              (e) => e.id == r.exerciseId,
              orElse: () => Exercise(
                id: r.exerciseId,
                kind: ExerciseKind.unknown,
                prompt: '',
                codeSnippet: '',
                order: 0,
                choices: const [],
              ),
            );
            return Card(
              child: Padding(
                padding: const EdgeInsets.all(14),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Icon(
                      r.isCorrect ? Icons.check_circle : Icons.cancel,
                      color: r.isCorrect ? AppColors.primary : AppColors.danger,
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(ex.prompt,
                              style: const TextStyle(
                                  fontWeight: FontWeight.w700)),
                          if (r.explanation.isNotEmpty) ...[
                            const SizedBox(height: 6),
                            Text(
                              r.explanation,
                              style: const TextStyle(
                                color: AppColors.textSecondary,
                              ),
                            ),
                          ],
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            );
          }),
          const SizedBox(height: 24),
          ElevatedButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('CONTINUER'),
          ),
        ],
      ),
    );
  }
}
