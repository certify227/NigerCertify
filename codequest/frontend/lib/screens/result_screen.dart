import 'package:flutter/material.dart';

import '../models/models.dart';
import '../theme.dart';

class ResultScreen extends StatelessWidget {
  final SubmissionResult result;
  final Lesson lesson;

  const ResultScreen({
    super.key,
    required this.result,
    required this.lesson,
  });

  @override
  Widget build(BuildContext context) {
    final passed = result.passed;
    final color = passed ? AppColors.primary : AppColors.danger;

    return Scaffold(
      body: SafeArea(
        child: Column(
          children: [
            Expanded(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(24),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    const SizedBox(height: 24),
                    Text(
                      passed ? '🎉' : '💪',
                      textAlign: TextAlign.center,
                      style: const TextStyle(fontSize: 80),
                    ),
                    const SizedBox(height: 16),
                    Text(
                      passed ? 'Leçon réussie !' : 'Presque !',
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        fontSize: 28,
                        fontWeight: FontWeight.w800,
                        color: color,
                      ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      '${result.correctCount}/${result.total} bonnes réponses',
                      textAlign: TextAlign.center,
                      style: const TextStyle(
                        color: AppColors.muted,
                        fontSize: 16,
                      ),
                    ),
                    const SizedBox(height: 24),
                    if (passed)
                      _RewardBanner(xp: result.earnedXp),
                    const SizedBox(height: 24),
                    const Text(
                      'Correction',
                      style: TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.bold,
                        color: AppColors.textDark,
                      ),
                    ),
                    const SizedBox(height: 12),
                    for (var i = 0; i < result.results.length; i++)
                      _ResultRow(
                        index: i + 1,
                        result: result.results[i],
                      ),
                  ],
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.all(24),
              child: SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  onPressed: () => Navigator.of(context).pop(),
                  child: const Text('CONTINUER'),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _RewardBanner extends StatelessWidget {
  final int xp;
  const _RewardBanner({required this.xp});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 16, horizontal: 20),
      decoration: BoxDecoration(
        color: AppColors.gold.withValues(alpha: 0.15),
        borderRadius: BorderRadius.circular(16),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(Icons.bolt, color: AppColors.gold, size: 28),
          const SizedBox(width: 8),
          Text(
            xp > 0 ? '+$xp XP gagnés !' : 'Leçon déjà terminée',
            style: const TextStyle(
              fontSize: 18,
              fontWeight: FontWeight.bold,
              color: AppColors.textDark,
            ),
          ),
        ],
      ),
    );
  }
}

class _ResultRow extends StatelessWidget {
  final int index;
  final ExerciseResult result;

  const _ResultRow({required this.index, required this.result});

  @override
  Widget build(BuildContext context) {
    final ok = result.correct;
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: (ok ? AppColors.primary : AppColors.danger)
            .withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(14),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(
            ok ? Icons.check_circle : Icons.cancel,
            color: ok ? AppColors.primary : AppColors.danger,
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Question $index',
                  style: const TextStyle(
                    fontWeight: FontWeight.bold,
                    color: AppColors.textDark,
                  ),
                ),
                const SizedBox(height: 2),
                Text('Réponse attendue : ${result.expected}'),
                if (result.explanation.isNotEmpty) ...[
                  const SizedBox(height: 4),
                  Text(
                    result.explanation,
                    style: const TextStyle(
                      color: AppColors.muted,
                      fontStyle: FontStyle.italic,
                    ),
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
}
