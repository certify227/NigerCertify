import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../api/endpoints.dart';
import '../models/lesson.dart';
import '../state/auth_state.dart';
import '../theme/app_theme.dart';
import '../widgets/exercise_card.dart';
import 'lesson_result_screen.dart';

class LessonScreen extends StatefulWidget {
  const LessonScreen({super.key, required this.lessonId});
  final int lessonId;

  @override
  State<LessonScreen> createState() => _LessonScreenState();
}

class _LessonScreenState extends State<LessonScreen> {
  late Future<LessonDetail> _future;
  final Map<int, String> _answers = {};
  int _currentIndex = 0;
  bool _submitting = false;

  @override
  void initState() {
    super.initState();
    _future =
        CoursesApi(context.read<AuthState>().client).lesson(widget.lessonId);
  }

  bool _hasAnswer(int exerciseId) {
    final a = _answers[exerciseId];
    return a != null && a.trim().isNotEmpty;
  }

  Future<void> _submit(LessonDetail lesson) async {
    setState(() => _submitting = true);
    try {
      final payload = lesson.exercises
          .map((e) => {
                'exercise_id': e.id,
                'answer': _answers[e.id] ?? '',
              })
          .toList();
      final res = await CoursesApi(context.read<AuthState>().client)
          .submitLesson(lesson.id, payload);
      final result = SubmissionResult.fromJson(res);
      // met à jour l'utilisateur avec le nouveau XP renvoyé
      context.read<AuthState>().updateUserFromJson(
            res['user'] as Map<String, dynamic>?,
          );
      if (!mounted) return;
      await Navigator.of(context).pushReplacement(
        MaterialPageRoute(
          builder: (_) => LessonResultScreen(
            lesson: lesson,
            result: result,
          ),
        ),
      );
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Erreur lors de la soumission : $e')),
      );
    } finally {
      if (mounted) setState(() => _submitting = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.close),
          onPressed: () => Navigator.of(context).pop(false),
        ),
        title: FutureBuilder<LessonDetail>(
          future: _future,
          builder: (context, snap) => Text(snap.data?.title ?? 'Leçon'),
        ),
      ),
      body: FutureBuilder<LessonDetail>(
        future: _future,
        builder: (context, snap) {
          if (snap.connectionState != ConnectionState.done) {
            return const Center(child: CircularProgressIndicator());
          }
          if (snap.hasError || !snap.hasData) {
            return Center(child: Text('Erreur : ${snap.error}'));
          }
          final lesson = snap.data!;
          if (lesson.exercises.isEmpty) {
            return const Center(
              child: Text('Aucun exercice dans cette leçon.'),
            );
          }
          final index = _currentIndex.clamp(0, lesson.exercises.length - 1);
          final exercise = lesson.exercises[index];
          final isLast = index == lesson.exercises.length - 1;
          return Column(
            children: [
              LinearProgressIndicator(
                value: (index + 1) / lesson.exercises.length,
                minHeight: 6,
                backgroundColor: const Color(0xFFE5E5E5),
                valueColor:
                    const AlwaysStoppedAnimation<Color>(AppColors.primary),
              ),
              Expanded(
                child: ExerciseCard(
                  key: ValueKey(exercise.id),
                  exercise: exercise,
                  initialAnswer: _answers[exercise.id],
                  onAnswerChanged: (v) => setState(
                      () => _answers[exercise.id] = v ?? ''),
                ),
              ),
              SafeArea(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Row(
                    children: [
                      if (index > 0)
                        Expanded(
                          child: OutlinedButton(
                            onPressed: () =>
                                setState(() => _currentIndex = index - 1),
                            child: const Text('PRÉCÉDENT'),
                          ),
                        ),
                      if (index > 0) const SizedBox(width: 12),
                      Expanded(
                        flex: 2,
                        child: ElevatedButton(
                          onPressed: !_hasAnswer(exercise.id) || _submitting
                              ? null
                              : () {
                                  if (isLast) {
                                    _submit(lesson);
                                  } else {
                                    setState(() => _currentIndex = index + 1);
                                  }
                                },
                          child: _submitting
                              ? const SizedBox(
                                  height: 20,
                                  width: 20,
                                  child: CircularProgressIndicator(
                                    color: Colors.white,
                                    strokeWidth: 2.5,
                                  ),
                                )
                              : Text(isLast ? 'VALIDER' : 'SUIVANT'),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          );
        },
      ),
    );
  }
}
