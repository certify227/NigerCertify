import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../models/models.dart';
import '../providers/app_state.dart';
import '../theme/app_theme.dart';
import '../widgets/code_editor_widget.dart';

class LessonScreen extends StatefulWidget {
  final int lessonId;
  final String title;

  const LessonScreen({super.key, required this.lessonId, required this.title});

  @override
  State<LessonScreen> createState() => _LessonScreenState();
}

class _LessonScreenState extends State<LessonScreen> {
  LessonDetail? _lesson;
  int _currentIndex = 0;
  bool _loading = true;
  bool _submitting = false;
  bool _runningCode = false;
  String? _feedback;
  bool? _lastCorrect;
  int? _selectedChoiceId;
  String _code = '';
  String? _codeOutput;
  String? _codeError;
  final _textController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _textController.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    final api = context.read<AppState>().api;
    final lesson = await api.getLesson(widget.lessonId);
    if (mounted) {
      setState(() {
        _lesson = lesson;
        _loading = false;
        if (lesson.exercises.isNotEmpty) {
          _code = lesson.exercises.first.starterCode;
        }
      });
    }
  }

  Exercise? get _currentExercise =>
      _lesson != null && _currentIndex < _lesson!.exercises.length
          ? _lesson!.exercises[_currentIndex]
          : null;

  void _resetExerciseState(Exercise exercise) {
    _feedback = null;
    _lastCorrect = null;
    _selectedChoiceId = null;
    _textController.clear();
    _code = exercise.starterCode;
    _codeOutput = null;
    _codeError = null;
  }

  Future<void> _runCode() async {
    setState(() {
      _runningCode = true;
      _codeOutput = null;
      _codeError = null;
    });
    try {
      final result = await context.read<AppState>().api.runCode(_code);
      if (!mounted) return;
      setState(() {
        _codeOutput = result.stdout.isNotEmpty ? result.stdout : '(aucune sortie)';
        if (result.stderr.isNotEmpty) _codeError = result.stderr;
        _runningCode = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _codeError = e.toString().replaceAll('ApiException: ', '');
        _runningCode = false;
      });
    }
  }

  Future<void> _submit() async {
    final exercise = _currentExercise;
    if (exercise == null || _submitting) return;

    setState(() => _submitting = true);
    try {
      final api = context.read<AppState>().api;
      final result = await api.submitAnswer(
        exercise.id,
        choiceId: _selectedChoiceId,
        answer: _textController.text.isNotEmpty ? _textController.text : null,
        code: exercise.exerciseType == 'code_challenge' ? _code : null,
      );

      if (!mounted) return;
      context.read<AppState>().updateFromSubmit(result);

      setState(() {
        _feedback = result.explanation;
        _lastCorrect = result.correct;
        _submitting = false;
      });

      if (result.correct) {
        await Future.delayed(const Duration(milliseconds: 1200));
        if (!mounted) return;
        if (_currentIndex < _lesson!.exercises.length - 1) {
          setState(() {
            _currentIndex++;
            _resetExerciseState(_lesson!.exercises[_currentIndex]);
          });
        } else {
          _showCompleteDialog(result.lessonComplete);
        }
      }
    } catch (e) {
      setState(() => _submitting = false);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(e.toString().replaceAll('ApiException: ', ''))),
        );
      }
    }
  }

  void _showCompleteDialog(bool lessonComplete) {
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        title: Text(lessonComplete ? '🎉 Leçon terminée !' : 'Exercices terminés'),
        content: Text(lessonComplete
            ? 'Bravo ! Vous avez gagné des XP bonus.'
            : 'Continuez pour terminer la leçon.'),
        actions: [
          TextButton(
            onPressed: () {
              Navigator.of(context).pop();
              Navigator.of(context).pop();
            },
            child: const Text('Continuer'),
          ),
        ],
      ),
    );
  }

  bool _canSubmit(Exercise exercise) {
    if (exercise.exerciseType == 'code_challenge') {
      return _code.trim().isNotEmpty;
    }
    if (exercise.exerciseType == 'fill_blank') {
      return _textController.text.isNotEmpty;
    }
    return _selectedChoiceId != null;
  }

  @override
  Widget build(BuildContext context) {
    if (_loading || _lesson == null) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }

    final exercise = _currentExercise!;
    final progress = (_currentIndex + 1) / _lesson!.exercises.length;
    final isCode = exercise.exerciseType == 'code_challenge';

    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
        leading: IconButton(
          icon: const Icon(Icons.close),
          onPressed: () => Navigator.of(context).pop(),
        ),
      ),
      body: Column(
        children: [
          LinearProgressIndicator(
            value: progress,
            backgroundColor: const Color(0xFFE5E5E5),
            color: AppTheme.primaryGreen,
            minHeight: 8,
          ),
          Expanded(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(20),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text(
                    'Question ${_currentIndex + 1}/${_lesson!.exercises.length}',
                    style: const TextStyle(color: AppTheme.textMuted, fontWeight: FontWeight.w600),
                  ),
                  const SizedBox(height: 16),
                  Text(
                    exercise.question,
                    style: Theme.of(context).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w800),
                  ),
                  if (exercise.hint.isNotEmpty) ...[
                    const SizedBox(height: 8),
                    Text('💡 ${exercise.hint}', style: const TextStyle(color: AppTheme.primaryBlue, fontSize: 13)),
                  ],
                  const SizedBox(height: 24),
                  if (isCode)
                    CodeEditorWidget(
                      key: ValueKey(exercise.id),
                      initialCode: exercise.starterCode,
                      onChanged: (v) => _code = v,
                      onRun: _runCode,
                      output: _codeOutput,
                      error: _codeError,
                      isRunning: _runningCode,
                    )
                  else if (exercise.exerciseType == 'fill_blank')
                    TextField(
                      controller: _textController,
                      decoration: const InputDecoration(hintText: 'Votre réponse'),
                      onSubmitted: (_) => _submit(),
                    )
                  else
                    ...exercise.choices.map((choice) {
                      final selected = _selectedChoiceId == choice.id;
                      Color? bg;
                      if (_lastCorrect != null && selected) {
                        bg = _lastCorrect!
                            ? AppTheme.primaryGreen.withOpacity(0.15)
                            : AppTheme.primaryRed.withOpacity(0.15);
                      }
                      return Padding(
                        padding: const EdgeInsets.only(bottom: 10),
                        child: Material(
                          color: bg ?? Colors.white,
                          borderRadius: BorderRadius.circular(12),
                          child: InkWell(
                            onTap: _lastCorrect == null
                                ? () => setState(() => _selectedChoiceId = choice.id)
                                : null,
                            borderRadius: BorderRadius.circular(12),
                            child: Container(
                              width: double.infinity,
                              padding: const EdgeInsets.all(16),
                              decoration: BoxDecoration(
                                borderRadius: BorderRadius.circular(12),
                                border: Border.all(
                                  color: selected ? AppTheme.primaryBlue : const Color(0xFFE5E5E5),
                                  width: selected ? 2 : 1,
                                ),
                              ),
                              child: Text(choice.text, style: const TextStyle(fontWeight: FontWeight.w600)),
                            ),
                          ),
                        ),
                      );
                    }),
                  if (_feedback != null && _feedback!.isNotEmpty) ...[
                    const SizedBox(height: 16),
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: (_lastCorrect ?? false)
                            ? AppTheme.primaryGreen.withOpacity(0.1)
                            : AppTheme.primaryRed.withOpacity(0.1),
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: Text(_feedback!, style: const TextStyle(fontSize: 14)),
                    ),
                  ],
                  const SizedBox(height: 24),
                  ElevatedButton(
                    onPressed: _submitting || !_canSubmit(exercise) ? null : _submit,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: _lastCorrect == false ? AppTheme.primaryRed : AppTheme.primaryGreen,
                    ),
                    child: _submitting
                        ? const SizedBox(
                            height: 20,
                            width: 20,
                            child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                          )
                        : Text(_lastCorrect == false ? 'Continuer' : isCode ? 'Soumettre le code' : 'Vérifier'),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}
