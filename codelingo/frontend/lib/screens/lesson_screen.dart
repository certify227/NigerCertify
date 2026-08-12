import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../app_state.dart';
import '../models.dart';
import '../theme.dart';

class LessonScreen extends StatefulWidget {
  final Lesson lesson;
  const LessonScreen({super.key, required this.lesson});

  @override
  State<LessonScreen> createState() => _LessonScreenState();
}

class _LessonScreenState extends State<LessonScreen> {
  late Future<List<Exercise>> _future;
  List<Exercise> _exercises = [];
  final Map<int, String> _answers = {};

  int _index = 0;
  String? _selected;
  final TextEditingController _typed = TextEditingController();
  bool _checked = false;
  bool _isCorrect = false;

  @override
  void initState() {
    super.initState();
    _future = context
        .read<AppState>()
        .api
        .fetchLessonExercises(widget.lesson.id)
        .then((value) {
      _exercises = value;
      return value;
    });
  }

  @override
  void dispose() {
    _typed.dispose();
    super.dispose();
  }

  Exercise get _current => _exercises[_index];

  bool get _hasAnswer {
    if (_isChoiceType(_current.type)) return _selected != null;
    return _typed.text.trim().isNotEmpty;
  }

  bool _isChoiceType(String type) =>
      type == 'multiple_choice' || type == 'true_false';

  void _check() {
    final answer =
        _isChoiceType(_current.type) ? (_selected ?? '') : _typed.text.trim();
    _answers[_current.id] = answer;
    setState(() {
      _checked = true;
      _isCorrect =
          answer.toLowerCase() == _current.correctAnswer.toLowerCase();
    });
  }

  Future<void> _next() async {
    if (_index < _exercises.length - 1) {
      setState(() {
        _index++;
        _selected = null;
        _typed.clear();
        _checked = false;
      });
    } else {
      await _finish();
    }
  }

  Future<void> _finish() async {
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (_) => const Center(child: CircularProgressIndicator()),
    );
    try {
      final result = await context
          .read<AppState>()
          .api
          .completeLesson(widget.lesson.id, _answers);
      if (!mounted) return;
      Navigator.of(context).pop(); // dismiss loader
      await showDialog(
        context: context,
        barrierDismissible: false,
        builder: (_) => _ResultDialog(result: result),
      );
      if (mounted) Navigator.of(context).pop(true);
    } catch (e) {
      if (!mounted) return;
      Navigator.of(context).pop();
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text('$e')));
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
        title: FutureBuilder<List<Exercise>>(
          future: _future,
          builder: (context, snapshot) {
            final total = _exercises.isEmpty ? 1 : _exercises.length;
            return ClipRRect(
              borderRadius: BorderRadius.circular(8),
              child: LinearProgressIndicator(
                value: _exercises.isEmpty ? 0 : (_index + 1) / total,
                minHeight: 12,
                backgroundColor: AppColors.locked,
                color: AppColors.primary,
              ),
            );
          },
        ),
      ),
      body: FutureBuilder<List<Exercise>>(
        future: _future,
        builder: (context, snapshot) {
          if (snapshot.connectionState == ConnectionState.waiting) {
            return const Center(child: CircularProgressIndicator());
          }
          if (snapshot.hasError) {
            return Center(child: Text('${snapshot.error}'));
          }
          if (_exercises.isEmpty) {
            return const Center(child: Text('Aucun exercice.'));
          }
          return _buildExercise();
        },
      ),
    );
  }

  Widget _buildExercise() {
    return Column(
      children: [
        Expanded(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(20),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  _questionLabel(_current.type),
                  style: const TextStyle(
                    color: AppColors.textLight,
                    fontWeight: FontWeight.bold,
                    letterSpacing: 1,
                  ),
                ),
                const SizedBox(height: 12),
                Text(
                  _current.question,
                  style: const TextStyle(
                    fontSize: 22,
                    fontWeight: FontWeight.bold,
                    color: AppColors.textDark,
                  ),
                ),
                const SizedBox(height: 24),
                if (_isChoiceType(_current.type))
                  ..._current.choices.map(_choiceTile)
                else
                  TextField(
                    controller: _typed,
                    enabled: !_checked,
                    onChanged: (_) => setState(() {}),
                    decoration: const InputDecoration(
                      hintText: 'Écris ta réponse',
                      border: OutlineInputBorder(),
                    ),
                  ),
              ],
            ),
          ),
        ),
        _buildFooter(),
      ],
    );
  }

  Widget _choiceTile(String choice) {
    final selected = _selected == choice;
    Color border = AppColors.locked;
    Color? bg;
    if (_checked) {
      if (choice.toLowerCase() == _current.correctAnswer.toLowerCase()) {
        border = AppColors.primary;
        bg = AppColors.primary.withValues(alpha: 0.12);
      } else if (selected) {
        border = AppColors.danger;
        bg = AppColors.danger.withValues(alpha: 0.12);
      }
    } else if (selected) {
      border = AppColors.secondary;
      bg = AppColors.secondary.withValues(alpha: 0.12);
    }
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: InkWell(
        borderRadius: BorderRadius.circular(14),
        onTap: _checked ? null : () => setState(() => _selected = choice),
        child: Container(
          width: double.infinity,
          padding: const EdgeInsets.all(18),
          decoration: BoxDecoration(
            color: bg,
            border: Border.all(color: border, width: 2),
            borderRadius: BorderRadius.circular(14),
          ),
          child: Text(
            choice,
            style: const TextStyle(
              fontSize: 16,
              fontWeight: FontWeight.w600,
              color: AppColors.textDark,
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildFooter() {
    final feedbackColor =
        _isCorrect ? AppColors.primaryDark : AppColors.danger;
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: _checked
            ? feedbackColor.withValues(alpha: 0.1)
            : Colors.white,
        border: const Border(top: BorderSide(color: AppColors.locked)),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (_checked) ...[
            Row(
              children: [
                Icon(
                  _isCorrect ? Icons.check_circle : Icons.cancel,
                  color: feedbackColor,
                ),
                const SizedBox(width: 8),
                Text(
                  _isCorrect ? 'Bravo !' : 'Pas tout à fait',
                  style: TextStyle(
                    color: feedbackColor,
                    fontWeight: FontWeight.bold,
                    fontSize: 18,
                  ),
                ),
              ],
            ),
            if (!_isCorrect)
              Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Text('Réponse : ${_current.correctAnswer}'),
              ),
            if (_current.explanation.isNotEmpty)
              Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Text(
                  _current.explanation,
                  style: const TextStyle(color: AppColors.textLight),
                ),
              ),
            const SizedBox(height: 12),
          ],
          SizedBox(
            width: double.infinity,
            child: ElevatedButton(
              style: _checked
                  ? ElevatedButton.styleFrom(backgroundColor: feedbackColor)
                  : null,
              onPressed: _checked
                  ? _next
                  : (_hasAnswer ? _check : null),
              child: Text(
                _checked
                    ? (_index < _exercises.length - 1 ? 'Continuer' : 'Terminer')
                    : 'Vérifier',
              ),
            ),
          ),
        ],
      ),
    );
  }

  String _questionLabel(String type) {
    switch (type) {
      case 'true_false':
        return 'VRAI OU FAUX';
      case 'fill_blank':
        return 'COMPLÈTE';
      case 'type_answer':
        return 'RÉPONDS';
      default:
        return 'CHOISIS LA BONNE RÉPONSE';
    }
  }
}

class _ResultDialog extends StatelessWidget {
  final LessonResult result;
  const _ResultDialog({required this.result});

  @override
  Widget build(BuildContext context) {
    final passed = result.passed;
    return Dialog(
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
      child: Padding(
        padding: const EdgeInsets.all(28),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(passed ? '🎉' : '💪', style: const TextStyle(fontSize: 64)),
            const SizedBox(height: 12),
            Text(
              passed ? 'Leçon terminée !' : 'Continue tes efforts !',
              style: const TextStyle(
                fontSize: 22,
                fontWeight: FontWeight.bold,
                color: AppColors.textDark,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              '${result.correct}/${result.total} bonnes réponses (${result.score}%)',
              style: const TextStyle(color: AppColors.textLight),
            ),
            const SizedBox(height: 16),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                _badge('⚡', '+${result.xpGained} XP', AppColors.primary),
              ],
            ),
            const SizedBox(height: 24),
            SizedBox(
              width: double.infinity,
              child: ElevatedButton(
                onPressed: () => Navigator.of(context).pop(),
                child: const Text('Continuer'),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _badge(String emoji, String label, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(emoji, style: const TextStyle(fontSize: 20)),
          const SizedBox(width: 6),
          Text(
            label,
            style: TextStyle(color: color, fontWeight: FontWeight.bold),
          ),
        ],
      ),
    );
  }
}
