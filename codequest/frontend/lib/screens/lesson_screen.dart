import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../models/models.dart';
import '../state/app_state.dart';
import '../theme.dart';
import 'result_screen.dart';

class LessonScreen extends StatefulWidget {
  final int lessonId;
  const LessonScreen({super.key, required this.lessonId});

  @override
  State<LessonScreen> createState() => _LessonScreenState();
}

class _LessonScreenState extends State<LessonScreen> {
  late Future<Lesson> _future;

  @override
  void initState() {
    super.initState();
    _future = context.read<AppState>().api.lesson(widget.lessonId);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: FutureBuilder<Lesson>(
          future: _future,
          builder: (context, snapshot) {
            if (snapshot.connectionState == ConnectionState.waiting) {
              return const Center(child: CircularProgressIndicator());
            }
            if (snapshot.hasError) {
              return Center(child: Text('Erreur : ${snapshot.error}'));
            }
            final lesson = snapshot.data!;
            if (lesson.exercises.isEmpty) {
              return const Center(child: Text('Cette leçon est vide.'));
            }
            return _LessonRunner(lesson: lesson);
          },
        ),
      ),
    );
  }
}

class _LessonRunner extends StatefulWidget {
  final Lesson lesson;
  const _LessonRunner({required this.lesson});

  @override
  State<_LessonRunner> createState() => _LessonRunnerState();
}

class _LessonRunnerState extends State<_LessonRunner> {
  int _index = 0;
  final Map<int, String> _answers = {};
  String? _current;
  final TextEditingController _textController = TextEditingController();
  bool _submitting = false;

  Exercise get _exercise => widget.lesson.exercises[_index];
  bool get _isLast => _index == widget.lesson.exercises.length - 1;

  @override
  void dispose() {
    _textController.dispose();
    super.dispose();
  }

  void _select(String value) => setState(() => _current = value);

  Future<void> _next() async {
    final answer =
        _exercise.kind == 'fill_blank' ? _textController.text.trim() : _current;
    _answers[_exercise.id] = answer ?? '';

    if (!_isLast) {
      setState(() {
        _index++;
        _current = null;
        _textController.clear();
      });
      return;
    }

    setState(() => _submitting = true);
    final state = context.read<AppState>();
    try {
      final result = await state.api.submitLesson(widget.lesson.id, _answers);
      state.updateProfile(result.profile);
      if (!mounted) return;
      Navigator.of(context).pushReplacement(
        MaterialPageRoute(
          builder: (_) =>
              ResultScreen(result: result, lesson: widget.lesson),
        ),
      );
    } catch (e) {
      setState(() => _submitting = false);
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Erreur : $e')),
      );
    }
  }

  bool get _canContinue {
    if (_exercise.kind == 'fill_blank') {
      return _textController.text.trim().isNotEmpty;
    }
    return _current != null;
  }

  @override
  Widget build(BuildContext context) {
    final total = widget.lesson.exercises.length;
    final progress = (_index) / total;

    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            children: [
              IconButton(
                icon: const Icon(Icons.close),
                color: AppColors.muted,
                onPressed: () => Navigator.of(context).maybePop(),
              ),
              Expanded(
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(8),
                  child: LinearProgressIndicator(
                    value: progress,
                    minHeight: 14,
                    backgroundColor: const Color(0xFFE5E5E5),
                    color: AppColors.primary,
                  ),
                ),
              ),
              const SizedBox(width: 12),
              Text(
                '${_index + 1}/$total',
                style: const TextStyle(
                  fontWeight: FontWeight.bold,
                  color: AppColors.muted,
                ),
              ),
            ],
          ),
        ),
        Expanded(
          child: SingleChildScrollView(
            padding: const EdgeInsets.symmetric(horizontal: 24),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const SizedBox(height: 8),
                Text(
                  _questionLabel(_exercise.kind),
                  style: const TextStyle(
                    color: AppColors.secondary,
                    fontWeight: FontWeight.bold,
                    letterSpacing: 1,
                  ),
                ),
                const SizedBox(height: 12),
                Text(
                  _exercise.prompt,
                  style: const TextStyle(
                    fontSize: 22,
                    fontWeight: FontWeight.w700,
                    color: AppColors.textDark,
                    height: 1.3,
                  ),
                ),
                const SizedBox(height: 24),
                if (_exercise.kind == 'fill_blank')
                  TextField(
                    controller: _textController,
                    autofocus: true,
                    onChanged: (_) => setState(() {}),
                    decoration: const InputDecoration(
                      hintText: 'Ta réponse…',
                    ),
                  )
                else
                  ..._exercise.choices.map(
                    (choice) => _ChoiceTile(
                      label: choice,
                      selected: _current == choice,
                      onTap: () => _select(choice),
                    ),
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
              onPressed: (_canContinue && !_submitting) ? _next : null,
              child: _submitting
                  ? const SizedBox(
                      height: 22,
                      width: 22,
                      child: CircularProgressIndicator(
                        strokeWidth: 2.5,
                        color: Colors.white,
                      ),
                    )
                  : Text(_isLast ? 'VALIDER' : 'CONTINUER'),
            ),
          ),
        ),
      ],
    );
  }

  String _questionLabel(String kind) {
    switch (kind) {
      case 'true_false':
        return 'VRAI OU FAUX';
      case 'fill_blank':
        return 'COMPLÈTE';
      default:
        return 'CHOISIS LA BONNE RÉPONSE';
    }
  }
}

class _ChoiceTile extends StatelessWidget {
  final String label;
  final bool selected;
  final VoidCallback onTap;

  const _ChoiceTile({
    required this.label,
    required this.selected,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Material(
        color: selected
            ? AppColors.secondary.withValues(alpha: 0.12)
            : AppColors.surface,
        borderRadius: BorderRadius.circular(16),
        child: InkWell(
          borderRadius: BorderRadius.circular(16),
          onTap: onTap,
          child: Container(
            width: double.infinity,
            padding: const EdgeInsets.all(18),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(16),
              border: Border.all(
                color: selected ? AppColors.secondary : const Color(0xFFE0E0E0),
                width: 2,
              ),
            ),
            child: Text(
              label,
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.w600,
                color: selected ? AppColors.secondary : AppColors.textDark,
              ),
            ),
          ),
        ),
      ),
    );
  }
}
