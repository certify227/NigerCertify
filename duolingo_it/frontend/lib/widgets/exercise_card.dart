import 'package:flutter/material.dart';

import '../models/lesson.dart';
import '../theme/app_theme.dart';

/// Widget d'exercice qui adapte son rendu selon [Exercise.kind].
/// Notifie le parent avec la réponse via [onAnswerChanged].
class ExerciseCard extends StatefulWidget {
  const ExerciseCard({
    super.key,
    required this.exercise,
    required this.onAnswerChanged,
    this.initialAnswer,
  });

  final Exercise exercise;
  final ValueChanged<String?> onAnswerChanged;
  final String? initialAnswer;

  @override
  State<ExerciseCard> createState() => _ExerciseCardState();
}

class _ExerciseCardState extends State<ExerciseCard> {
  String? _answer;
  final TextEditingController _textController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _answer = widget.initialAnswer;
    if (widget.exercise.kind == ExerciseKind.fillBlank ||
        widget.exercise.kind == ExerciseKind.codeOutput) {
      _textController.text = widget.initialAnswer ?? '';
    }
  }

  @override
  void dispose() {
    _textController.dispose();
    super.dispose();
  }

  void _set(String? value) {
    setState(() => _answer = value);
    widget.onAnswerChanged(value);
  }

  @override
  Widget build(BuildContext context) {
    final ex = widget.exercise;
    return SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(
            ex.prompt,
            style: const TextStyle(fontSize: 22, fontWeight: FontWeight.w800),
          ),
          if (ex.codeSnippet.isNotEmpty) ...[
            const SizedBox(height: 16),
            _CodeBlock(code: ex.codeSnippet),
          ],
          const SizedBox(height: 24),
          _buildBody(ex),
        ],
      ),
    );
  }

  Widget _buildBody(Exercise ex) {
    switch (ex.kind) {
      case ExerciseKind.mcq:
        return Column(
          children: ex.choices.map((c) {
            final selected = _answer == c.id.toString();
            return Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: _ChoiceTile(
                text: c.text,
                selected: selected,
                onTap: () => _set(c.id.toString()),
              ),
            );
          }).toList(),
        );
      case ExerciseKind.trueFalse:
        return Row(
          children: [
            Expanded(
              child: _ChoiceTile(
                text: 'Vrai',
                selected: _answer == 'true',
                onTap: () => _set('true'),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _ChoiceTile(
                text: 'Faux',
                selected: _answer == 'false',
                onTap: () => _set('false'),
              ),
            ),
          ],
        );
      case ExerciseKind.fillBlank:
      case ExerciseKind.codeOutput:
        return TextField(
          controller: _textController,
          decoration: InputDecoration(
            hintText: ex.kind == ExerciseKind.codeOutput
                ? 'Ta réponse (ex : 3)'
                : 'Ta réponse',
          ),
          onChanged: _set,
        );
      case ExerciseKind.unknown:
        return const Text('Type d\'exercice non supporté.');
    }
  }
}

class _ChoiceTile extends StatelessWidget {
  const _ChoiceTile({
    required this.text,
    required this.selected,
    required this.onTap,
  });

  final String text;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return Material(
      color: selected ? AppColors.primary.withOpacity(0.1) : Colors.white,
      borderRadius: BorderRadius.circular(14),
      child: InkWell(
        borderRadius: BorderRadius.circular(14),
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(14),
            border: Border.all(
              color: selected ? AppColors.primary : const Color(0xFFE5E5E5),
              width: 2,
            ),
          ),
          child: Text(
            text,
            style: TextStyle(
              fontSize: 16,
              fontWeight: FontWeight.w700,
              color: selected ? AppColors.primaryDark : AppColors.textPrimary,
            ),
          ),
        ),
      ),
    );
  }
}

class _CodeBlock extends StatelessWidget {
  const _CodeBlock({required this.code});
  final String code;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: const Color(0xFF1E1E1E),
        borderRadius: BorderRadius.circular(12),
      ),
      child: SelectableText(
        code,
        style: const TextStyle(
          fontFamily: 'monospace',
          color: Color(0xFFEEEEEE),
          fontSize: 14,
          height: 1.4,
        ),
      ),
    );
  }
}
