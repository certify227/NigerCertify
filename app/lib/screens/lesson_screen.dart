import 'package:flutter/material.dart';

import '../api_client.dart';
import '../models.dart';
import '../widgets/duo_card.dart';

class LessonScreen extends StatefulWidget {
  const LessonScreen({super.key, required this.api, required this.lesson});

  final ItLingoApi api;
  final LessonSummary lesson;

  @override
  State<LessonScreen> createState() => _LessonScreenState();
}

class _LessonScreenState extends State<LessonScreen> {
  late Future<LessonDetail> _detail;
  int _index = 0;
  dynamic _answer;
  AttemptResult? _result;
  bool _submitting = false;
  int _sessionXp = 0;

  @override
  void initState() {
    super.initState();
    _detail = widget.api.fetchLesson(widget.lesson.id);
  }

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<LessonDetail>(
      future: _detail,
      builder: (context, snapshot) {
        if (snapshot.connectionState != ConnectionState.done) {
          return const Scaffold(body: Center(child: CircularProgressIndicator()));
        }
        if (snapshot.hasError) {
          return Scaffold(
            appBar: AppBar(title: Text(widget.lesson.title)),
            body: Center(child: Text(snapshot.error.toString())),
          );
        }
        final detail = snapshot.data!;
        if (_index >= detail.challenges.length) {
          return _LessonDone(title: detail.title, xp: _sessionXp);
        }
        final challenge = detail.challenges[_index];
        return Scaffold(
          appBar: AppBar(
            title: Text(detail.title),
            bottom: PreferredSize(
              preferredSize: const Size.fromHeight(8),
              child: LinearProgressIndicator(value: (_index + 1) / detail.challenges.length),
            ),
          ),
          body: ListView(
            padding: const EdgeInsets.all(20),
            children: [
              Text('Défi ${_index + 1}/${detail.challenges.length}', style: Theme.of(context).textTheme.labelLarge),
              const SizedBox(height: 12),
              Text(challenge.prompt, style: Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w900)),
              const SizedBox(height: 24),
              _AnswerChoices(
                challenge: challenge,
                answer: _answer,
                onChanged: _result == null ? (value) => setState(() => _answer = value) : null,
              ),
              const SizedBox(height: 20),
              if (_result != null) _FeedbackCard(result: _result!),
              const SizedBox(height: 20),
              FilledButton(
                onPressed: _canSubmit ? () => _submit(challenge) : null,
                child: Text(_result == null ? 'Valider' : 'Continuer'),
              ),
            ],
          ),
        );
      },
    );
  }

  bool get _canSubmit => !_submitting && (_result != null || _answer != null);

  Future<void> _submit(Challenge challenge) async {
    if (_result != null) {
      setState(() {
        _index += 1;
        _answer = null;
        _result = null;
      });
      return;
    }

    setState(() => _submitting = true);
    try {
      final result = await widget.api.submitAnswer(challenge.id, _answer);
      setState(() {
        _result = result;
        _sessionXp += result.earnedXp;
      });
    } finally {
      if (mounted) {
        setState(() => _submitting = false);
      }
    }
  }
}

class _AnswerChoices extends StatelessWidget {
  const _AnswerChoices({
    required this.challenge,
    required this.answer,
    required this.onChanged,
  });

  final Challenge challenge;
  final dynamic answer;
  final ValueChanged<dynamic>? onChanged;

  @override
  Widget build(BuildContext context) {
    if (challenge.type == 'code_order') {
      final selected = (answer as List<dynamic>?)?.cast<String>() ?? <String>[];
      return Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              for (final line in selected)
                Chip(
                  label: Text(line),
                  onDeleted: onChanged == null
                      ? null
                      : () {
                          final next = List<String>.from(selected)..remove(line);
                          onChanged!(next.isEmpty ? null : next);
                        },
                ),
            ],
          ),
          const SizedBox(height: 16),
          for (final choice in challenge.choices.cast<String>())
            Padding(
              padding: const EdgeInsets.only(bottom: 10),
              child: OutlinedButton(
                onPressed: onChanged == null || selected.contains(choice)
                    ? null
                    : () => onChanged!([...selected, choice]),
                child: Align(alignment: Alignment.centerLeft, child: Text(choice)),
              ),
            ),
        ],
      );
    }

    return Column(
      children: [
        for (final choice in challenge.choices)
          Padding(
            padding: const EdgeInsets.only(bottom: 10),
            child: _ChoiceButton(
              label: choice.toString(),
              selected: answer == choice,
              onTap: onChanged == null ? null : () => onChanged!(choice),
            ),
          ),
      ],
    );
  }
}

class _ChoiceButton extends StatelessWidget {
  const _ChoiceButton({required this.label, required this.selected, required this.onTap});

  final String label;
  final bool selected;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: double.infinity,
      child: OutlinedButton(
        onPressed: onTap,
        style: OutlinedButton.styleFrom(
          alignment: Alignment.centerLeft,
          backgroundColor: selected ? Theme.of(context).colorScheme.primaryContainer : null,
          padding: const EdgeInsets.all(18),
        ),
        child: Text(label),
      ),
    );
  }
}

class _FeedbackCard extends StatelessWidget {
  const _FeedbackCard({required this.result});

  final AttemptResult result;

  @override
  Widget build(BuildContext context) {
    final color = result.isCorrect ? const Color(0xff58cc02) : Theme.of(context).colorScheme.error;
    return DuoCard(
      color: color.withOpacity(0.12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            result.isCorrect ? 'Correct !' : 'À revoir',
            style: Theme.of(context).textTheme.titleLarge?.copyWith(color: color, fontWeight: FontWeight.w900),
          ),
          const SizedBox(height: 8),
          Text(result.explanation),
          if (result.earnedXp > 0) ...[
            const SizedBox(height: 12),
            XpPill(xp: result.earnedXp),
          ],
        ],
      ),
    );
  }
}

class _LessonDone extends StatelessWidget {
  const _LessonDone({required this.title, required this.xp});

  final String title;
  final int xp;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(title)),
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: DuoCard(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.emoji_events, size: 64, color: Color(0xffffc800)),
                const SizedBox(height: 16),
                Text('Leçon terminée', style: Theme.of(context).textTheme.headlineSmall),
                const SizedBox(height: 8),
                Text('Tu as gagné $xp XP pendant cette session.'),
                const SizedBox(height: 20),
                FilledButton(
                  onPressed: () => Navigator.of(context).pop(),
                  child: const Text('Retour au parcours'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
