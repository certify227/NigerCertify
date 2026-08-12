import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';

const apiBaseUrl = String.fromEnvironment(
  'API_BASE_URL',
  defaultValue: 'http://127.0.0.1:8000/api',
);

void main() {
  runApp(const ItQuestApp());
}

class ItQuestApp extends StatelessWidget {
  const ItQuestApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'IT Quest',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF36B37E)),
        useMaterial3: true,
      ),
      home: const HomePage(),
    );
  }
}

class ApiClient {
  ApiClient({this.baseUrl = apiBaseUrl});

  final String baseUrl;
  final HttpClient _client = HttpClient();

  Future<dynamic> getJson(String path) async {
    final request = await _client.getUrl(Uri.parse('$baseUrl$path'));
    final response = await request.close();
    return _decode(response);
  }

  Future<dynamic> postJson(String path, Map<String, dynamic> body) async {
    final request = await _client.postUrl(Uri.parse('$baseUrl$path'));
    request.headers.contentType = ContentType.json;
    request.write(jsonEncode(body));
    final response = await request.close();
    return _decode(response);
  }

  Future<dynamic> _decode(HttpClientResponse response) async {
    final body = await utf8.decodeStream(response);
    if (response.statusCode >= 400) {
      throw ApiException('Erreur API ${response.statusCode}: $body');
    }
    return body.isEmpty ? null : jsonDecode(body);
  }
}

class ApiException implements Exception {
  const ApiException(this.message);
  final String message;

  @override
  String toString() => message;
}

class Track {
  const Track({
    required this.id,
    required this.title,
    required this.description,
    required this.icon,
    required this.lessons,
  });

  final int id;
  final String title;
  final String description;
  final String icon;
  final List<LessonSummary> lessons;

  factory Track.fromJson(Map<String, dynamic> json) {
    return Track(
      id: json['id'] as int,
      title: json['title'] as String,
      description: json['description'] as String,
      icon: json['icon'] as String,
      lessons: (json['lessons'] as List<dynamic>? ?? [])
          .map((item) => LessonSummary.fromJson(item as Map<String, dynamic>))
          .toList(),
    );
  }
}

class LessonSummary {
  const LessonSummary({
    required this.id,
    required this.title,
    required this.summary,
    required this.xpReward,
  });

  final int id;
  final String title;
  final String summary;
  final int xpReward;

  factory LessonSummary.fromJson(Map<String, dynamic> json) {
    return LessonSummary(
      id: json['id'] as int,
      title: json['title'] as String,
      summary: json['summary'] as String,
      xpReward: json['xp_reward'] as int,
    );
  }
}

class LessonDetail {
  const LessonDetail({
    required this.id,
    required this.track,
    required this.title,
    required this.summary,
    required this.xpReward,
    required this.questions,
  });

  final int id;
  final String track;
  final String title;
  final String summary;
  final int xpReward;
  final List<Question> questions;

  factory LessonDetail.fromJson(Map<String, dynamic> json) {
    return LessonDetail(
      id: json['id'] as int,
      track: json['track'] as String,
      title: json['title'] as String,
      summary: json['summary'] as String,
      xpReward: json['xp_reward'] as int,
      questions: (json['questions'] as List<dynamic>? ?? [])
          .map((item) => Question.fromJson(item as Map<String, dynamic>))
          .toList(),
    );
  }
}

class Question {
  const Question({
    required this.id,
    required this.prompt,
    required this.explanation,
    required this.options,
  });

  final int id;
  final String prompt;
  final String explanation;
  final List<AnswerOption> options;

  factory Question.fromJson(Map<String, dynamic> json) {
    return Question(
      id: json['id'] as int,
      prompt: json['prompt'] as String,
      explanation: json['explanation'] as String,
      options: (json['options'] as List<dynamic>? ?? [])
          .map((item) => AnswerOption.fromJson(item as Map<String, dynamic>))
          .toList(),
    );
  }
}

class AnswerOption {
  const AnswerOption({required this.id, required this.text});

  final int id;
  final String text;

  factory AnswerOption.fromJson(Map<String, dynamic> json) {
    return AnswerOption(
      id: json['id'] as int,
      text: json['text'] as String,
    );
  }
}

class SubmitResult {
  const SubmitResult({
    required this.score,
    required this.maxScore,
    required this.xp,
    required this.totalXp,
    required this.feedback,
  });

  final int score;
  final int maxScore;
  final int xp;
  final int totalXp;
  final List<QuestionFeedback> feedback;

  factory SubmitResult.fromJson(Map<String, dynamic> json) {
    final progress = json['progress'] as Map<String, dynamic>;
    return SubmitResult(
      score: progress['score'] as int,
      maxScore: progress['max_score'] as int,
      xp: progress['xp'] as int,
      totalXp: json['total_xp'] as int,
      feedback: (json['feedback'] as List<dynamic>? ?? [])
          .map((item) => QuestionFeedback.fromJson(item as Map<String, dynamic>))
          .toList(),
    );
  }
}

class QuestionFeedback {
  const QuestionFeedback({
    required this.questionId,
    required this.isCorrect,
    required this.explanation,
  });

  final int questionId;
  final bool isCorrect;
  final String explanation;

  factory QuestionFeedback.fromJson(Map<String, dynamic> json) {
    return QuestionFeedback(
      questionId: json['question_id'] as int,
      isCorrect: json['is_correct'] as bool,
      explanation: json['explanation'] as String,
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final ApiClient _apiClient = ApiClient();
  final TextEditingController _usernameController =
      TextEditingController(text: 'amina');
  late Future<List<Track>> _tracksFuture;
  LessonDetail? _activeLesson;

  @override
  void initState() {
    super.initState();
    _tracksFuture = _loadTracks();
  }

  @override
  void dispose() {
    _usernameController.dispose();
    super.dispose();
  }

  Future<List<Track>> _loadTracks() async {
    final json = await _apiClient.getJson('/tracks/') as List<dynamic>;
    return json.map((item) => Track.fromJson(item as Map<String, dynamic>)).toList();
  }

  Future<void> _openLesson(int lessonId) async {
    final json = await _apiClient.getJson('/lessons/$lessonId/') as Map<String, dynamic>;
    setState(() {
      _activeLesson = LessonDetail.fromJson(json);
    });
  }

  @override
  Widget build(BuildContext context) {
    final activeLesson = _activeLesson;
    if (activeLesson != null) {
      return LessonRunner(
        apiClient: _apiClient,
        lesson: activeLesson,
        username: _usernameController.text.trim().isEmpty
            ? 'apprenant'
            : _usernameController.text.trim(),
        onExit: () => setState(() => _activeLesson = null),
      );
    }

    return Scaffold(
      appBar: AppBar(title: const Text('IT Quest')),
      body: FutureBuilder<List<Track>>(
        future: _tracksFuture,
        builder: (context, snapshot) {
          if (snapshot.connectionState == ConnectionState.waiting) {
            return const Center(child: CircularProgressIndicator());
          }
          if (snapshot.hasError) {
            return _ErrorState(
              message: snapshot.error.toString(),
              onRetry: () => setState(() => _tracksFuture = _loadTracks()),
            );
          }

          final tracks = snapshot.data ?? [];
          return ListView(
            padding: const EdgeInsets.all(20),
            children: [
              Text(
                "Apprends l'informatique par petites missions.",
                style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                      fontWeight: FontWeight.bold,
                    ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _usernameController,
                decoration: const InputDecoration(
                  labelText: 'Nom utilisateur',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 20),
              for (final track in tracks) _TrackCard(track: track, onOpen: _openLesson),
            ],
          );
        },
      ),
    );
  }
}

class _TrackCard extends StatelessWidget {
  const _TrackCard({required this.track, required this.onOpen});

  final Track track;
  final ValueChanged<int> onOpen;

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.only(bottom: 18),
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                CircleAvatar(
                  child: Text(track.icon.isEmpty ? '?' : track.icon[0].toUpperCase()),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    track.title,
                    style: Theme.of(context).textTheme.titleLarge,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Text(track.description),
            const SizedBox(height: 12),
            for (final lesson in track.lessons)
              ListTile(
                contentPadding: EdgeInsets.zero,
                title: Text(lesson.title),
                subtitle: Text('${lesson.summary} - ${lesson.xpReward} XP'),
                trailing: const Icon(Icons.chevron_right),
                onTap: () => onOpen(lesson.id),
              ),
          ],
        ),
      ),
    );
  }
}

class LessonRunner extends StatefulWidget {
  const LessonRunner({
    required this.apiClient,
    required this.lesson,
    required this.username,
    required this.onExit,
    super.key,
  });

  final ApiClient apiClient;
  final LessonDetail lesson;
  final String username;
  final VoidCallback onExit;

  @override
  State<LessonRunner> createState() => _LessonRunnerState();
}

class _LessonRunnerState extends State<LessonRunner> {
  int _questionIndex = 0;
  bool _submitting = false;
  String? _error;
  SubmitResult? _result;
  final Map<int, int> _answers = {};

  Future<void> _nextOrSubmit() async {
    if (_questionIndex < widget.lesson.questions.length - 1) {
      setState(() => _questionIndex += 1);
      return;
    }

    setState(() {
      _submitting = true;
      _error = null;
    });
    try {
      final json = await widget.apiClient.postJson(
        '/lessons/${widget.lesson.id}/submit/',
        {
          'username': widget.username,
          'answers': _answers.entries
              .map((entry) => {
                    'question_id': entry.key,
                    'option_id': entry.value,
                  })
              .toList(),
        },
      ) as Map<String, dynamic>;
      setState(() => _result = SubmitResult.fromJson(json));
    } catch (error) {
      setState(() => _error = error.toString());
    } finally {
      setState(() => _submitting = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final result = _result;
    if (result != null) {
      return _ResultScreen(result: result, onExit: widget.onExit);
    }
    if (widget.lesson.questions.isEmpty) {
      return Scaffold(
        appBar: AppBar(title: Text(widget.lesson.title)),
        body: const Center(child: Text('Cette leçon ne contient pas encore de question.')),
      );
    }

    final question = widget.lesson.questions[_questionIndex];
    final selectedOptionId = _answers[question.id];
    final canContinue = selectedOptionId != null && !_submitting;

    return Scaffold(
      appBar: AppBar(
        title: Text(widget.lesson.title),
        leading: IconButton(
          icon: const Icon(Icons.close),
          onPressed: widget.onExit,
        ),
      ),
      body: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            LinearProgressIndicator(
              value: (_questionIndex + 1) / widget.lesson.questions.length,
              minHeight: 10,
              borderRadius: BorderRadius.circular(99),
            ),
            const SizedBox(height: 24),
            Text(
              widget.lesson.track,
              style: Theme.of(context).textTheme.labelLarge,
            ),
            const SizedBox(height: 6),
            Text(
              question.prompt,
              style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                    fontWeight: FontWeight.bold,
                  ),
            ),
            const SizedBox(height: 24),
            for (final option in question.options)
              Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: OutlinedButton(
                  style: OutlinedButton.styleFrom(
                    alignment: Alignment.centerLeft,
                    backgroundColor: selectedOptionId == option.id
                        ? Theme.of(context).colorScheme.primaryContainer
                        : null,
                    padding: const EdgeInsets.all(18),
                  ),
                  onPressed: () {
                    setState(() => _answers[question.id] = option.id);
                  },
                  child: Text(option.text),
                ),
              ),
            const Spacer(),
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: Text(
                  _error!,
                  style: TextStyle(color: Theme.of(context).colorScheme.error),
                ),
              ),
            FilledButton(
              onPressed: canContinue ? _nextOrSubmit : null,
              child: Text(
                _submitting
                    ? 'Correction...'
                    : _questionIndex == widget.lesson.questions.length - 1
                        ? 'Terminer'
                        : 'Continuer',
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _ResultScreen extends StatelessWidget {
  const _ResultScreen({required this.result, required this.onExit});

  final SubmitResult result;
  final VoidCallback onExit;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Résultat')),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Icon(
              result.score == result.maxScore ? Icons.emoji_events : Icons.school,
              size: 84,
              color: Theme.of(context).colorScheme.primary,
            ),
            const SizedBox(height: 16),
            Text(
              '${result.score}/${result.maxScore} bonnes réponses',
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                    fontWeight: FontWeight.bold,
                  ),
            ),
            const SizedBox(height: 8),
            Text(
              '+${result.xp} XP cette leçon - ${result.totalXp} XP au total',
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 24),
            Expanded(
              child: ListView(
                children: [
                  for (final item in result.feedback)
                    ListTile(
                      leading: Icon(
                        item.isCorrect ? Icons.check_circle : Icons.cancel,
                        color: item.isCorrect ? Colors.green : Colors.red,
                      ),
                      title: Text(item.isCorrect ? 'Correct' : 'A revoir'),
                      subtitle: Text(item.explanation),
                    ),
                ],
              ),
            ),
            FilledButton(
              onPressed: onExit,
              child: const Text('Retour aux parcours'),
            ),
          ],
        ),
      ),
    );
  }
}

class _ErrorState extends StatelessWidget {
  const _ErrorState({required this.message, required this.onRetry});

  final String message;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.cloud_off, size: 56),
            const SizedBox(height: 16),
            Text(
              'Impossible de joindre le backend.',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(message, textAlign: TextAlign.center),
            const SizedBox(height: 16),
            FilledButton(onPressed: onRetry, child: const Text('Réessayer')),
          ],
        ),
      ),
    );
  }
}
