import 'dart:convert';

import 'package:http/http.dart' as http;

import 'models.dart';

class ItLingoApi {
  ItLingoApi({
    http.Client? httpClient,
    this.baseUrl = const String.fromEnvironment(
      'API_BASE_URL',
      defaultValue: 'http://127.0.0.1:8000/api',
    ),
  }) : _httpClient = httpClient ?? http.Client();

  final String baseUrl;
  final http.Client _httpClient;

  Future<List<Track>> fetchTracks() async {
    final response = await _httpClient.get(Uri.parse('$baseUrl/tracks/'));
    _ensureSuccess(response);
    final payload = jsonDecode(utf8.decode(response.bodyBytes)) as List<dynamic>;
    return payload.map((item) => Track.fromJson(item as Map<String, dynamic>)).toList();
  }

  Future<LessonDetail> fetchLesson(int lessonId) async {
    final response = await _httpClient.get(Uri.parse('$baseUrl/lessons/$lessonId/'));
    _ensureSuccess(response);
    return LessonDetail.fromJson(jsonDecode(utf8.decode(response.bodyBytes)) as Map<String, dynamic>);
  }

  Future<AttemptResult> submitAnswer(int challengeId, dynamic answer) async {
    final response = await _httpClient.post(
      Uri.parse('$baseUrl/challenges/$challengeId/submit/'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'answer': answer}),
    );
    _ensureSuccess(response);
    return AttemptResult.fromJson(jsonDecode(utf8.decode(response.bodyBytes)) as Map<String, dynamic>);
  }

  void close() => _httpClient.close();

  void _ensureSuccess(http.Response response) {
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw ApiException('Erreur API ${response.statusCode}: ${response.body}');
    }
  }
}

class ApiException implements Exception {
  const ApiException(this.message);

  final String message;

  @override
  String toString() => message;
}
