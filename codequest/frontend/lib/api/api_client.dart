import 'dart:convert';

import 'package:http/http.dart' as http;

import '../config.dart';
import '../models/models.dart';

/// Thrown when the API returns a non-2xx response.
class ApiException implements Exception {
  final int statusCode;
  final String message;
  ApiException(this.statusCode, this.message);

  @override
  String toString() => message;
}

/// Thin wrapper around the CodeQuest REST API.
class ApiClient {
  ApiClient({http.Client? client}) : _client = client ?? http.Client();

  final http.Client _client;
  String? _token;

  void setToken(String? token) => _token = token;

  Map<String, String> _headers() => {
        'Content-Type': 'application/json',
        if (_token != null) 'Authorization': 'Token $_token',
      };

  Uri _uri(String path) => Uri.parse('${AppConfig.apiRoot}$path');

  dynamic _decode(http.Response resp) {
    final body = resp.body.isEmpty ? null : jsonDecode(resp.body);
    if (resp.statusCode >= 200 && resp.statusCode < 300) {
      return body;
    }
    String message = 'Erreur ${resp.statusCode}';
    if (body is Map) {
      if (body['detail'] != null) {
        message = body['detail'].toString();
      } else {
        message = body.values.map((v) => v is List ? v.join(' ') : v).join('\n');
      }
    }
    throw ApiException(resp.statusCode, message);
  }

  // --- Auth ---------------------------------------------------------------

  Future<({String token, Profile profile})> register(
      String username, String email, String password) async {
    final resp = await _client.post(
      _uri('/auth/register/'),
      headers: _headers(),
      body: jsonEncode({
        'username': username,
        'email': email,
        'password': password,
      }),
    );
    final data = _decode(resp) as Map<String, dynamic>;
    return (
      token: data['token'] as String,
      profile: Profile.fromJson(data['profile'] as Map<String, dynamic>),
    );
  }

  Future<({String token, Profile profile})> login(
      String username, String password) async {
    final resp = await _client.post(
      _uri('/auth/login/'),
      headers: _headers(),
      body: jsonEncode({'username': username, 'password': password}),
    );
    final data = _decode(resp) as Map<String, dynamic>;
    return (
      token: data['token'] as String,
      profile: Profile.fromJson(data['profile'] as Map<String, dynamic>),
    );
  }

  Future<Profile> me() async {
    final resp = await _client.get(_uri('/me/'), headers: _headers());
    return Profile.fromJson(_decode(resp) as Map<String, dynamic>);
  }

  // --- Content ------------------------------------------------------------

  Future<List<Course>> courses() async {
    final resp = await _client.get(_uri('/courses/'), headers: _headers());
    final data = _decode(resp) as List<dynamic>;
    return data
        .map((e) => Course.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  Future<CourseDetail> courseDetail(String slug) async {
    final resp =
        await _client.get(_uri('/courses/$slug/'), headers: _headers());
    return CourseDetail.fromJson(_decode(resp) as Map<String, dynamic>);
  }

  Future<Lesson> lesson(int id) async {
    final resp = await _client.get(_uri('/lessons/$id/'), headers: _headers());
    return Lesson.fromJson(_decode(resp) as Map<String, dynamic>);
  }

  Future<SubmissionResult> submitLesson(
      int lessonId, Map<int, String> answers) async {
    final payload = {
      'answers': answers.map((k, v) => MapEntry(k.toString(), v)),
    };
    final resp = await _client.post(
      _uri('/lessons/$lessonId/submit/'),
      headers: _headers(),
      body: jsonEncode(payload),
    );
    return SubmissionResult.fromJson(_decode(resp) as Map<String, dynamic>);
  }

  Future<List<LeaderboardEntry>> leaderboard() async {
    final resp = await _client.get(_uri('/leaderboard/'), headers: _headers());
    final data = _decode(resp) as List<dynamic>;
    return data
        .map((e) => LeaderboardEntry.fromJson(e as Map<String, dynamic>))
        .toList();
  }
}
