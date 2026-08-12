import 'dart:convert';
import 'dart:io' show Platform;

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

import '../models.dart';

/// Thin client around the CodeLingo Django REST API.
class ApiService {
  ApiService._();
  static final ApiService instance = ApiService._();

  static const String _accessKey = 'access_token';
  static const String _refreshKey = 'refresh_token';

  String? _accessToken;
  String? _refreshToken;

  /// Resolve the API base URL depending on the platform.
  ///
  /// Android emulators reach the host machine through 10.0.2.2, whereas
  /// desktop/web use localhost. Override with --dart-define=API_BASE_URL=...
  static String get baseUrl {
    const override = String.fromEnvironment('API_BASE_URL');
    if (override.isNotEmpty) return override;
    if (!kIsWeb && Platform.isAndroid) {
      return 'http://10.0.2.2:8000';
    }
    return 'http://127.0.0.1:8000';
  }

  Future<void> loadTokens() async {
    final prefs = await SharedPreferences.getInstance();
    _accessToken = prefs.getString(_accessKey);
    _refreshToken = prefs.getString(_refreshKey);
  }

  bool get isAuthenticated => _accessToken != null;

  Future<void> _saveTokens(String access, String refresh) async {
    _accessToken = access;
    _refreshToken = refresh;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_accessKey, access);
    await prefs.setString(_refreshKey, refresh);
  }

  Future<void> logout() async {
    _accessToken = null;
    _refreshToken = null;
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_accessKey);
    await prefs.remove(_refreshKey);
  }

  Map<String, String> get _headers => {
        'Content-Type': 'application/json',
        if (_accessToken != null) 'Authorization': 'Bearer $_accessToken',
      };

  Uri _uri(String path) => Uri.parse('$baseUrl$path');

  Future<http.Response> _get(String path) async {
    var resp = await http.get(_uri(path), headers: _headers);
    if (resp.statusCode == 401 && await _refresh()) {
      resp = await http.get(_uri(path), headers: _headers);
    }
    return resp;
  }

  Future<http.Response> _post(String path, Object body,
      {bool auth = true}) async {
    var resp = await http.post(_uri(path),
        headers: _headers, body: jsonEncode(body));
    if (auth && resp.statusCode == 401 && await _refresh()) {
      resp = await http.post(_uri(path),
          headers: _headers, body: jsonEncode(body));
    }
    return resp;
  }

  Future<bool> _refresh() async {
    if (_refreshToken == null) return false;
    final resp = await http.post(
      _uri('/api/auth/refresh/'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'refresh': _refreshToken}),
    );
    if (resp.statusCode == 200) {
      final data = jsonDecode(resp.body);
      _accessToken = data['access'];
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(_accessKey, _accessToken!);
      return true;
    }
    await logout();
    return false;
  }

  // --- Auth -----------------------------------------------------------------

  Future<void> login(String username, String password) async {
    final resp = await _post(
      '/api/auth/login/',
      {'username': username, 'password': password},
      auth: false,
    );
    if (resp.statusCode != 200) {
      throw ApiException('Identifiants invalides', resp.statusCode);
    }
    final data = jsonDecode(resp.body);
    await _saveTokens(data['access'], data['refresh']);
  }

  Future<void> register(String username, String email, String password) async {
    final resp = await _post(
      '/api/auth/register/',
      {'username': username, 'email': email, 'password': password},
      auth: false,
    );
    if (resp.statusCode != 201) {
      throw ApiException(_firstError(resp.body), resp.statusCode);
    }
    await login(username, password);
  }

  Future<AppUser> fetchMe() async {
    final resp = await _get('/api/auth/me/');
    if (resp.statusCode != 200) {
      throw ApiException('Impossible de charger le profil', resp.statusCode);
    }
    return AppUser.fromJson(jsonDecode(utf8.decode(resp.bodyBytes)));
  }

  // --- Learning -------------------------------------------------------------

  Future<List<Course>> fetchCourses() async {
    final resp = await _get('/api/courses/');
    if (resp.statusCode != 200) {
      throw ApiException('Impossible de charger les cours', resp.statusCode);
    }
    final list = jsonDecode(utf8.decode(resp.bodyBytes)) as List;
    return list.map((e) => Course.fromJson(e)).toList();
  }

  Future<CourseDetail> fetchCourse(String slug) async {
    final resp = await _get('/api/courses/$slug/');
    if (resp.statusCode != 200) {
      throw ApiException('Impossible de charger le cours', resp.statusCode);
    }
    return CourseDetail.fromJson(jsonDecode(utf8.decode(resp.bodyBytes)));
  }

  Future<List<Exercise>> fetchLessonExercises(int lessonId) async {
    final resp = await _get('/api/lessons/$lessonId/');
    if (resp.statusCode != 200) {
      throw ApiException('Impossible de charger la leçon', resp.statusCode);
    }
    final data = jsonDecode(utf8.decode(resp.bodyBytes));
    return (data['exercises'] as List)
        .map((e) => Exercise.fromJson(e))
        .toList();
  }

  Future<LessonResult> completeLesson(
      int lessonId, Map<int, String> answers) async {
    final payload = {
      'answers': answers.entries
          .map((e) => {'exercise_id': e.key, 'answer': e.value})
          .toList(),
    };
    final resp = await _post('/api/lessons/$lessonId/complete/', payload);
    if (resp.statusCode != 200) {
      throw ApiException('Erreur lors de la validation', resp.statusCode);
    }
    return LessonResult.fromJson(jsonDecode(utf8.decode(resp.bodyBytes)));
  }

  Future<List<LeaderboardEntry>> fetchLeaderboard() async {
    final resp = await _get('/api/leaderboard/');
    if (resp.statusCode != 200) {
      throw ApiException('Impossible de charger le classement', resp.statusCode);
    }
    final list = jsonDecode(utf8.decode(resp.bodyBytes)) as List;
    return list.map((e) => LeaderboardEntry.fromJson(e)).toList();
  }

  String _firstError(String body) {
    try {
      final data = jsonDecode(body) as Map<String, dynamic>;
      final firstValue = data.values.first;
      if (firstValue is List && firstValue.isNotEmpty) return '$firstValue'.replaceAll(RegExp(r'[\[\]]'), '');
      return '$firstValue';
    } catch (_) {
      return 'Une erreur est survenue';
    }
  }
}

class ApiException implements Exception {
  final String message;
  final int statusCode;
  ApiException(this.message, this.statusCode);
  @override
  String toString() => message;
}
