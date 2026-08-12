import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

import '../config/api_config.dart';
import '../models/models.dart';

class ApiException implements Exception {
  final String message;
  final int? statusCode;
  ApiException(this.message, {this.statusCode});

  @override
  String toString() => message;
}

class ApiService {
  static const _tokenKey = 'access_token';
  static const _refreshKey = 'refresh_token';

  String? _accessToken;

  Future<void> loadTokens() async {
    final prefs = await SharedPreferences.getInstance();
    _accessToken = prefs.getString(_tokenKey);
  }

  Future<void> _saveTokens(String access, String refresh) async {
    _accessToken = access;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_tokenKey, access);
    await prefs.setString(_refreshKey, refresh);
  }

  Future<void> clearTokens() async {
    _accessToken = null;
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_tokenKey);
    await prefs.remove(_refreshKey);
  }

  bool get isLoggedIn => _accessToken != null;

  Map<String, String> get _headers => {
        'Content-Type': 'application/json',
        if (_accessToken != null) 'Authorization': 'Bearer $_accessToken',
      };

  Future<http.Response> _request(
    String method,
    String path, {
    Map<String, dynamic>? body,
  }) async {
    final uri = Uri.parse('${ApiConfig.baseUrl}$path');
    http.Response response;

    switch (method) {
      case 'GET':
        response = await http.get(uri, headers: _headers);
        break;
      case 'POST':
        response = await http.post(uri, headers: _headers, body: jsonEncode(body));
        break;
      case 'PATCH':
        response = await http.patch(uri, headers: _headers, body: jsonEncode(body));
        break;
      default:
        throw ApiException('Méthode HTTP non supportée');
    }

    if (response.statusCode == 401) {
      final refreshed = await _tryRefresh();
      if (refreshed) {
        return _request(method, path, body: body);
      }
    }

    return response;
  }

  Future<bool> _tryRefresh() async {
    final prefs = await SharedPreferences.getInstance();
    final refresh = prefs.getString(_refreshKey);
    if (refresh == null) return false;

    final uri = Uri.parse('${ApiConfig.baseUrl.replaceAll('/api', '')}/api/auth/token/refresh/');
    final response = await http.post(
      uri,
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'refresh': refresh}),
    );

    if (response.statusCode == 200) {
      final data = jsonDecode(response.body) as Map<String, dynamic>;
      await prefs.setString(_tokenKey, data['access'] as String);
      _accessToken = data['access'] as String;
      return true;
    }
    return false;
  }

  void _checkResponse(http.Response response) {
    if (response.statusCode >= 400) {
      Map<String, dynamic>? body;
      try {
        body = jsonDecode(response.body) as Map<String, dynamic>;
      } catch (_) {}
      final msg = body?['detail']?.toString() ??
          body?['error']?.toString() ??
          'Erreur serveur (${response.statusCode})';
      throw ApiException(msg, statusCode: response.statusCode);
    }
  }

  // --- Auth ---

  Future<void> login(String username, String password) async {
    final uri = Uri.parse('${ApiConfig.baseUrl.replaceAll('/api', '')}/api/auth/token/');
    final response = await http.post(
      uri,
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'username': username, 'password': password}),
    );
    _checkResponse(response);
    final data = jsonDecode(response.body) as Map<String, dynamic>;
    await _saveTokens(data['access'] as String, data['refresh'] as String);
  }

  Future<void> register(String username, String email, String password) async {
    final response = await _request('POST', '/accounts/register/', body: {
      'username': username,
      'email': email,
      'password': password,
      'password_confirm': password,
    });
    _checkResponse(response);
    await login(username, password);
  }

  Future<void> logout() => clearTokens();

  // --- Profile & Dashboard ---

  Future<UserProfile> getProfile() async {
    final response = await _request('GET', '/accounts/profile/');
    _checkResponse(response);
    return UserProfile.fromJson(jsonDecode(response.body) as Map<String, dynamic>);
  }

  Future<Dashboard> getDashboard() async {
    final response = await _request('GET', '/progress/dashboard/');
    _checkResponse(response);
    return Dashboard.fromJson(jsonDecode(response.body) as Map<String, dynamic>);
  }

  Future<void> refillHearts() async {
    final response = await _request('POST', '/accounts/hearts/refill/');
    _checkResponse(response);
  }

  // --- Courses ---

  Future<List<Track>> getTracks() async {
    final response = await _request('GET', '/courses/tracks/');
    _checkResponse(response);
    final data = jsonDecode(response.body);
    final results = data is List ? data : (data['results'] as List<dynamic>);
    return results.map((t) => Track.fromJson(t as Map<String, dynamic>)).toList();
  }

  Future<TrackDetail> getTrackDetail(String slug) async {
    final response = await _request('GET', '/courses/tracks/$slug/');
    _checkResponse(response);
    return TrackDetail.fromJson(jsonDecode(response.body) as Map<String, dynamic>);
  }

  Future<LessonDetail> getLesson(int id) async {
    final response = await _request('GET', '/courses/lessons/$id/');
    _checkResponse(response);
    return LessonDetail.fromJson(jsonDecode(response.body) as Map<String, dynamic>);
  }

  Future<SubmitResult> submitAnswer(int exerciseId, {int? choiceId, String? answer}) async {
    final body = <String, dynamic>{};
    if (choiceId != null) body['choice_id'] = choiceId;
    if (answer != null) body['answer'] = answer;

    final response = await _request('POST', '/courses/exercises/$exerciseId/submit/', body: body);
    if (response.statusCode == 403) {
      final data = jsonDecode(response.body) as Map<String, dynamic>;
      throw ApiException(data['error']?.toString() ?? 'Plus de cœurs');
    }
    _checkResponse(response);
    return SubmitResult.fromJson(jsonDecode(response.body) as Map<String, dynamic>);
  }

  Future<List<UserProfile>> getLeaderboard() async {
    final response = await _request('GET', '/accounts/leaderboard/');
    _checkResponse(response);
    final data = jsonDecode(response.body);
    final results = data is List ? data : (data['results'] as List<dynamic>);
    return results.map((u) => UserProfile.fromJson(u as Map<String, dynamic>)).toList();
  }
}
