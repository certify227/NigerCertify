import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

import '../config/api_config.dart';
import '../models/models.dart';
import 'cache_service.dart';
import 'connectivity_service.dart';
import 'offline_queue_service.dart';

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

  final CacheService cache = CacheService();
  final ConnectivityService connectivity = ConnectivityService();
  final OfflineQueueService offlineQueue = OfflineQueueService();

  String? _accessToken;
  bool isOffline = false;

  Future<void> loadTokens() async {
    final prefs = await SharedPreferences.getInstance();
    _accessToken = prefs.getString(_tokenKey);
    isOffline = !(await connectivity.isOnline);
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
    await cache.clear();
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

  Future<void> checkConnectivity() async {
    isOffline = !(await connectivity.isOnline);
  }

  Future<void> syncOfflineQueue() async {
    if (!await connectivity.isOnline) return;
    final queue = await offlineQueue.getQueue();
    for (var i = 0; i < queue.length; i++) {
      final item = queue[i];
      try {
        await submitAnswer(
          item['exercise_id'] as int,
          choiceId: item['choice_id'] as int?,
          answer: item['answer'] as String?,
          code: item['code'] as String?,
          skipQueue: true,
        );
        await offlineQueue.removeAt(0);
      } catch (_) {
        break;
      }
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
    await syncOfflineQueue();
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
    if (await connectivity.isOnline) {
      final response = await _request('GET', '/accounts/profile/');
      _checkResponse(response);
      final data = jsonDecode(response.body) as Map<String, dynamic>;
      await cache.save('profile', data);
      return UserProfile.fromJson(data);
    }
    final cached = await cache.load('profile');
    if (cached != null) return UserProfile.fromJson(cached as Map<String, dynamic>);
    throw ApiException('Hors ligne — profil non disponible');
  }

  Future<Dashboard> getDashboard() async {
    if (await connectivity.isOnline) {
      final response = await _request('GET', '/progress/dashboard/');
      _checkResponse(response);
      final data = jsonDecode(response.body) as Map<String, dynamic>;
      await cache.save('dashboard', data);
      return Dashboard.fromJson(data);
    }
    final cached = await cache.load('dashboard');
    if (cached != null) return Dashboard.fromJson(cached as Map<String, dynamic>);
    throw ApiException('Hors ligne — tableau de bord non disponible');
  }

  Future<UserProfile> updateReminders({required bool enabled, required int hour}) async {
    final response = await _request('PATCH', '/accounts/reminders/', body: {
      'reminder_enabled': enabled,
      'reminder_hour': hour,
    });
    _checkResponse(response);
    return UserProfile.fromJson(jsonDecode(response.body) as Map<String, dynamic>);
  }

  Future<void> refillHearts() async {
    final response = await _request('POST', '/accounts/hearts/refill/');
    _checkResponse(response);
  }

  // --- Courses ---

  Future<List<Track>> getTracks() async {
    if (await connectivity.isOnline) {
      final response = await _request('GET', '/courses/tracks/');
      _checkResponse(response);
      final data = jsonDecode(response.body);
      final results = data is List ? data : (data['results'] as List<dynamic>);
      await cache.save('tracks', results);
      return results.map((t) => Track.fromJson(t as Map<String, dynamic>)).toList();
    }
    final cached = await cache.load('tracks') as List<dynamic>?;
    if (cached != null) {
      return cached.map((t) => Track.fromJson(t as Map<String, dynamic>)).toList();
    }
    throw ApiException('Hors ligne — parcours non disponibles');
  }

  Future<TrackDetail> getTrackDetail(String slug) async {
    final cacheKey = 'track_$slug';
    if (await connectivity.isOnline) {
      final response = await _request('GET', '/courses/tracks/$slug/');
      _checkResponse(response);
      final data = jsonDecode(response.body) as Map<String, dynamic>;
      await cache.save(cacheKey, data);
      return TrackDetail.fromJson(data);
    }
    final cached = await cache.load(cacheKey) as Map<String, dynamic>?;
    if (cached != null) return TrackDetail.fromJson(cached);
    throw ApiException('Hors ligne — parcours non disponible');
  }

  Future<LessonDetail> getLesson(int id) async {
    final cacheKey = 'lesson_$id';
    if (await connectivity.isOnline) {
      final response = await _request('GET', '/courses/lessons/$id/');
      _checkResponse(response);
      final data = jsonDecode(response.body) as Map<String, dynamic>;
      await cache.save(cacheKey, data);
      return LessonDetail.fromJson(data);
    }
    final cached = await cache.load(cacheKey) as Map<String, dynamic>?;
    if (cached != null) return LessonDetail.fromJson(cached);
    throw ApiException('Hors ligne — leçon non disponible');
  }

  Future<RunCodeResult> runCode(String code, {String stdin = ''}) async {
    final response = await _request('POST', '/courses/sandbox/run/', body: {
      'code': code,
      'stdin': stdin,
    });
    if (response.statusCode == 400) {
      final data = jsonDecode(response.body) as Map<String, dynamic>;
      throw ApiException(data['error']?.toString() ?? 'Erreur sandbox');
    }
    _checkResponse(response);
    return RunCodeResult.fromJson(jsonDecode(response.body) as Map<String, dynamic>);
  }

  Future<SubmitResult> submitAnswer(
    int exerciseId, {
    int? choiceId,
    String? answer,
    String? code,
    bool skipQueue = false,
  }) async {
    final body = <String, dynamic>{};
    if (choiceId != null) body['choice_id'] = choiceId;
    if (answer != null) body['answer'] = answer;
    if (code != null) body['code'] = code;

    if (!skipQueue && !(await connectivity.isOnline)) {
      await offlineQueue.enqueue({
        'exercise_id': exerciseId,
        'choice_id': choiceId,
        'answer': answer,
        'code': code,
      });
      return SubmitResult(
        correct: true,
        explanation: 'Réponse enregistrée hors ligne. Synchronisation à la reconnexion.',
      );
    }

    final response = await _request('POST', '/courses/exercises/$exerciseId/submit/', body: body);
    if (response.statusCode == 403) {
      final data = jsonDecode(response.body) as Map<String, dynamic>;
      throw ApiException(data['error']?.toString() ?? 'Plus de cœurs');
    }
    _checkResponse(response);
    return SubmitResult.fromJson(jsonDecode(response.body) as Map<String, dynamic>);
  }

  Future<List<UserProfile>> getLeaderboard() async {
    if (!await connectivity.isOnline) {
      final cached = await cache.load('leaderboard') as List<dynamic>?;
      if (cached != null) {
        return cached.map((u) => UserProfile.fromJson(u as Map<String, dynamic>)).toList();
      }
      throw ApiException('Hors ligne — classement non disponible');
    }
    final response = await _request('GET', '/accounts/leaderboard/');
    _checkResponse(response);
    final data = jsonDecode(response.body);
    final results = data is List ? data : (data['results'] as List<dynamic>);
    await cache.save('leaderboard', results);
    return results.map((u) => UserProfile.fromJson(u as Map<String, dynamic>)).toList();
  }
}
