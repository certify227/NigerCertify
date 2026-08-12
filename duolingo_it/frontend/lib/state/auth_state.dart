import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../api/api_client.dart';
import '../api/endpoints.dart';
import '../models/user.dart';

enum AuthStatus { unknown, unauthenticated, authenticated }

class AuthState extends ChangeNotifier {
  AuthState(this._client) : _authApi = AuthApi(_client);

  static const _kAccessKey = 'codelingo.access';
  static const _kRefreshKey = 'codelingo.refresh';

  final ApiClient _client;
  final AuthApi _authApi;

  AuthStatus _status = AuthStatus.unknown;
  AppUser? _user;
  String? _error;

  AuthStatus get status => _status;
  AppUser? get user => _user;
  String? get error => _error;
  ApiClient get client => _client;

  Future<void> bootstrap() async {
    final prefs = await SharedPreferences.getInstance();
    final access = prefs.getString(_kAccessKey);
    if (access == null || access.isEmpty) {
      _status = AuthStatus.unauthenticated;
      notifyListeners();
      return;
    }
    _client.setAccessToken(access);
    try {
      _user = await _authApi.me();
      _status = AuthStatus.authenticated;
    } catch (_) {
      _client.setAccessToken(null);
      await prefs.remove(_kAccessKey);
      await prefs.remove(_kRefreshKey);
      _status = AuthStatus.unauthenticated;
    }
    notifyListeners();
  }

  Future<bool> login(String username, String password) async {
    _error = null;
    try {
      final tokens = await _authApi.login(username: username, password: password);
      await _persistAndLoad(tokens['access'] as String, tokens['refresh'] as String?);
      return true;
    } on ApiException catch (e) {
      _error = e.statusCode == 401
          ? "Identifiants invalides"
          : "Erreur ${e.statusCode} : ${e.message}";
      notifyListeners();
      return false;
    } catch (e) {
      _error = "Impossible de se connecter au serveur ($e)";
      notifyListeners();
      return false;
    }
  }

  Future<bool> register({
    required String username,
    required String email,
    required String password,
    String firstName = '',
  }) async {
    _error = null;
    try {
      final data = await _authApi.register(
        username: username,
        email: email,
        password: password,
        firstName: firstName,
      );
      await _persistAndLoad(
        data['access'] as String,
        data['refresh'] as String?,
        prefetched: AppUser.fromJson(data['user'] as Map<String, dynamic>),
      );
      return true;
    } on ApiException catch (e) {
      final body = e.body;
      if (body != null) {
        _error = body.entries
            .map((entry) => '${entry.key} : ${entry.value}')
            .join('\n');
      } else {
        _error = e.message;
      }
      notifyListeners();
      return false;
    } catch (e) {
      _error = "Erreur inattendue ($e)";
      notifyListeners();
      return false;
    }
  }

  Future<void> _persistAndLoad(String access, String? refresh,
      {AppUser? prefetched}) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_kAccessKey, access);
    if (refresh != null) await prefs.setString(_kRefreshKey, refresh);
    _client.setAccessToken(access);
    _user = prefetched ?? await _authApi.me();
    _status = AuthStatus.authenticated;
    notifyListeners();
  }

  Future<void> logout() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_kAccessKey);
    await prefs.remove(_kRefreshKey);
    _client.setAccessToken(null);
    _user = null;
    _status = AuthStatus.unauthenticated;
    notifyListeners();
  }

  void updateUserFromJson(Map<String, dynamic>? json) {
    if (json == null) return;
    _user = AppUser.fromJson(json);
    notifyListeners();
  }

  Future<void> refreshUser() async {
    try {
      _user = await _authApi.me();
      notifyListeners();
    } catch (_) {}
  }
}
