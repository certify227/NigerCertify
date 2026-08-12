import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../api/api_client.dart';
import '../models/models.dart';

/// Holds authentication state and the current user's gamification profile.
class AppState extends ChangeNotifier {
  AppState({ApiClient? api}) : api = api ?? ApiClient();

  final ApiClient api;

  static const _tokenKey = 'codequest_token';

  String? _token;
  Profile? _profile;
  bool _initializing = true;

  Profile? get profile => _profile;
  bool get isAuthenticated => _token != null;
  bool get initializing => _initializing;

  /// Restore a previously saved session, if any.
  Future<void> bootstrap() async {
    final prefs = await SharedPreferences.getInstance();
    final saved = prefs.getString(_tokenKey);
    if (saved != null) {
      _token = saved;
      api.setToken(saved);
      try {
        _profile = await api.me();
      } catch (_) {
        // Token is stale/invalid: clear it.
        await _clearToken();
      }
    }
    _initializing = false;
    notifyListeners();
  }

  Future<void> _persistToken(String token) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_tokenKey, token);
  }

  Future<void> _clearToken() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_tokenKey);
    _token = null;
    api.setToken(null);
  }

  Future<void> login(String username, String password) async {
    final result = await api.login(username, password);
    _token = result.token;
    _profile = result.profile;
    api.setToken(result.token);
    await _persistToken(result.token);
    notifyListeners();
  }

  Future<void> register(
      String username, String email, String password) async {
    final result = await api.register(username, email, password);
    _token = result.token;
    _profile = result.profile;
    api.setToken(result.token);
    await _persistToken(result.token);
    notifyListeners();
  }

  Future<void> logout() async {
    await _clearToken();
    _profile = null;
    notifyListeners();
  }

  /// Update the cached profile after a lesson submission.
  void updateProfile(Profile profile) {
    _profile = profile;
    notifyListeners();
  }

  Future<void> refreshProfile() async {
    _profile = await api.me();
    notifyListeners();
  }
}
