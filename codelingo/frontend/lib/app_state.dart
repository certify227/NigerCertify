import 'package:flutter/material.dart';

import 'models.dart';
import 'services/api_service.dart';

/// Central app state: authentication + current user gamification stats.
class AppState extends ChangeNotifier {
  final ApiService api = ApiService.instance;

  AppUser? user;
  bool loading = false;
  bool initialized = false;

  bool get isLoggedIn => user != null;

  Future<void> bootstrap() async {
    await api.loadTokens();
    if (api.isAuthenticated) {
      try {
        user = await api.fetchMe();
      } catch (_) {
        await api.logout();
      }
    }
    initialized = true;
    notifyListeners();
  }

  Future<void> login(String username, String password) async {
    await api.login(username, password);
    user = await api.fetchMe();
    notifyListeners();
  }

  Future<void> register(String username, String email, String password) async {
    await api.register(username, email, password);
    user = await api.fetchMe();
    notifyListeners();
  }

  Future<void> logout() async {
    await api.logout();
    user = null;
    notifyListeners();
  }

  Future<void> refreshUser() async {
    if (!api.isAuthenticated) return;
    user = await api.fetchMe();
    notifyListeners();
  }
}
