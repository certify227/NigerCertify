import 'package:flutter/foundation.dart';

import '../models/models.dart';
import '../services/api_service.dart';

class AppState extends ChangeNotifier {
  final ApiService api = ApiService();

  bool isLoading = true;
  bool isAuthenticated = false;
  UserProfile? user;
  Dashboard? dashboard;
  List<Track> tracks = [];
  String? error;

  Future<void> init() async {
    isLoading = true;
    notifyListeners();
    try {
      await api.loadTokens();
      if (api.isLoggedIn) {
        await _loadUserData();
        isAuthenticated = true;
      }
    } catch (e) {
      error = e.toString();
    } finally {
      isLoading = false;
      notifyListeners();
    }
  }

  Future<void> login(String username, String password) async {
    error = null;
    isLoading = true;
    notifyListeners();
    try {
      await api.login(username, password);
      await _loadUserData();
      isAuthenticated = true;
    } catch (e) {
      error = e.toString();
      rethrow;
    } finally {
      isLoading = false;
      notifyListeners();
    }
  }

  Future<void> register(String username, String email, String password) async {
    error = null;
    await api.register(username, email, password);
    await _loadUserData();
    isAuthenticated = true;
    notifyListeners();
  }

  Future<void> logout() async {
    await api.logout();
    isAuthenticated = false;
    user = null;
    dashboard = null;
    tracks = [];
    notifyListeners();
  }

  Future<void> _loadUserData() async {
    user = await api.getProfile();
    dashboard = await api.getDashboard();
    tracks = await api.getTracks();
  }

  Future<void> refresh() async {
    await _loadUserData();
    notifyListeners();
  }

  void updateFromSubmit(SubmitResult result) {
    if (result.correct && result.xpGained != null && user != null) {
      user = user!.copyWith(
        xp: user!.xp + result.xpGained!,
        level: (user!.xp + result.xpGained!) ~/ 100 + 1,
      );
    } else if (!result.correct && result.heartsLeft != null) {
      user = user?.copyWith(hearts: result.heartsLeft);
      dashboard = dashboard?.copyWith(hearts: result.heartsLeft!);
    }
    notifyListeners();
  }
}

extension on Dashboard {
  Dashboard copyWith({int? hearts}) {
    return Dashboard(
      xp: xp,
      level: level,
      streak: streak,
      hearts: hearts ?? this.hearts,
      lessonsCompletedToday: lessonsCompletedToday,
      xpToday: xpToday,
    );
  }
}
