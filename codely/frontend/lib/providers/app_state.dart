import 'package:flutter/foundation.dart';

import '../models/models.dart';
import '../services/api_service.dart';
import '../services/notification_service.dart';

class AppState extends ChangeNotifier {
  final ApiService api = ApiService();
  final NotificationService notifications = NotificationService();

  bool isLoading = true;
  bool isAuthenticated = false;
  bool isOffline = false;
  UserProfile? user;
  Dashboard? dashboard;
  List<Track> tracks = [];
  String? error;

  Future<void> init() async {
    isLoading = true;
    notifyListeners();
    try {
      await notifications.init();
      await api.loadTokens();
      isOffline = api.isOffline;
      api.connectivity.onStatusChanged.listen((online) async {
        isOffline = !online;
        api.isOffline = !online;
        if (online && isAuthenticated) {
          await api.syncOfflineQueue();
          await refresh();
        }
        notifyListeners();
      });
      if (api.isLoggedIn) {
        await _loadUserData();
        isAuthenticated = true;
        await _syncNotifications();
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
      await _syncNotifications();
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
    await notifications.cancelReminders();
    await api.logout();
    isAuthenticated = false;
    user = null;
    dashboard = null;
    tracks = [];
    notifyListeners();
  }

  Future<void> _loadUserData() async {
    await api.checkConnectivity();
    isOffline = api.isOffline;
    user = await api.getProfile();
    dashboard = await api.getDashboard();
    tracks = await api.getTracks();
  }

  Future<void> refresh() async {
    await _loadUserData();
    notifyListeners();
  }

  Future<void> updateReminders({required bool enabled, required int hour}) async {
    user = await api.updateReminders(enabled: enabled, hour: hour);
    if (enabled) {
      await notifications.scheduleStreakReminder(hour: hour, streak: user?.streak ?? 0);
    } else {
      await notifications.cancelReminders();
    }
    notifyListeners();
  }

  Future<void> _syncNotifications() async {
    if (user?.reminderEnabled == true) {
      await notifications.scheduleStreakReminder(
        hour: user!.reminderHour,
        streak: user!.streak,
      );
    }
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
