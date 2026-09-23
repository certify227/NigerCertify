import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../domain/logger.dart';

class ThemeController extends ChangeNotifier {
  ThemeController(this._preferences, {Logger? logger}) : _logger = logger ?? Logger('theme');

  static const storageKey = 'aureon-theme';

  final SharedPreferences _preferences;
  final Logger _logger;
  ThemeMode _mode = ThemeMode.dark;

  ThemeMode get mode => _mode;

  Future<void> load() async {
    _mode = _preferences.getString(storageKey) == 'light' ? ThemeMode.light : ThemeMode.dark;
    notifyListeners();
  }

  Future<void> setMode(ThemeMode mode) async {
    _mode = mode;
    await _preferences.setString(storageKey, mode == ThemeMode.light ? 'light' : 'dark');
    _logger.info('Thème enregistré', {'theme': mode.name});
    notifyListeners();
  }
}
