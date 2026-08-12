import 'dart:io' show Platform;

import 'package:flutter/foundation.dart' show kIsWeb;

/// Central place to configure how the app reaches the Django backend.
///
/// You can override the base URL at build/run time with:
///   flutter run --dart-define=API_BASE_URL=http://192.168.1.20:8000
class AppConfig {
  static const String _override =
      String.fromEnvironment('API_BASE_URL', defaultValue: '');

  /// Base URL of the CodeQuest REST API (without a trailing slash).
  static String get apiBaseUrl {
    if (_override.isNotEmpty) return _override;

    // The Android emulator maps the host machine to 10.0.2.2.
    if (!kIsWeb && Platform.isAndroid) {
      return 'http://10.0.2.2:8000';
    }
    // Desktop (Windows/Linux/macOS), iOS simulator and web default to
    // localhost. On a physical device, pass --dart-define to point at the
    // machine running the backend.
    return 'http://127.0.0.1:8000';
  }

  static String get apiRoot => '$apiBaseUrl/api';
}
