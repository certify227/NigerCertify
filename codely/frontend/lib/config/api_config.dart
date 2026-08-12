import 'dart:io' show Platform;

class ApiConfig {
  /// URL de base de l'API Django.
  /// Android émulateur : 10.0.2.2 | Windows/iOS : localhost
  static String get baseUrl {
    const envUrl = String.fromEnvironment('API_URL');
    if (envUrl.isNotEmpty) return envUrl;

    if (Platform.isAndroid) {
      return 'http://10.0.2.2:8000/api';
    }
    return 'http://127.0.0.1:8000/api';
  }
}
