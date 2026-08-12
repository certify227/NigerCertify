import 'dart:convert';
import 'dart:io' show Platform;

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

class ApiException implements Exception {
  final int statusCode;
  final String message;
  final Map<String, dynamic>? body;

  ApiException(this.statusCode, this.message, [this.body]);

  @override
  String toString() => 'ApiException($statusCode): $message';
}

/// Client HTTP centralisé pour l'API CodeLingo.
///
/// L'URL de base peut être surchargée à la compilation avec :
/// flutter run --dart-define=API_BASE_URL=http://192.168.1.10:8000
class ApiClient {
  ApiClient({String? baseUrl, http.Client? httpClient})
      : _http = httpClient ?? http.Client(),
        _baseUrl = baseUrl ?? _defaultBaseUrl();

  final http.Client _http;
  final String _baseUrl;
  String? _accessToken;

  String get baseUrl => _baseUrl;

  static String _defaultBaseUrl() {
    const override = String.fromEnvironment('API_BASE_URL', defaultValue: '');
    if (override.isNotEmpty) return override;
    if (kIsWeb) return 'http://localhost:8000';
    // Android émulateur → 10.0.2.2 pour joindre le host.
    try {
      if (Platform.isAndroid) return 'http://10.0.2.2:8000';
    } catch (_) {}
    return 'http://127.0.0.1:8000';
  }

  void setAccessToken(String? token) {
    _accessToken = token;
  }

  Map<String, String> _headers({bool jsonBody = false}) {
    final headers = <String, String>{'Accept': 'application/json'};
    if (jsonBody) headers['Content-Type'] = 'application/json';
    if (_accessToken != null) headers['Authorization'] = 'Bearer $_accessToken';
    return headers;
  }

  Uri _uri(String path) => Uri.parse('$_baseUrl$path');

  Future<dynamic> get(String path) async {
    final res = await _http.get(_uri(path), headers: _headers());
    return _handle(res);
  }

  Future<dynamic> post(String path, Object body) async {
    final res = await _http.post(
      _uri(path),
      headers: _headers(jsonBody: true),
      body: jsonEncode(body),
    );
    return _handle(res);
  }

  Future<dynamic> patch(String path, Object body) async {
    final res = await _http.patch(
      _uri(path),
      headers: _headers(jsonBody: true),
      body: jsonEncode(body),
    );
    return _handle(res);
  }

  dynamic _handle(http.Response res) {
    final decoded = res.body.isEmpty ? null : jsonDecode(utf8.decode(res.bodyBytes));
    if (res.statusCode >= 200 && res.statusCode < 300) {
      return decoded;
    }
    final message = decoded is Map<String, dynamic>
        ? (decoded['detail']?.toString() ?? decoded.toString())
        : res.reasonPhrase ?? 'Erreur inconnue';
    throw ApiException(
      res.statusCode,
      message,
      decoded is Map<String, dynamic> ? decoded : null,
    );
  }
}
