import 'package:devlingo_app/app.dart';
import 'package:flutter/material.dart';

void main() {
  const apiBaseUrl = String.fromEnvironment(
    'API_BASE_URL',
    defaultValue: 'http://127.0.0.1:8000/api',
  );
  runApp(DevLingoApp(repository: HttpLearningRepository(apiBaseUrl)));
}
