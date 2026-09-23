import 'dart:convert';

import 'package:flutter/foundation.dart';

import 'redact.dart';

enum LogLevel { debug, info, warn, error }

const _weight = {LogLevel.debug: 10, LogLevel.info: 20, LogLevel.warn: 30, LogLevel.error: 40};

typedef LogWriter = void Function(String line);

void debugLogWriter(String line) => debugPrint(line);

class Logger {
  Logger(this.scope, {this.level = LogLevel.info, this.write = debugLogWriter});

  final String scope;
  final LogLevel level;
  final LogWriter write;

  void debug(String message, [Object? details]) => _write(LogLevel.debug, message, details);
  void info(String message, [Object? details]) => _write(LogLevel.info, message, details);
  void warn(String message, [Object? details]) => _write(LogLevel.warn, message, details);
  void error(String message, [Object? details]) => _write(LogLevel.error, message, details);

  void _write(LogLevel current, String message, Object? details) {
    if (_weight[current]! < _weight[level]!) return;
    final suffix = details == null ? '' : ' ${jsonEncode(redact(details))}';
    write('[${current.name.toUpperCase()}] [$scope] ${redactText(message)}$suffix');
  }
}
