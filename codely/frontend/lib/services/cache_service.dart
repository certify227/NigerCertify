import 'dart:convert';
import 'dart:io';

import 'package:path_provider/path_provider.dart';

class CacheService {
  static const _cacheDir = 'codequest_cache';

  Future<File> _file(String name) async {
    final dir = await getApplicationDocumentsDirectory();
    final cachePath = Directory('${dir.path}/$_cacheDir');
    if (!await cachePath.exists()) {
      await cachePath.create(recursive: true);
    }
    return File('${cachePath.path}/$name.json');
  }

  Future<void> save(String key, dynamic data) async {
    final file = await _file(key);
    await file.writeAsString(jsonEncode(data));
  }

  Future<dynamic> load(String key) async {
    final file = await _file(key);
    if (!await file.exists()) return null;
    return jsonDecode(await file.readAsString());
  }

  Future<void> clear() async {
    final dir = await getApplicationDocumentsDirectory();
    final cachePath = Directory('${dir.path}/$_cacheDir');
    if (await cachePath.exists()) {
      await cachePath.delete(recursive: true);
    }
  }
}
