import 'dart:convert';

import 'package:shared_preferences/shared_preferences.dart';

class OfflineQueueService {
  static const _key = 'offline_submit_queue';

  Future<List<Map<String, dynamic>>> getQueue() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getStringList(_key) ?? [];
    return raw.map((e) => jsonDecode(e) as Map<String, dynamic>).toList();
  }

  Future<void> enqueue(Map<String, dynamic> item) async {
    final prefs = await SharedPreferences.getInstance();
    final queue = prefs.getStringList(_key) ?? [];
    queue.add(jsonEncode(item));
    await prefs.setStringList(_key, queue);
  }

  Future<void> clear() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_key);
  }

  Future<void> removeAt(int index) async {
    final prefs = await SharedPreferences.getInstance();
    final queue = prefs.getStringList(_key) ?? [];
    if (index >= 0 && index < queue.length) {
      queue.removeAt(index);
      await prefs.setStringList(_key, queue);
    }
  }
}
