import '../models/course.dart';
import '../models/lesson.dart';
import '../models/user.dart';
import 'api_client.dart';

class AuthApi {
  AuthApi(this._client);
  final ApiClient _client;

  Future<Map<String, dynamic>> register({
    required String username,
    required String email,
    required String password,
    String firstName = '',
  }) async {
    final data = await _client.post('/api/v1/auth/register/', {
      'username': username,
      'email': email,
      'password': password,
      'first_name': firstName,
    }) as Map<String, dynamic>;
    return data;
  }

  Future<Map<String, dynamic>> login({
    required String username,
    required String password,
  }) async {
    return await _client.post('/api/v1/auth/token/', {
      'username': username,
      'password': password,
    }) as Map<String, dynamic>;
  }

  Future<AppUser> me() async {
    final data = await _client.get('/api/v1/me/') as Map<String, dynamic>;
    return AppUser.fromJson(data);
  }

  Future<List<AppUser>> leaderboard() async {
    final data = await _client.get('/api/v1/leaderboard/') as List<dynamic>;
    return data
        .map((e) => AppUser.fromJson(e as Map<String, dynamic>))
        .toList(growable: false);
  }
}

class CoursesApi {
  CoursesApi(this._client);
  final ApiClient _client;

  Future<List<Course>> list() async {
    final data = await _client.get('/api/v1/courses/') as List<dynamic>;
    return data
        .map((e) => Course.fromJson(e as Map<String, dynamic>))
        .toList(growable: false);
  }

  Future<Course> detail(String slug) async {
    final data =
        await _client.get('/api/v1/courses/$slug/') as Map<String, dynamic>;
    return Course.fromJson(data);
  }

  Future<LessonDetail> lesson(int id) async {
    final data =
        await _client.get('/api/v1/lessons/$id/') as Map<String, dynamic>;
    return LessonDetail.fromJson(data);
  }

  Future<Map<String, dynamic>> submitLesson(
    int id,
    List<Map<String, dynamic>> answers,
  ) async {
    return await _client.post(
      '/api/v1/lessons/$id/submit/',
      {'answers': answers},
    ) as Map<String, dynamic>;
  }
}
