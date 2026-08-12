class AppUser {
  final int id;
  final String username;
  final String email;
  final String firstName;
  final int xp;
  final int hearts;
  final int streak;
  final int level;
  final String? lastActivityDate;
  final String avatar;

  const AppUser({
    required this.id,
    required this.username,
    required this.email,
    required this.firstName,
    required this.xp,
    required this.hearts,
    required this.streak,
    required this.level,
    required this.lastActivityDate,
    required this.avatar,
  });

  factory AppUser.fromJson(Map<String, dynamic> json) => AppUser(
        id: json['id'] as int,
        username: json['username'] as String? ?? '',
        email: json['email'] as String? ?? '',
        firstName: json['first_name'] as String? ?? '',
        xp: json['xp'] as int? ?? 0,
        hearts: json['hearts'] as int? ?? 0,
        streak: json['streak'] as int? ?? 0,
        level: json['level'] as int? ?? 1,
        lastActivityDate: json['last_activity_date'] as String?,
        avatar: json['avatar'] as String? ?? '',
      );
}
