import '../constants.dart';

sealed class UrlCheck {
  const UrlCheck();
}

class UrlAccepted extends UrlCheck {
  const UrlAccepted(this.url);
  final String url;
}

class UrlRejected extends UrlCheck {
  const UrlRejected(this.message);
  final String message;
}

UrlCheck parseHttpUrl(String input) {
  final trimmed = input.trim();
  final Uri uri;
  try {
    uri = Uri.parse(trimmed);
  } on FormatException {
    return const UrlRejected(invalidUrlMessage);
  }

  final allowedScheme = uri.scheme == 'http' || uri.scheme == 'https';
  if (!uri.hasScheme || !allowedScheme || uri.host.isEmpty || uri.userInfo.isNotEmpty) {
    return const UrlRejected(invalidUrlMessage);
  }
  return UrlAccepted(uri.toString());
}
