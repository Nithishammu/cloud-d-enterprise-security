import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

class ApiFailure implements Exception {
  ApiFailure(this.message, {this.statusCode, this.payload});

  final String message;
  final int? statusCode;
  final Map<String, dynamic>? payload;

  @override
  String toString() => message;
}

class CloudDApi {
  CloudDApi._();
  static final CloudDApi instance = CloudDApi._();

  static const _cookieKey = 'cloud_d_session';
  static const _baseUrlKey = 'cloud_d_api_base_url';
  static const _secureStorage = FlutterSecureStorage();
  final http.Client _client = http.Client();
  String baseUrl = 'http://10.0.2.2:8765';
  String? _sessionCookie;

  Future<void> initialize({required String fallbackUrl}) async {
    final prefs = await SharedPreferences.getInstance();
    baseUrl = _normalize(prefs.getString(_baseUrlKey) ?? fallbackUrl);
    _sessionCookie = await _secureStorage.read(key: _cookieKey);
  }

  String _normalize(String value) {
    final normalized = value.trim().replaceAll(RegExp(r'/+$'), '');
    if (normalized.isEmpty) throw ApiFailure('Enter a server address.');
    final uri = Uri.tryParse(normalized);
    if (uri == null ||
        !uri.hasScheme ||
        uri.host.isEmpty ||
        !{'http', 'https'}.contains(uri.scheme)) {
      throw ApiFailure('Use a valid http:// or https:// server address.');
    }
    return normalized;
  }

  Future<void> setBaseUrl(String value) async {
    final normalized = _normalize(value);
    if (Uri.parse(normalized).origin != Uri.parse(baseUrl).origin) {
      await clearSession();
    }
    baseUrl = normalized;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_baseUrlKey, baseUrl);
  }

  Uri _uri(String path) => Uri.parse('$baseUrl$path');

  Map<String, String> _headers({Map<String, String>? extra}) {
    final headers = <String, String>{'Accept': 'application/json'};
    if (_sessionCookie != null && _sessionCookie!.isNotEmpty) {
      headers['Cookie'] = 'cloud_d_session=$_sessionCookie';
    }
    if (extra != null) headers.addAll(extra);
    return headers;
  }

  Future<Map<String, dynamic>> _decode(http.Response response) async {
    _rememberCookie(response.headers['set-cookie']);
    Map<String, dynamic> body = {};
    try {
      final decoded = jsonDecode(utf8.decode(response.bodyBytes));
      if (decoded is Map<String, dynamic>) body = decoded;
    } catch (_) {
      // A hosting proxy can return an HTML error page; show a compact message.
    }
    if (response.statusCode >= 200 &&
        response.statusCode < 300 &&
        !(response.headers['content-type'] ?? '').contains(
          'application/json',
        )) {
      throw ApiFailure(
        'This address did not return the Cloud-D API. The service may be suspended or the address may be incorrect.',
      );
    }
    if (response.statusCode < 200 || response.statusCode >= 300) {
      if (response.statusCode == 401 && _sessionCookie != null) {
        await clearSession();
      }
      throw ApiFailure(
        (body['error'] as String?) ??
            'Request failed (${response.statusCode}). Check the server address and try again.',
        statusCode: response.statusCode,
        payload: body,
      );
    }
    return body;
  }

  void _rememberCookie(String? setCookie) {
    if (setCookie == null) return;
    final match = RegExp(r'(?:^|,\s*)cloud_d_session=([^; ,]+)')
        .firstMatch(setCookie);
    if (match == null) return;
    final value = match.group(1)!;
    if (value.isEmpty) {
      clearSession();
    } else {
      _sessionCookie = value;
      _secureStorage.write(key: _cookieKey, value: value);
    }
  }

  Future<Map<String, dynamic>> request(
    String path, {
    String method = 'GET',
    Object? body,
  }) async {
    try {
      final request = http.Request(method, _uri(path))
        ..headers.addAll(_headers());
      if (body != null) {
        request.headers['Content-Type'] = 'application/json';
        request.body = jsonEncode(body);
      }
      final response = await http.Response.fromStream(
        await _client.send(request).timeout(const Duration(seconds: 30)),
      );
      return await _decode(response);
    } on ApiFailure {
      rethrow;
    } catch (error) {
      throw ApiFailure(
        'Could not reach Cloud-D at $baseUrl. ${error is TimeoutException ? 'The server timed out.' : 'Check your connection and server address.'}',
      );
    }
  }

  Future<Map<String, dynamic>> login(String username, String password) =>
      request(
        '/api/auth/login',
        method: 'POST',
        body: {'username': username, 'password': password},
      );

  Future<Map<String, dynamic>> signup(Map<String, dynamic> details) =>
      request('/api/auth/signup', method: 'POST', body: details);

  Future<void> logout() async {
    try {
      await request('/api/auth/logout', method: 'POST', body: const {});
    } finally {
      await clearSession();
    }
  }

  Future<void> clearSession() async {
    _sessionCookie = null;
    await _secureStorage.delete(key: _cookieKey);
  }

  Future<Map<String, dynamic>?> currentUser() async {
    final result = await request('/api/auth/me');
    final user = result['user'];
    return user is Map<String, dynamic> ? user : null;
  }

  Future<Map<String, dynamic>> getState() => request('/api/state');
  Future<Map<String, dynamic>> getFolders() => request('/api/folders');

  Future<Map<String, dynamic>> createFolder(String name) =>
      request('/api/folders', method: 'POST', body: {'name': name});

  Future<Map<String, dynamic>> updateDrive(String logicalId, String action) =>
      request(
        '/api/drive-state',
        method: 'POST',
        body: {'logical_id': logicalId, 'action': action},
      );

  Future<Map<String, dynamic>> fileVersions(String logicalId) =>
      request('/api/file-groups/${Uri.encodeComponent(logicalId)}/versions');

  Future<Uint8List> downloadFile(String fileId) async {
    try {
      final request = http.Request(
        'GET',
        _uri('/api/files/${Uri.encodeComponent(fileId)}/download'),
      )..headers.addAll(_headers());
      final response = await http.Response.fromStream(
        await _client.send(request).timeout(const Duration(seconds: 45)),
      );
      if (response.statusCode < 200 || response.statusCode >= 300) {
        Map<String, dynamic> body = {};
        try {
          body = jsonDecode(
            utf8.decode(response.bodyBytes),
          ) as Map<String, dynamic>;
        } catch (_) {}
        throw ApiFailure(
          (body['error'] as String?) ?? 'The file download failed.',
          statusCode: response.statusCode,
          payload: body,
        );
      }
      return response.bodyBytes;
    } on ApiFailure {
      rethrow;
    } catch (_) {
      throw ApiFailure(
        'Could not download the file. Check your connection and server address.',
      );
    }
  }

  Future<Map<String, dynamic>> upload({
    required String folderId,
    required String filename,
    required Uint8List bytes,
    String? duplicateMode,
  }) async {
    try {
      final request = http.MultipartRequest('POST', _uri('/api/upload'))
        ..headers.addAll(_headers())
        ..fields['folder_id'] = folderId;
      if (duplicateMode != null) {
        request.fields['duplicate_mode'] = duplicateMode;
      }
      request.files.add(
        http.MultipartFile.fromBytes('file', bytes, filename: filename),
      );
      final response = await http.Response.fromStream(
        await _client.send(request).timeout(const Duration(minutes: 2)),
      );
      return await _decode(response);
    } on ApiFailure {
      rethrow;
    } catch (_) {
      throw ApiFailure(
        'The upload could not reach Cloud-D. Check your connection and try again.',
      );
    }
  }

  Future<Map<String, dynamic>> beginSimulation(Map<String, dynamic> config) =>
      request('/api/restart', method: 'POST', body: config);

  Future<Map<String, dynamic>> simulateRound(Map<String, dynamic> config) =>
      request('/api/round', method: 'POST', body: config);
}
