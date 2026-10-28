import 'dart:async';
import 'dart:convert';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:share_plus/share_plus.dart';

import 'cloud_d_api.dart';

const _ink = Color(0xFF261C36);
const _purple = Color(0xFF7252C8);
const _violet = Color(0xFF9B5BC2);
const _teal = Color(0xFF2D9E98);
const _canvas = Color(0xFFF7F3FA);
const _line = Color(0xFFE2D8EC);

Map<String, dynamic> asMap(dynamic value) =>
    value is Map ? value.cast<String, dynamic>() : <String, dynamic>{};
List<Map<String, dynamic>> asMaps(dynamic value) => value is List
    ? value
          .whereType<Map>()
          .map((item) => item.cast<String, dynamic>())
          .toList()
    : <Map<String, dynamic>>[];
String displayDate(dynamic value) {
  if (value == null || value.toString().isEmpty) return '—';
  final parsed = DateTime.tryParse(value.toString())?.toLocal();
  if (parsed == null) return value.toString();
  final date =
      '${parsed.day.toString().padLeft(2, '0')}/${parsed.month.toString().padLeft(2, '0')}/${parsed.year}';
  final time =
      '${parsed.hour.toString().padLeft(2, '0')}:${parsed.minute.toString().padLeft(2, '0')}';
  return '$date · $time';
}

String byteLabel(dynamic value) {
  final bytes = (value is num ? value.toInt() : int.tryParse('$value') ?? 0)
      .toDouble();
  if (bytes < 1024) return '${bytes.toInt()} B';
  if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
  return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
}

String apiError(Object error) => error is ApiFailure
    ? error.message
    : 'Something went wrong. Please try again.';

void main() => runApp(const CloudDApp());

class CloudDApp extends StatefulWidget {
  const CloudDApp({super.key});

  @override
  State<CloudDApp> createState() => _CloudDAppState();
}

class _CloudDAppState extends State<CloudDApp> {
  final _api = CloudDApi.instance;
  Map<String, dynamic>? _user;
  Map<String, dynamic> _state = {};
  bool _loading = true;
  String? _connectionMessage;

  String get _fallbackUrl {
    if (kIsWeb) return 'http://127.0.0.1:8765';
    return defaultTargetPlatform == TargetPlatform.android
        ? 'http://10.0.2.2:8765'
        : 'http://127.0.0.1:8765';
  }

  @override
  void initState() {
    super.initState();
    _bootstrap();
  }

  Future<void> _bootstrap() async {
    await _api.initialize(fallbackUrl: _fallbackUrl);
    try {
      final user = await _api.currentUser();
      if (user != null) {
        final state = await _api.getState();
        if (mounted)
          setState(() {
            _user = user;
            _state = state;
            _connectionMessage = null;
          });
      }
    } catch (error) {
      if (mounted) setState(() => _connectionMessage = apiError(error));
    }
    if (mounted) setState(() => _loading = false);
  }

  Future<void> _signedIn(Map<String, dynamic> user) async {
    setState(() {
      _loading = true;
      _connectionMessage = null;
    });
    try {
      final data = await _api.getState();
      if (mounted)
        setState(() {
          _user = user;
          _state = data;
          _loading = false;
        });
    } catch (error) {
      if (mounted)
        setState(() {
          _connectionMessage = apiError(error);
          _loading = false;
        });
    }
  }

  Future<void> _refresh() async {
    final data = await _api.getState();
    if (mounted) setState(() => _state = data);
  }

  Future<void> _signOut() async {
    await _api.logout();
    if (mounted)
      setState(() {
        _user = null;
        _state = {};
        _connectionMessage = null;
      });
  }

  Future<void> _runSimulation({
    required Map<String, dynamic> config,
    required int rounds,
  }) async {
    if (_user?['role'] != 'staff') {
      _message('Simulation controls are available to staff accounts.');
      return;
    }
    if ((config['active_vectors'] as List? ?? []).isEmpty) {
      _message('Choose at least one attacker agent.');
      return;
    }
    setState(() => _state = {..._state, '_running': true});
    try {
      final fresh = await _api.beginSimulation(config);
      if (mounted) setState(() => _state = {...fresh, '_running': true});
      for (var i = 0; i < rounds; i++) {
        if (_state['game_over'] == true) break;
        final currentRound = (_state['round'] as num?)?.toInt() ?? 0;
        final maxRounds = (_state['max_rounds'] as num?)?.toInt() ?? 20;
        if (currentRound >= maxRounds) break;
        final next = await _api.simulateRound(config);
        if (mounted) setState(() => _state = {...next, '_running': true});
        await Future<void>.delayed(const Duration(milliseconds: 140));
      }
      if (mounted)
        _message(
          'Simulation updated · ${_state['round'] ?? 0} rounds completed.',
        );
    } catch (error) {
      if (mounted) _message(apiError(error));
    } finally {
      if (mounted) setState(() => _state = {..._state, '_running': false});
    }
  }

  void _message(String text) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(
        SnackBar(content: Text(text), behavior: SnackBarBehavior.floating),
      );
  }

  @override
  Widget build(BuildContext context) {
    final scheme =
        ColorScheme.fromSeed(
          seedColor: _purple,
          brightness: Brightness.light,
        ).copyWith(
          primary: _purple,
          secondary: _teal,
          surface: Colors.white,
          onSurface: _ink,
        );
    return MaterialApp(
      title: 'Cloud-D',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: scheme,
        scaffoldBackgroundColor: _canvas,
        appBarTheme: const AppBarTheme(
          backgroundColor: _canvas,
          foregroundColor: _ink,
          centerTitle: false,
        ),
        cardTheme: CardThemeData(
          color: Colors.white,
          elevation: 0,
          margin: EdgeInsets.zero,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(18),
            side: const BorderSide(color: _line),
          ),
        ),
        inputDecorationTheme: InputDecorationTheme(
          filled: true,
          fillColor: Colors.white,
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(13),
            borderSide: const BorderSide(color: _line),
          ),
          enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(13),
            borderSide: const BorderSide(color: _line),
          ),
          focusedBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(13),
            borderSide: const BorderSide(color: _purple, width: 1.6),
          ),
          contentPadding: const EdgeInsets.symmetric(
            horizontal: 14,
            vertical: 13,
          ),
        ),
        filledButtonTheme: FilledButtonThemeData(
          style: FilledButton.styleFrom(
            backgroundColor: _purple,
            foregroundColor: Colors.white,
            minimumSize: const Size(0, 46),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(13),
            ),
            textStyle: const TextStyle(fontWeight: FontWeight.w700),
          ),
        ),
        outlinedButtonTheme: OutlinedButtonThemeData(
          style: OutlinedButton.styleFrom(
            foregroundColor: _ink,
            minimumSize: const Size(0, 44),
            side: const BorderSide(color: _line),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(13),
            ),
          ),
        ),
        textTheme: ThemeData.light().textTheme.apply(
          bodyColor: _ink,
          displayColor: _ink,
        ),
      ),
      home: _loading
          ? const Scaffold(body: Center(child: CircularProgressIndicator()))
          : _user == null
          ? LoginScreen(
              api: _api,
              fallbackUrl: _fallbackUrl,
              initialMessage: _connectionMessage,
              onSignedIn: _signedIn,
            )
          : MainShell(
              api: _api,
              user: _user!,
              state: _state,
              onRefresh: _refresh,
              onSignOut: _signOut,
              onRunSimulation: _runSimulation,
            ),
    );
  }
}

class LoginScreen extends StatefulWidget {
  const LoginScreen({
    required this.api,
    required this.fallbackUrl,
    required this.onSignedIn,
    this.initialMessage,
    super.key,
  });
  final CloudDApi api;
  final String fallbackUrl;
  final String? initialMessage;
  final ValueChanged<Map<String, dynamic>> onSignedIn;

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _formKey = GlobalKey<FormState>();
  final _username = TextEditingController();
  final _name = TextEditingController();
  final _email = TextEditingController();
  final _password = TextEditingController();
  final _staffCode = TextEditingController();
  final _server = TextEditingController();
  bool _signup = false;
  bool _staff = false;
  bool _busy = false;
  bool _showPassword = false;
  PlatformFile? _profile;
  String? _error;

  @override
  void initState() {
    super.initState();
    _server.text = widget.api.baseUrl;
    _error = widget.initialMessage;
  }

  @override
  void dispose() {
    _username.dispose();
    _name.dispose();
    _email.dispose();
    _password.dispose();
    _staffCode.dispose();
    _server.dispose();
    super.dispose();
  }

  Future<void> _pickProfile() async {
    final file = await FilePicker.pickFile(type: FileType.image);
    if (file == null) return;
    if ((file.lengthSync() ?? 0) > 2 * 1024 * 1024) {
      setState(() => _error = 'Profile photos must be 2 MB or smaller.');
      return;
    }
    setState(() {
      _profile = file;
      _error = null;
    });
  }

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await widget.api.setBaseUrl(_server.text);
      Map<String, dynamic> result;
      if (_signup) {
        final payload = <String, dynamic>{
          'email': _email.text.trim(),
          'name': _name.text.trim(),
          'username': _username.text.trim(),
          'password': _password.text,
          'role': _staff ? 'staff' : 'customer',
          'staff_registration_code': _staff ? _staffCode.text.trim() : '',
        };
        if (_profile != null) {
          final ext = (_profile!.extension ?? 'png').toLowerCase();
          final mime = ext == 'jpg' || ext == 'jpeg' ? 'jpeg' : ext;
          payload['profile_picture'] =
              'data:image/$mime;base64,${base64Encode(await _profile!.readAsBytes())}';
        }
        result = await widget.api.signup(payload);
      } else {
        result = await widget.api.login(_username.text.trim(), _password.text);
      }
      final user = asMap(result['user']);
      if (user.isEmpty)
        throw ApiFailure(
          'The server response did not include an account. Check that this is a Cloud-D server.',
        );
      widget.onSignedIn(user);
    } catch (error) {
      if (mounted) setState(() => _error = apiError(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(22),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 460),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const SizedBox(height: 20),
                  const _BrandHeader(),
                  const SizedBox(height: 30),
                  Text(
                    _signup ? 'Create your account' : 'Sign in to your cloud',
                    style: const TextStyle(
                      fontSize: 28,
                      fontWeight: FontWeight.w800,
                      letterSpacing: -.8,
                    ),
                  ),
                  const SizedBox(height: 7),
                  Text(
                    _signup
                        ? 'Your account type assigns the correct storage area.'
                        : 'Sign in with your Cloud-D username and password.',
                    style: const TextStyle(
                      color: Color(0xFF716881),
                      height: 1.5,
                    ),
                  ),
                  const SizedBox(height: 20),
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(18),
                      child: Form(
                        key: _formKey,
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.stretch,
                          children: [
                            Row(
                              children: [
                                const Icon(Icons.dns_outlined, color: _purple),
                                const SizedBox(width: 9),
                                const Expanded(
                                  child: Text(
                                    'Cloud-D server',
                                    style: TextStyle(
                                      fontWeight: FontWeight.w700,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                            TextFormField(
                              controller: _server,
                              keyboardType: TextInputType.url,
                              decoration: const InputDecoration(
                                hintText: 'https://your-cloud-d-service',
                              ),
                              validator: (value) =>
                                  value == null || value.trim().isEmpty
                                  ? 'Enter a server address.'
                                  : null,
                            ),
                            const SizedBox(height: 6),
                            const Text(
                              'For the Android emulator: http://10.0.2.2:8765 · iOS simulator: http://127.0.0.1:8765',
                              style: TextStyle(
                                fontSize: 11,
                                color: Color(0xFF756D80),
                                height: 1.4,
                              ),
                            ),
                            const SizedBox(height: 17),
                            if (_signup) ...[
                              SegmentedButton<bool>(
                                segments: const [
                                  ButtonSegment(
                                    value: false,
                                    label: Text('Customer'),
                                    icon: Icon(Icons.person_outline),
                                  ),
                                  ButtonSegment(
                                    value: true,
                                    label: Text('Staff'),
                                    icon: Icon(Icons.badge_outlined),
                                  ),
                                ],
                                selected: {_staff},
                                onSelectionChanged: (selected) =>
                                    setState(() => _staff = selected.first),
                              ),
                              const SizedBox(height: 14),
                              TextFormField(
                                controller: _email,
                                keyboardType: TextInputType.emailAddress,
                                autofillHints: const [AutofillHints.email],
                                decoration: const InputDecoration(
                                  labelText: 'Email address',
                                  prefixIcon: Icon(Icons.mail_outline),
                                ),
                                validator: (value) =>
                                    value == null ||
                                        !RegExp(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
                                            .hasMatch(value.trim())
                                    ? 'Enter a valid email address.'
                                    : null,
                              ),
                              const SizedBox(height: 12),
                              TextFormField(
                                controller: _name,
                                textCapitalization: TextCapitalization.words,
                                autofillHints: const [AutofillHints.name],
                                decoration: InputDecoration(
                                  labelText: 'Your name',
                                  prefixIcon: Padding(
                                    padding: const EdgeInsets.all(9),
                                    child:
                                        ValueListenableBuilder<
                                          TextEditingValue
                                        >(
                                          valueListenable: _name,
                                          builder: (context, value, child) =>
                                              CircleAvatar(
                                                radius: 17,
                                                backgroundColor: const Color(
                                                  0xFFEDE5F8,
                                                ),
                                                foregroundColor: _ink,
                                                child: Text(
                                                  value.text.trim().isEmpty
                                                      ? ''
                                                      : value.text
                                                            .trim()[0]
                                                            .toUpperCase(),
                                                ),
                                              ),
                                        ),
                                  ),
                                ),
                                validator: (value) =>
                                    value == null ||
                                        value.trim().isEmpty ||
                                        value.trim().length > 80
                                    ? 'Enter your name (up to 80 characters).'
                                    : null,
                              ),
                              const SizedBox(height: 12),
                              OutlinedButton.icon(
                                onPressed: _pickProfile,
                                icon: const Icon(Icons.add_a_photo_outlined),
                                label: Text(
                                  _profile == null
                                      ? 'Add profile photo (optional)'
                                      : _profile!.name,
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                              if (_staff) ...[
                                const SizedBox(height: 12),
                                TextFormField(
                                  controller: _staffCode,
                                  obscureText: true,
                                  decoration: const InputDecoration(
                                    labelText: 'Staff Registration Code',
                                    prefixIcon: Icon(Icons.key_outlined),
                                    helperText:
                                        'Required for staff account creation.',
                                  ),
                                  validator: (value) =>
                                      _staff &&
                                          (value == null ||
                                              value.trim().isEmpty)
                                      ? 'A valid staff registration code is required.'
                                      : null,
                                ),
                              ],
                              const SizedBox(height: 12),
                            ],
                            TextFormField(
                              controller: _username,
                              autofillHints: const [AutofillHints.username],
                              textInputAction: TextInputAction.next,
                              decoration: const InputDecoration(
                                labelText: 'Username',
                                prefixIcon: Icon(Icons.person_outline),
                              ),
                              validator: (value) =>
                                  value == null ||
                                      !RegExp(
                                        r'^[A-Za-z0-9][A-Za-z0-9._-]{2,29}$',
                                      ).hasMatch(value.trim())
                                  ? 'Use 3–30 letters, numbers, dots, underscores, or hyphens.'
                                  : null,
                            ),
                            const SizedBox(height: 12),
                            TextFormField(
                              controller: _password,
                              obscureText: !_showPassword,
                              autofillHints: _signup
                                  ? const [AutofillHints.newPassword]
                                  : const [AutofillHints.password],
                              decoration: InputDecoration(
                                labelText: 'Password',
                                prefixIcon: const Icon(Icons.lock_outline),
                                suffixIcon: IconButton(
                                  tooltip: _showPassword
                                      ? 'Hide password'
                                      : 'Show password',
                                  onPressed: () => setState(
                                    () => _showPassword = !_showPassword,
                                  ),
                                  icon: Icon(
                                    _showPassword
                                        ? Icons.visibility_off_outlined
                                        : Icons.visibility_outlined,
                                  ),
                                ),
                              ),
                              validator: (value) =>
                                  value == null ||
                                      value.length < (_signup ? 10 : 1)
                                  ? (_signup
                                        ? 'Use at least 10 characters.'
                                        : 'Enter your password.')
                                  : null,
                            ),
                            if (_error != null) ...[
                              const SizedBox(height: 13),
                              _ErrorBanner(_error!),
                            ],
                            const SizedBox(height: 16),
                            FilledButton(
                              onPressed: _busy ? null : _submit,
                              child: _busy
                                  ? const SizedBox(
                                      height: 21,
                                      width: 21,
                                      child: CircularProgressIndicator(
                                        strokeWidth: 2,
                                        color: Colors.white,
                                      ),
                                    )
                                  : Text(
                                      _signup ? 'Create account' : 'Sign in',
                                    ),
                            ),
                            const SizedBox(height: 12),
                            Center(
                              child: TextButton(
                                onPressed: _busy
                                    ? null
                                    : () => setState(() {
                                        _signup = !_signup;
                                        _error = null;
                                        _profile = null;
                                      }),
                                child: Text(
                                  _signup
                                      ? 'Already registered? Sign in'
                                      : 'New to Cloud-D? Create an account',
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 18),
                  const Text(
                    'Cloud-D · PSG College of Technology',
                    textAlign: TextAlign.center,
                    style: TextStyle(color: Color(0xFF80768E), fontSize: 12),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class MainShell extends StatefulWidget {
  const MainShell({
    required this.api,
    required this.user,
    required this.state,
    required this.onRefresh,
    required this.onSignOut,
    required this.onRunSimulation,
    super.key,
  });
  final CloudDApi api;
  final Map<String, dynamic> user;
  final Map<String, dynamic> state;
  final Future<void> Function() onRefresh;
  final Future<void> Function() onSignOut;
  final Future<void> Function({
    required Map<String, dynamic> config,
    required int rounds,
  })
  onRunSimulation;

  @override
  State<MainShell> createState() => _MainShellState();
}

class _MainShellState extends State<MainShell> with WidgetsBindingObserver {
  int _tab = 0;
  Timer? _syncTimer;
  bool _syncing = false;
  String? _lastSecurityNoticeId;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _lastSecurityNoticeId = asMap(
      widget.state['security_notice'],
    )['id']?.toString();
    _syncTimer = Timer.periodic(
      const Duration(seconds: 12),
      (_) => _syncFromServer(),
    );
  }

  @override
  void didUpdateWidget(covariant MainShell oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.user['role'] != 'customer') return;
    final noticeId = asMap(widget.state['security_notice'])['id']?.toString();
    if (noticeId == null || noticeId == _lastSecurityNoticeId) return;
    _lastSecurityNoticeId = noticeId;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      showDialog<void>(
        context: context,
        builder: (context) => AlertDialog(
          icon: const Icon(Icons.verified_user_outlined, color: _teal),
          title: const Text('Security activity detected'),
          content: const Text(
            'A simulated attack is in progress. Cloud-D defender agents have responded and the situation is under control.',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Understood'),
            ),
          ],
        ),
      );
    });
  }

  @override
  void dispose() {
    _syncTimer?.cancel();
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) _syncFromServer();
  }

  Future<void> _syncFromServer() async {
    if (_syncing) return;
    _syncing = true;
    try {
      await widget.onRefresh();
    } catch (_) {
      // Keep the last server snapshot visible during a brief connection loss.
    } finally {
      _syncing = false;
    }
  }

  @override
  Widget build(BuildContext context) {
    final isStaff = widget.user['role'] == 'staff';
    final drivePage = CloudFilesPage(
      api: widget.api,
      state: widget.state,
      onRefresh: widget.onRefresh,
    );
    final pages = isStaff
        ? [
            drivePage,
            SecurityOverviewPage(state: widget.state, staff: true),
            SimulationPage(
              state: widget.state,
              staff: true,
              onRun: widget.onRunSimulation,
            ),
            DefenseReportPage(state: widget.state, staff: true),
          ]
        : [
            drivePage,
            CustomerArchitecturePage(state: widget.state),
            DefenseReportPage(state: widget.state, staff: false),
          ];
    final titles = isStaff
        ? [
            'Your Cloud Workspace',
            'Security Overview',
            'Attack & Defense',
            'Defense report',
          ]
        : ['Your Cloud Workspace', 'Cloud Architecture', 'Defense report'];
    final destinations = isStaff
        ? const [
            NavigationDestination(
              icon: Icon(Icons.cloud_outlined),
              selectedIcon: Icon(Icons.cloud),
              label: 'Cloud',
            ),
            NavigationDestination(
              icon: Icon(Icons.shield_outlined),
              selectedIcon: Icon(Icons.shield),
              label: 'Overview',
            ),
            NavigationDestination(
              icon: Icon(Icons.bolt_outlined),
              selectedIcon: Icon(Icons.bolt),
              label: 'Simulation',
            ),
            NavigationDestination(
              icon: Icon(Icons.description_outlined),
              selectedIcon: Icon(Icons.description),
              label: 'Report',
            ),
          ]
        : const [
            NavigationDestination(
              icon: Icon(Icons.cloud_outlined),
              selectedIcon: Icon(Icons.cloud),
              label: 'Drive',
            ),
            NavigationDestination(
              icon: Icon(Icons.account_tree_outlined),
              selectedIcon: Icon(Icons.account_tree),
              label: 'Architecture',
            ),
            NavigationDestination(
              icon: Icon(Icons.description_outlined),
              selectedIcon: Icon(Icons.description),
              label: 'Reports',
            ),
          ];
    return Scaffold(
      appBar: AppBar(
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              titles[_tab],
              style: const TextStyle(fontSize: 17, fontWeight: FontWeight.w800),
            ),
            Text(
              '${widget.user['role'] == 'staff' ? 'Staff area · Primary DB' : 'Customer area · Customer DB'}',
              style: const TextStyle(fontSize: 11, color: Color(0xFF746A83)),
            ),
          ],
        ),
        actions: [
          IconButton(
            tooltip: 'Sync with Cloud-D',
            onPressed: _syncFromServer,
            icon: const Icon(Icons.sync),
          ),
          PopupMenuButton<String>(
            tooltip: 'Account',
            onSelected: (value) async {
              if (value == 'logout') await widget.onSignOut();
            },
            itemBuilder: (context) => [
              PopupMenuItem(
                enabled: false,
                child: Text(
                  '${widget.user['username'] ?? 'Cloud-D account'}\n${widget.user['email'] ?? ''}',
                ),
              ),
              const PopupMenuDivider(),
              const PopupMenuItem(
                value: 'logout',
                child: Row(
                  children: [
                    Icon(Icons.logout),
                    SizedBox(width: 10),
                    Text('Log out'),
                  ],
                ),
              ),
            ],
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: _Avatar(user: widget.user),
            ),
          ),
        ],
      ),
      body: IndexedStack(index: _tab, children: pages),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _tab,
        onDestinationSelected: (value) => setState(() => _tab = value),
        destinations: destinations,
      ),
    );
  }
}

class CloudFilesPage extends StatefulWidget {
  const CloudFilesPage({
    required this.api,
    required this.state,
    required this.onRefresh,
    super.key,
  });
  final CloudDApi api;
  final Map<String, dynamic> state;
  final Future<void> Function() onRefresh;

  @override
  State<CloudFilesPage> createState() => _CloudFilesPageState();
}

class _CloudFilesPageState extends State<CloudFilesPage> {
  String _view = 'My Drive';
  String _query = '';
  String? _folder;
  bool _busy = false;
  static const _views = ['My Drive', 'Recent', 'Starred', 'Trash'];

  void _message(String message) => ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(content: Text(message), behavior: SnackBarBehavior.floating),
  );

  Future<void> _newFolder() async {
    final controller = TextEditingController();
    final name = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Create folder'),
        content: TextField(
          controller: controller,
          autofocus: true,
          maxLength: 64,
          decoration: const InputDecoration(labelText: 'Folder name'),
          onSubmitted: (value) => Navigator.pop(context, value.trim()),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, controller.text.trim()),
            child: const Text('Create'),
          ),
        ],
      ),
    );
    controller.dispose();
    if (name == null || name.isEmpty) return;
    try {
      await widget.api.createFolder(name);
      await widget.onRefresh();
      if (mounted) _message('Folder created.');
    } catch (error) {
      if (mounted) _message(apiError(error));
    }
  }

  Future<String?> _duplicateChoice(
    String filename,
    List<Map<String, dynamic>> duplicates,
  ) async {
    final duplicate = duplicates.isEmpty
        ? <String, dynamic>{}
        : duplicates.first;
    return showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('A file with this name exists'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(filename, style: const TextStyle(fontWeight: FontWeight.w700)),
            const SizedBox(height: 12),
            Text(
              'Current: Version ${duplicate['version'] ?? 1} · ${byteLabel(duplicate['size_bytes'])}\nSaved ${displayDate(duplicate['created_at'])}',
            ),
            const SizedBox(height: 8),
            const Text(
              'Update keeps the existing file as version history. Replace removes the old version history.',
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          OutlinedButton(
            onPressed: () => Navigator.pop(context, 'replace'),
            child: const Text('Replace'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, 'new_version'),
            child: const Text('Update version'),
          ),
        ],
      ),
    );
  }

  Future<void> _upload() async {
    final folders = asMaps(widget.state['folders']);
    final folder =
        _folder ?? (folders.isNotEmpty ? '${folders.first['id']}' : null);
    if (folder == null || folder.isEmpty) {
      _message('Create or select a destination folder first.');
      return;
    }
    final pickedFiles = await FilePicker.pickFiles();
    if (pickedFiles.isEmpty) return;
    final total = pickedFiles.fold<int>(
      0,
      (sum, file) => sum + (file.lengthSync() ?? 0),
    );
    if (total > 10 * 1024 * 1024) {
      _message('Selected files must total 10 MB or less.');
      return;
    }
    setState(() => _busy = true);
    try {
      for (final file in pickedFiles) {
        final bytes = await file.readAsBytes();
        try {
          await widget.api.upload(
            folderId: folder,
            filename: file.name,
            bytes: bytes,
          );
        } on ApiFailure catch (error) {
          if (error.statusCode != 409) rethrow;
          final duplicates = asMaps(error.payload?['duplicates']);
          final choice = await _duplicateChoice(file.name, duplicates);
          if (choice == null) continue;
          await widget.api.upload(
            folderId: folder,
            filename: file.name,
            bytes: bytes,
            duplicateMode: choice,
          );
        }
      }
      await widget.onRefresh();
      if (mounted) _message('Upload complete.');
    } catch (error) {
      if (mounted) _message(apiError(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _driveAction(Map<String, dynamic> file, String action) async {
    try {
      await widget.api.updateDrive('${file['logical_id']}', action);
      await widget.onRefresh();
    } catch (error) {
      if (mounted) _message(apiError(error));
    }
  }

  Future<void> _download(Map<String, dynamic> file) async {
    try {
      final bytes = await widget.api.downloadFile('${file['id']}');
      await SharePlus.instance.share(
        ShareParams(
          files: [
            XFile.fromData(
              bytes,
              name: '${file['filename']}',
              mimeType: 'application/octet-stream',
            ),
          ],
          subject: '${file['filename']}',
        ),
      );
    } catch (error) {
      if (mounted) _message(apiError(error));
    }
  }

  Future<void> _versions(Map<String, dynamic> file) async {
    try {
      final result = await widget.api.fileVersions('${file['logical_id']}');
      final versions = asMaps(result['versions']);
      if (!mounted) return;
      await showModalBottomSheet<void>(
        context: context,
        isScrollControlled: true,
        showDragHandle: true,
        builder: (context) => SafeArea(
          child: Padding(
            padding: const EdgeInsets.fromLTRB(18, 0, 18, 20),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Version history · ${file['filename']}',
                  style: Theme.of(context).textTheme.titleLarge
                      ?.copyWith(fontWeight: FontWeight.w800),
                ),
                const SizedBox(height: 12),
                ...versions.map(
                  (version) => ListTile(
                    leading: Icon(
                      version['current'] == true
                          ? Icons.check_circle
                          : Icons.history,
                      color: version['current'] == true ? _teal : _purple,
                    ),
                    title: Text('Version ${version['version'] ?? '?'}'),
                    subtitle: Text(
                      '${displayDate(version['created_at'])} · ${byteLabel(version['size_bytes'])}',
                    ),
                    trailing: IconButton(
                      tooltip: 'Download version',
                      icon: const Icon(Icons.download_outlined),
                      onPressed: () async {
                        await _download({...file, 'id': version['id']});
                        if (context.mounted) Navigator.pop(context);
                      },
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      );
    } catch (error) {
      if (mounted) _message(apiError(error));
    }
  }

  @override
  Widget build(BuildContext context) {
    final files = asMaps(widget.state['files']);
    final folders = asMaps(widget.state['folders']);
    final current = files.where((file) {
      final trashed = file['trashed_at'] != null;
      if (_view == 'Trash' ? !trashed : trashed) return false;
      if (_view == 'Starred' && file['starred'] != true) return false;
      if (_folder != null && file['folder_id'] != _folder) return false;
      final search = _query.trim().toLowerCase();
      return search.isEmpty ||
          '${file['filename']} ${file['folder_name']}'.toLowerCase().contains(
            search,
          );
    }).toList();
    if (_view == 'Recent')
      current.sort(
        (a, b) => '${b['created_at']}'.compareTo('${a['created_at']}'),
      );
    final storage = asMap(widget.state['storage']);
    return RefreshIndicator(
      onRefresh: widget.onRefresh,
      child: ListView(
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
        children: [
          _WelcomeCard(
            title: 'Your Cloud Workspace',
            subtitle:
                'Upload documents and data to your encrypted ${widget.state['current_user']?['role'] == 'staff' ? 'Primary DB' : 'Customer DB'} area.',
            icon: Icons.cloud_done_outlined,
          ),
          const SizedBox(height: 14),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              _StatChip(
                icon: Icons.folder_outlined,
                label:
                    '${files.where((file) => file['trashed_at'] == null).length} files',
              ),
              _StatChip(
                icon: Icons.security_outlined,
                label: '${storage['encryption'] ?? 'AES-256-GCM'} encrypted',
              ),
            ],
          ),
          const SizedBox(height: 16),
          Row(
            children: [
              Expanded(
                child: Text(
                  'Files and folders',
                  style: Theme.of(context).textTheme.titleLarge
                      ?.copyWith(fontWeight: FontWeight.w800),
                ),
              ),
              IconButton(
                tooltip: 'Create folder',
                onPressed: _newFolder,
                icon: const Icon(Icons.create_new_folder_outlined),
              ),
              const SizedBox(width: 6),
              FilledButton.icon(
                onPressed: _busy ? null : _upload,
                icon: _busy
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          color: Colors.white,
                        ),
                      )
                    : const Icon(Icons.upload_file_outlined),
                label: const Text('Upload'),
              ),
            ],
          ),
          const SizedBox(height: 10),
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
              children: _views
                  .map(
                    (view) => Padding(
                      padding: const EdgeInsets.only(right: 7),
                      child: ChoiceChip(
                        label: Text(view),
                        selected: _view == view,
                        onSelected: (_) => setState(() => _view = view),
                      ),
                    ),
                  )
                  .toList(),
            ),
          ),
          const SizedBox(height: 10),
          TextField(
            decoration: const InputDecoration(
              hintText: 'Search files',
              prefixIcon: Icon(Icons.search),
            ),
            onChanged: (value) => setState(() => _query = value),
          ),
          if (folders.length > 1) ...[
            const SizedBox(height: 10),
            DropdownButtonFormField<String?>(
              initialValue: _folder,
              decoration: const InputDecoration(
                labelText: 'Destination folder',
                prefixIcon: Icon(Icons.folder_open_outlined),
              ),
              items: [
                const DropdownMenuItem<String?>(
                  value: null,
                  child: Text('All folders'),
                ),
                ...folders.map(
                  (folder) => DropdownMenuItem<String?>(
                    value: '${folder['id']}',
                    child: Text('${folder['name']}'),
                  ),
                ),
              ],
              onChanged: (value) => setState(() => _folder = value),
            ),
          ],
          if (_view == 'Trash') ...[
            const SizedBox(height: 10),
            const _InfoBanner('Trash is automatically cleared after 90 days.'),
          ],
          const SizedBox(height: 12),
          if (current.isEmpty)
            _EmptyCard(
              icon: Icons.cloud_queue_outlined,
              title: 'Nothing here yet',
              subtitle: _view == 'Trash'
                  ? 'Deleted files will appear here.'
                  : 'Upload a file or change the selected view.',
            ),
          ...current.map(
            (file) => Padding(
              padding: const EdgeInsets.only(bottom: 9),
              child: _FileCard(
                file: file,
                view: _view,
                onDownload: () => _download(file),
                onVersions: () => _versions(file),
                onStar: () => _driveAction(
                  file,
                  file['starred'] == true ? 'unstar' : 'star',
                ),
                onTrash: () => _driveAction(file, 'trash'),
                onRestore: () => _driveAction(file, 'restore'),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class SecurityOverviewPage extends StatelessWidget {
  const SecurityOverviewPage({
    required this.state,
    required this.staff,
    super.key,
  });
  final Map<String, dynamic> state;
  final bool staff;

  @override
  Widget build(BuildContext context) {
    if (!staff) return const _StaffOnlyPage();
    final metrics = asMap(state['metrics']);
    final nodes = asMaps(state['nodes']);
    final defenders = asMaps(state['defenders']);
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        const _WelcomeCard(
          title: 'Security Overview',
          subtitle: 'Cloud-D coordinates four defender agents around selected attack types.',
          icon: Icons.shield_outlined,
        ),
        const SizedBox(height: 14),
        _StatGrid(
          items: [
            _MetricData(
              'Attack block rate',
              metrics['block_rate'] == null
                  ? '—'
                  : '${(metrics['block_rate'] as num).toStringAsFixed(1)}%',
              Icons.gpp_good_outlined,
            ),
            _MetricData(
              'Data protected',
              metrics['protection_rate'] == null
                  ? '100%'
                  : '${(metrics['protection_rate'] as num).toStringAsFixed(3)}%',
              Icons.lock_outline,
            ),
            _MetricData(
              'Rounds',
              '${state['round'] ?? 0}/${state['max_rounds'] ?? 20}',
              Icons.replay_outlined,
            ),
            _MetricData(
              'Threats blocked',
              '${metrics['blocked'] ?? 0}',
              Icons.block_outlined,
            ),
          ],
        ),
        const SizedBox(height: 18),
        Text(
          'Defender agents',
          style: Theme.of(context).textTheme.titleLarge
              ?.copyWith(fontWeight: FontWeight.w800),
        ),
        const SizedBox(height: 10),
        ...defenders.map(
          (agent) => Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: _AgentRow(
              name: '${agent['name']}',
              subtitle:
                  '${agent['algorithm'] ?? 'Automated response'} · ${agent['active'] == true ? 'active' : 'ready'}',
              icon: Icons.shield_outlined,
            ),
          ),
        ),
        const SizedBox(height: 8),
        Text(
          'Cloud nodes',
          style: Theme.of(context).textTheme.titleLarge
              ?.copyWith(fontWeight: FontWeight.w800),
        ),
        const SizedBox(height: 10),
        ...nodes.map(
          (node) => Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: _AgentRow(
              name: '${node['name']}',
              subtitle:
                  '${node['status'] ?? 'HEALTHY'} · ${node['health'] ?? 100} health · ${node['uploaded_records'] ?? 0} uploaded records',
              icon: Icons.storage_outlined,
            ),
          ),
        ),
      ],
    );
  }
}

class CustomerArchitecturePage extends StatelessWidget {
  const CustomerArchitecturePage({required this.state, super.key});
  final Map<String, dynamic> state;

  @override
  Widget build(BuildContext context) {
    final notice = asMap(state['security_notice']);
    final securityMessage = notice.isEmpty
        ? 'Your assigned customer storage is ready. Security activity updates here when a simulation runs.'
        : 'Security event detected during round ${notice['round']}/${notice['max_rounds']}. Defender agents responded; the situation is under control.';
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        const _WelcomeCard(
          title: 'Cloud Architecture',
          subtitle: 'How Cloud-D routes and protects your files.',
          icon: Icons.account_tree_outlined,
        ),
        const SizedBox(height: 14),
        _SectionCard(
          title: 'Your secure file path',
          subtitle: 'Your account uses its assigned customer storage area.',
          child: Column(
            children: const [
              _ArchitectureStep(
                icon: Icons.verified_user_outlined,
                title: 'Your account',
                detail: 'Verified sign-in',
              ),
              _ArchitectureConnector(),
              _ArchitectureStep(
                icon: Icons.swap_horiz,
                title: 'Cloud-D API',
                detail: 'Routes authorized requests',
              ),
              _ArchitectureConnector(),
              _ArchitectureStep(
                icon: Icons.storage_outlined,
                title: 'Customer DB',
                detail: 'Your private file area',
              ),
              _ArchitectureConnector(),
              _ArchitectureStep(
                icon: Icons.backup_outlined,
                title: 'Recovery DB',
                detail: 'Encrypted recovery copy',
              ),
            ],
          ),
        ),
        const SizedBox(height: 14),
        _SectionCard(
          title: 'Storage and security',
          subtitle: 'Protection shared by the website and mobile app.',
          child: Column(
            children: const [
              _AgentRow(
                name: 'Primary and recovery storage',
                subtitle:
                    'Separate SQLite databases store and mirror file records.',
                icon: Icons.storage_outlined,
              ),
              _AgentRow(
                name: 'File encryption',
                subtitle: 'AES-256-GCM encrypts uploaded file contents and saved report snapshots.',
                icon: Icons.lock_outline,
              ),
              _AgentRow(
                name: 'Password protection',
                subtitle: 'Passwords are stored as salted scrypt hashes.',
                icon: Icons.password_outlined,
              ),
            ],
          ),
        ),
        const SizedBox(height: 14),
        _SectionCard(
          title: notice.isEmpty ? 'Cloud status' : 'Security activity',
          subtitle: 'Current status for your account.',
          child: _AgentRow(
            name: notice.isEmpty
                ? 'Your cloud is protected'
                : 'Defense response active',
            subtitle: securityMessage,
            icon: Icons.verified_user_outlined,
          ),
        ),
      ],
    );
  }
}

class _ArchitectureStep extends StatelessWidget {
  const _ArchitectureStep({
    required this.icon,
    required this.title,
    required this.detail,
  });
  final IconData icon;
  final String title;
  final String detail;

  @override
  Widget build(BuildContext context) => Container(
    width: double.infinity,
    padding: const EdgeInsets.all(14),
    decoration: BoxDecoration(
      color: const Color(0xFFF8F3FC),
      border: Border.all(color: _line),
      borderRadius: BorderRadius.circular(14),
    ),
    child: Row(
      children: [
        Icon(icon, color: _purple),
        const SizedBox(width: 12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(title, style: const TextStyle(fontWeight: FontWeight.w800)),
              Text(
                detail,
                style: const TextStyle(fontSize: 12, color: Color(0xFF746A83)),
              ),
            ],
          ),
        ),
      ],
    ),
  );
}

class _ArchitectureConnector extends StatelessWidget {
  const _ArchitectureConnector();
  @override
  Widget build(BuildContext context) => const Padding(
    padding: EdgeInsets.symmetric(vertical: 3),
    child: Icon(Icons.south, size: 17, color: _violet),
  );
}

class SimulationPage extends StatefulWidget {
  const SimulationPage({
    required this.state,
    required this.staff,
    required this.onRun,
    super.key,
  });
  final Map<String, dynamic> state;
  final bool staff;
  final Future<void> Function({
    required Map<String, dynamic> config,
    required int rounds,
  })
  onRun;

  @override
  State<SimulationPage> createState() => _SimulationPageState();
}

class _SimulationPageState extends State<SimulationPage> {
  final Set<String> _vectors = {'auth', 'flow', 'query', 'behavior'};
  int _rounds = 20;
  int _intensity = 5;
  double _threshold = .4;
  static const _attackers = {
    'auth': 'Credential-Bot',
    'flow': 'FloodSwarm',
    'query': 'Injector-X',
    'behavior': 'GhostUser',
  };

  Map<String, dynamic> get _config => {
    'active_vectors': _vectors.toList(),
    'intensity': _intensity,
    'threshold': _threshold,
  };

  @override
  Widget build(BuildContext context) {
    if (!widget.staff) return const _StaffOnlyPage();
    final attacks = asMaps(widget.state['attack_log']).reversed.toList();
    final proposals = asMaps(widget.state['proposals']);
    final isRunning = widget.state['_running'] == true;
    final latestEvent = attacks.isEmpty
        ? <String, dynamic>{}
        : asMap(attacks.first);
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        const _WelcomeCard(
          title: 'Attack & Defense Simulation',
          subtitle: 'Choose attacker agents. Cloud-D activates each matching defender automatically.',
          icon: Icons.bolt_outlined,
        ),
        const SizedBox(height: 14),
        _SectionCard(
          title: 'Simulation controls',
          subtitle: 'Attackers are user-selected; defenders are assigned by attack type.',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(
                'Simulation rounds · $_rounds',
                style: const TextStyle(fontWeight: FontWeight.w700),
              ),
              Slider(
                value: _rounds.toDouble(),
                min: 1,
                max: 20,
                divisions: 19,
                label: '$_rounds',
                onChanged: (value) => setState(() => _rounds = value.round()),
              ),
              const SizedBox(height: 12),
              Text(
                'Attack intensity · $_intensity / 10',
                style: const TextStyle(fontWeight: FontWeight.w700),
              ),
              Slider(
                value: _intensity.toDouble(),
                min: 1,
                max: 10,
                divisions: 9,
                label: '$_intensity / 10',
                onChanged: (value) =>
                    setState(() => _intensity = value.round()),
              ),
              const SizedBox(height: 16),
              Text(
                'Attackers to include',
                style: Theme.of(context).textTheme.titleMedium
                    ?.copyWith(fontWeight: FontWeight.w800),
              ),
              const SizedBox(height: 6),
              ..._attackers.entries.map(
                (entry) => CheckboxListTile(
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                  title: Text(entry.value),
                  value: _vectors.contains(entry.key),
                  onChanged: (value) => setState(
                    () => value == true
                        ? _vectors.add(entry.key)
                        : _vectors.remove(entry.key),
                  ),
                ),
              ),
              const _InfoBanner(
                'AuthSentinel, FlowGuardian, QueryShield, and BehaviorWatch respond automatically to selected attack types.',
              ),
              const SizedBox(height: 12),
              Text(
                'Decision threshold · ${_threshold.toStringAsFixed(2)}',
                style: Theme.of(context).textTheme.titleSmall
                    ?.copyWith(fontWeight: FontWeight.w700),
              ),
              Slider(
                value: _threshold,
                min: .1,
                max: .9,
                divisions: 80,
                label: _threshold.toStringAsFixed(2),
                onChanged: (value) => setState(() => _threshold = value),
              ),
              SizedBox(
                width: double.infinity,
                child: FilledButton.icon(
                  onPressed: isRunning
                      ? null
                      : () => widget.onRun(config: _config, rounds: _rounds),
                  icon: isRunning
                      ? const SizedBox(
                          height: 17,
                          width: 17,
                          child: CircularProgressIndicator(
                            strokeWidth: 2,
                            color: Colors.white,
                          ),
                        )
                      : const Icon(Icons.play_arrow),
                  label: Text(isRunning ? 'Running…' : 'Run simulation'),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        _AttackDefensePath(
          running: isRunning,
          attacker: '${latestEvent['attacker'] ?? 'Attacker station'}',
          defender:
              '${latestEvent['defender'] ?? latestEvent['assigned_defender'] ?? 'Automatic defender'}',
          target: '${latestEvent['target'] ?? 'Protected cloud'}',
        ),
        const SizedBox(height: 16),
        _SectionCard(
          title: 'Defense event stream',
          subtitle:
              '${stateRounds(widget.state)} rounds completed · ${attacks.length} recent events',
          child: attacks.isEmpty
              ? const Text('Run a simulation to see attack and defense events.')
              : Column(
                  children: attacks
                      .take(12)
                      .map(
                        (event) => _AgentRow(
                          name:
                              '${event['attacker'] ?? 'Threat'} · ${event['blocked'] == true ? 'blocked' : 'not blocked'}',
                          subtitle:
                              'Round ${event['round'] ?? 0} · ${event['action'] ?? 'No qualifying defense'} · ${event['target_name'] ?? event['target'] ?? ''}',
                          icon: event['blocked'] == true
                              ? Icons.verified_user_outlined
                              : Icons.warning_amber_outlined,
                        ),
                      )
                      .toList(),
                ),
        ),
        const SizedBox(height: 14),
        _SectionCard(
          title: 'Defender decisions',
          subtitle: 'Utility-ranked actions',
          child: proposals.isEmpty
              ? const Text('No defender proposals yet.')
              : Column(
                  children: proposals
                      .map(
                        (proposal) => _AgentRow(
                          name:
                              '${proposal['agent'] ?? proposal['defender'] ?? 'Defender'}',
                          subtitle:
                              'Utility ${(proposal['utility'] as num? ?? 0).toStringAsFixed(2)} · ${proposal['action'] ?? 'Monitoring'}',
                          icon: Icons.shield_outlined,
                        ),
                      )
                      .toList(),
                ),
        ),
      ],
    );
  }
}

class _AttackDefensePath extends StatelessWidget {
  const _AttackDefensePath({
    required this.running,
    required this.attacker,
    required this.defender,
    required this.target,
  });
  final bool running;
  final String attacker;
  final String defender;
  final String target;

  @override
  Widget build(BuildContext context) => _SectionCard(
    title: 'Attack and defense path',
    subtitle: 'Red threat reaches the firewall; the Python engine assigns a defender by target.',
    child: Column(
      children: [
        Row(
          children: [
            const Icon(Icons.bolt, color: Color(0xFFD94455)),
            Expanded(
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 450),
                height: 4,
                margin: const EdgeInsets.symmetric(horizontal: 7),
                color: running ? const Color(0xFFD94455) : _line,
              ),
            ),
            const Icon(Icons.security, color: _purple),
            Expanded(
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 450),
                height: 4,
                margin: const EdgeInsets.symmetric(horizontal: 7),
                color: running ? _teal : _line,
              ),
            ),
            const Icon(Icons.cloud_done_outlined, color: _teal),
          ],
        ),
        const SizedBox(height: 10),
        Row(
          children: [
            Expanded(
              child: Text(
                attacker,
                textAlign: TextAlign.center,
                style: const TextStyle(fontSize: 11),
              ),
            ),
            const Expanded(
              child: Text(
                'Firewall',
                textAlign: TextAlign.center,
                style: TextStyle(fontSize: 11),
              ),
            ),
            Expanded(
              child: Text(
                target,
                textAlign: TextAlign.center,
                style: const TextStyle(fontSize: 11),
              ),
            ),
          ],
        ),
        const SizedBox(height: 8),
        Align(
          alignment: Alignment.centerRight,
          child: Text(
            'Automatic response · $defender',
            style: const TextStyle(
              color: _teal,
              fontSize: 11,
              fontWeight: FontWeight.w700,
            ),
          ),
        ),
      ],
    ),
  );
}

int stateRounds(Map<String, dynamic> state) =>
    (state['round'] as num?)?.toInt() ?? 0;

class DefenseReportPage extends StatelessWidget {
  const DefenseReportPage({
    required this.state,
    required this.staff,
    super.key,
  });
  final Map<String, dynamic> state;
  final bool staff;

  @override
  Widget build(BuildContext context) {
    final reports = asMaps(state['saved_reports']);
    final metrics = asMap(state['metrics']);
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        const _WelcomeCard(
          title: 'Defense report',
          subtitle: 'Metrics update as Cloud-D processes each simulation run.',
          icon: Icons.summarize_outlined,
        ),
        const SizedBox(height: 14),
        _StatGrid(
          items: [
            _MetricData(
              'Run status',
              state['has_run'] == true ? 'Round ${state['round']}' : 'Not run',
              Icons.play_circle_outline,
            ),
            _MetricData(
              'Attacks',
              '${metrics['total_attacks'] ?? 0}',
              Icons.bolt_outlined,
            ),
            _MetricData(
              'Blocked',
              '${metrics['blocked'] ?? 0}',
              Icons.gpp_good_outlined,
            ),
            _MetricData(
              'Data protected',
              metrics['protection_rate'] == null
                  ? '—'
                  : '${(metrics['protection_rate'] as num).toStringAsFixed(3)}%',
              Icons.lock_outline,
            ),
          ],
        ),
        const SizedBox(height: 18),
        Text(
          'Saved simulation reports',
          style: Theme.of(context).textTheme.titleLarge
              ?.copyWith(fontWeight: FontWeight.w800),
        ),
        const SizedBox(height: 10),
        if (reports.isEmpty)
          const _EmptyCard(
            icon: Icons.description_outlined,
            title: 'No reports saved yet',
            subtitle: 'Run a simulation to create an encrypted report.',
          ),
        ...reports.map((item) {
          final payload = asMap(item['payload']);
          final reportMetrics = asMap(payload['metrics']);
          return Padding(
            padding: const EdgeInsets.only(bottom: 9),
            child: _AgentRow(
              name: 'Simulation · ${displayDate(item['created_at'])}',
              subtitle:
                  'Round ${payload['round'] ?? 0}/${payload['max_rounds'] ?? 20} · ${reportMetrics['blocked'] ?? 0} blocks · AES-256-GCM',
              icon: Icons.description_outlined,
            ),
          );
        }),
      ],
    );
  }
}

class _BrandHeader extends StatelessWidget {
  const _BrandHeader();
  @override
  Widget build(BuildContext context) => Row(
    children: [
      Container(
        width: 52,
        height: 52,
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(16),
          gradient: const LinearGradient(colors: [_purple, _violet]),
        ),
        child: const Icon(Icons.shield_outlined, color: Colors.white, size: 29),
      ),
      const SizedBox(width: 13),
      const Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Cloud-D',
            style: TextStyle(fontSize: 23, fontWeight: FontWeight.w900),
          ),
          Text(
            'SECURE CLOUD WORKSPACE',
            style: TextStyle(
              fontSize: 10,
              letterSpacing: 1.5,
              color: Color(0xFF776B89),
              fontWeight: FontWeight.w700,
            ),
          ),
        ],
      ),
    ],
  );
}

class _Avatar extends StatelessWidget {
  const _Avatar({required this.user});
  final Map<String, dynamic> user;
  @override
  Widget build(BuildContext context) {
    final username = '${user['username'] ?? 'N'}';
    final image = user['profile_picture']?.toString();
    Uint8List? bytes;
    if (image != null && image.contains(',')) {
      try {
        bytes = base64Decode(image.split(',').last);
      } catch (_) {}
    }
    return CircleAvatar(
      radius: 19,
      backgroundColor: const Color(0xFFE5D9FA),
      foregroundColor: _ink,
      backgroundImage: bytes == null ? null : MemoryImage(bytes),
      child: bytes == null
          ? Text(
              username.isEmpty ? 'N' : username.substring(0, 1).toUpperCase(),
              style: const TextStyle(fontWeight: FontWeight.w800),
            )
          : null,
    );
  }
}

class _WelcomeCard extends StatelessWidget {
  const _WelcomeCard({
    required this.title,
    required this.subtitle,
    required this.icon,
  });
  final String title;
  final String subtitle;
  final IconData icon;
  @override
  Widget build(BuildContext context) => Card(
    child: Padding(
      padding: const EdgeInsets.all(17),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 42,
            height: 42,
            decoration: BoxDecoration(
              color: const Color(0xFFF0EAF8),
              borderRadius: BorderRadius.circular(13),
            ),
            child: Icon(icon, color: _purple),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: const TextStyle(
                    fontWeight: FontWeight.w800,
                    fontSize: 17,
                  ),
                ),
                const SizedBox(height: 5),
                Text(
                  subtitle,
                  style: const TextStyle(color: Color(0xFF706780), height: 1.4),
                ),
              ],
            ),
          ),
        ],
      ),
    ),
  );
}

class _StatChip extends StatelessWidget {
  const _StatChip({required this.icon, required this.label});
  final IconData icon;
  final String label;
  @override
  Widget build(BuildContext context) => Chip(
    avatar: Icon(icon, size: 17, color: _purple),
    label: Text(label),
    backgroundColor: Colors.white,
    side: const BorderSide(color: _line),
  );
}

class _FileCard extends StatelessWidget {
  const _FileCard({
    required this.file,
    required this.view,
    required this.onDownload,
    required this.onVersions,
    required this.onStar,
    required this.onTrash,
    required this.onRestore,
  });
  final Map<String, dynamic> file;
  final String view;
  final VoidCallback onDownload;
  final VoidCallback onVersions;
  final VoidCallback onStar;
  final VoidCallback onTrash;
  final VoidCallback onRestore;
  @override
  Widget build(BuildContext context) {
    final isTrash = view == 'Trash';
    return Card(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(13, 12, 8, 8),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Container(
                  width: 38,
                  height: 38,
                  decoration: BoxDecoration(
                    color: const Color(0xFFF0EAF8),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Icon(
                    file['kind'] == 'data'
                        ? Icons.table_chart_outlined
                        : Icons.description_outlined,
                    color: _purple,
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    '${file['filename'] ?? 'File'}',
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(fontWeight: FontWeight.w700),
                  ),
                ),
                PopupMenuButton<String>(
                  onSelected: (value) {
                    if (value == 'download') onDownload();
                    if (value == 'versions') onVersions();
                    if (value == 'star') onStar();
                    if (value == 'trash') onTrash();
                    if (value == 'restore') onRestore();
                  },
                  itemBuilder: (context) => [
                    const PopupMenuItem(
                      value: 'download',
                      child: Text('Download'),
                    ),
                    if (!isTrash && (file['version_count'] as num? ?? 1) > 1)
                      const PopupMenuItem(
                        value: 'versions',
                        child: Text('Version history'),
                      ),
                    if (!isTrash)
                      PopupMenuItem(
                        value: 'star',
                        child: Text(
                          file['starred'] == true
                              ? 'Remove from starred'
                              : 'Add to starred',
                        ),
                      ),
                    PopupMenuItem(
                      value: isTrash ? 'restore' : 'trash',
                      child: Text(isTrash ? 'Restore' : 'Move to trash'),
                    ),
                  ],
                ),
              ],
            ),
            const SizedBox(height: 8),
            Text(
              '${file['folder_name'] ?? 'My Files'} · Version ${file['version'] ?? 1} · ${byteLabel(file['size_bytes'])}',
              style: const TextStyle(fontSize: 12, color: Color(0xFF706780)),
            ),
            const SizedBox(height: 3),
            Text(
              'Saved ${displayDate(file['created_at'])} · ${file['record_count'] ?? 0} records',
              style: const TextStyle(fontSize: 11, color: Color(0xFF827A8D)),
            ),
            if (file['backup_available'] == true)
              const Padding(
                padding: EdgeInsets.only(top: 7),
                child: _StatusPill(label: 'Encrypted backup ready'),
              ),
          ],
        ),
      ),
    );
  }
}

class _StatusPill extends StatelessWidget {
  const _StatusPill({required this.label});
  final String label;
  @override
  Widget build(BuildContext context) => DecoratedBox(
    decoration: BoxDecoration(
      color: const Color(0xFFE6F5EF),
      borderRadius: BorderRadius.circular(99),
    ),
    child: Padding(
      padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5),
      child: Text(
        label,
        style: const TextStyle(
          color: Color(0xFF287A60),
          fontSize: 10,
          fontWeight: FontWeight.w700,
        ),
      ),
    ),
  );
}

class _AgentRow extends StatelessWidget {
  const _AgentRow({
    required this.name,
    required this.subtitle,
    required this.icon,
  });
  final String name;
  final String subtitle;
  final IconData icon;
  @override
  Widget build(BuildContext context) => Card(
    child: ListTile(
      leading: CircleAvatar(
        backgroundColor: const Color(0xFFF0EAF8),
        foregroundColor: _purple,
        child: Icon(icon, size: 20),
      ),
      title: Text(
        name,
        style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 14),
      ),
      subtitle: Text(
        subtitle,
        maxLines: 2,
        overflow: TextOverflow.ellipsis,
        style: const TextStyle(fontSize: 12, height: 1.4),
      ),
    ),
  );
}

class _MetricData {
  const _MetricData(this.label, this.value, this.icon);
  final String label;
  final String value;
  final IconData icon;
}

class _StatGrid extends StatelessWidget {
  const _StatGrid({required this.items});
  final List<_MetricData> items;
  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, constraints) {
      final columns = constraints.maxWidth < 400 ? 1 : 2;
      return GridView.count(
        shrinkWrap: true,
        physics: const NeverScrollableScrollPhysics(),
        crossAxisCount: columns,
        crossAxisSpacing: 9,
        mainAxisSpacing: 9,
        childAspectRatio: columns == 1 ? 3.5 : 1.6,
        children: items
            .map(
              (item) => Card(
                child: Padding(
                  padding: const EdgeInsets.all(13),
                  child: Row(
                    children: [
                      CircleAvatar(
                        backgroundColor: const Color(0xFFF0EAF8),
                        foregroundColor: _purple,
                        child: Icon(item.icon),
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Text(
                              item.label,
                              style: const TextStyle(
                                fontSize: 11,
                                color: Color(0xFF756D80),
                              ),
                            ),
                            const SizedBox(height: 3),
                            Text(
                              item.value,
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: const TextStyle(
                                fontWeight: FontWeight.w800,
                                fontSize: 17,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            )
            .toList(),
      );
    },
  );
}

class _SectionCard extends StatelessWidget {
  const _SectionCard({
    required this.title,
    required this.subtitle,
    required this.child,
  });
  final String title;
  final String subtitle;
  final Widget child;
  @override
  Widget build(BuildContext context) => Card(
    child: Padding(
      padding: const EdgeInsets.all(15),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(
            title,
            style: const TextStyle(fontWeight: FontWeight.w800, fontSize: 17),
          ),
          const SizedBox(height: 4),
          Text(
            subtitle,
            style: const TextStyle(
              color: Color(0xFF756D80),
              fontSize: 12,
              height: 1.4,
            ),
          ),
          const SizedBox(height: 14),
          child,
        ],
      ),
    ),
  );
}

class _InfoBanner extends StatelessWidget {
  const _InfoBanner(this.text);
  final String text;
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.all(11),
    decoration: BoxDecoration(
      color: const Color(0xFFF1ECF8),
      borderRadius: BorderRadius.circular(12),
    ),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Icon(Icons.info_outline, size: 18, color: _purple),
        const SizedBox(width: 8),
        Expanded(
          child: Text(
            text,
            style: const TextStyle(
              color: Color(0xFF56496A),
              fontSize: 12,
              height: 1.4,
            ),
          ),
        ),
      ],
    ),
  );
}

class _EmptyCard extends StatelessWidget {
  const _EmptyCard({
    required this.icon,
    required this.title,
    required this.subtitle,
  });
  final IconData icon;
  final String title;
  final String subtitle;
  @override
  Widget build(BuildContext context) => Card(
    child: Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        children: [
          Icon(icon, size: 34, color: _purple),
          const SizedBox(height: 8),
          Text(title, style: const TextStyle(fontWeight: FontWeight.w800)),
          const SizedBox(height: 4),
          Text(
            subtitle,
            textAlign: TextAlign.center,
            style: const TextStyle(color: Color(0xFF756D80)),
          ),
        ],
      ),
    ),
  );
}

class _ErrorBanner extends StatelessWidget {
  const _ErrorBanner(this.text);
  final String text;
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.all(12),
    decoration: BoxDecoration(
      color: const Color(0xFFFFEEEC),
      borderRadius: BorderRadius.circular(12),
      border: Border.all(color: const Color(0xFFF1C6C2)),
    ),
    child: Text(
      text,
      style: const TextStyle(color: Color(0xFF9C3934), height: 1.4),
    ),
  );
}

class _StaffOnlyPage extends StatelessWidget {
  const _StaffOnlyPage();
  @override
  Widget build(BuildContext context) => const Center(
    child: Padding(
      padding: EdgeInsets.all(25),
      child: _EmptyCard(
        icon: Icons.lock_outline,
        title: 'Staff workspace',
        subtitle: 'Sign in with a staff account to access the security overview, simulation controls, and defense reports.',
      ),
    ),
  );
}
