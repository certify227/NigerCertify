import 'package:flutter/material.dart';

import '../theme/app_theme.dart';

class CodeEditorWidget extends StatefulWidget {
  final String initialCode;
  final ValueChanged<String> onChanged;
  final String? output;
  final String? error;
  final VoidCallback onRun;
  final bool isRunning;

  const CodeEditorWidget({
    super.key,
    required this.initialCode,
    required this.onChanged,
    required this.onRun,
    this.output,
    this.error,
    this.isRunning = false,
  });

  @override
  State<CodeEditorWidget> createState() => _CodeEditorWidgetState();
}

class _CodeEditorWidgetState extends State<CodeEditorWidget> {
  late final TextEditingController _controller;

  @override
  void initState() {
    super.initState();
    _controller = TextEditingController(text: widget.initialCode);
    _controller.addListener(() => widget.onChanged(_controller.text));
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Container(
          decoration: BoxDecoration(
            color: const Color(0xFF1E1E1E),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: const Color(0xFF333333)),
          ),
          child: TextField(
            controller: _controller,
            maxLines: 10,
            style: const TextStyle(
              fontFamily: 'monospace',
              fontSize: 14,
              color: Color(0xFFD4D4D4),
            ),
            decoration: const InputDecoration(
              contentPadding: EdgeInsets.all(16),
              border: InputBorder.none,
              hintText: '# Écrivez votre code Python ici',
              hintStyle: TextStyle(color: Color(0xFF666666)),
            ),
          ),
        ),
        const SizedBox(height: 10),
        OutlinedButton.icon(
          onPressed: widget.isRunning ? null : widget.onRun,
          icon: widget.isRunning
              ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
              : const Icon(Icons.play_arrow, color: AppTheme.primaryBlue),
          label: const Text('Exécuter'),
          style: OutlinedButton.styleFrom(
            foregroundColor: AppTheme.primaryBlue,
            side: const BorderSide(color: AppTheme.primaryBlue),
          ),
        ),
        if (widget.output != null && widget.output!.isNotEmpty) ...[
          const SizedBox(height: 10),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: const Color(0xFF1E1E1E),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Text(
              widget.output!,
              style: const TextStyle(fontFamily: 'monospace', color: Color(0xFF4EC9B0), fontSize: 13),
            ),
          ),
        ],
        if (widget.error != null && widget.error!.isNotEmpty) ...[
          const SizedBox(height: 8),
          Text(widget.error!, style: const TextStyle(color: AppTheme.primaryRed, fontSize: 13)),
        ],
      ],
    );
  }
}
