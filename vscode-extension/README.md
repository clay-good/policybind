# PolicyBind VS Code Extension

Language support, validation, and IntelliSense for PolicyBind AI governance policy files.

## Features

### Schema Validation
- Real-time validation of policy YAML files
- Error highlighting with detailed messages
- Validates against the official PolicyBind schema

### IntelliSense & Autocompletion
- Smart completions for actions, providers, operators, and more
- Context-aware suggestions based on cursor position
- Auto-complete for match conditions and action parameters

### Hover Documentation
- Hover over any keyword to see documentation
- Includes examples and valid values
- Links to official documentation

### Snippets
- Quick templates for common policy patterns
- Create full policy sets or individual rules with a few keystrokes
- Includes best-practice patterns like "deny PII to external", "rate limiting", etc.

### Syntax Highlighting
- Custom syntax highlighting for policy files
- Color-coded actions (ALLOW=green, DENY=red, etc.)
- Distinct highlighting for operators, providers, and values

### Commands
- **PolicyBind: Validate File** - Validate the current policy file
- **PolicyBind: Validate All Policies in Workspace** - Validate all policy files
- **PolicyBind: Create New Policy Set** - Generate a new policy set from template
- **PolicyBind: Create New Rule** - Insert a new rule at cursor position
- **PolicyBind: Show Documentation** - Open PolicyBind documentation

## Installation

### From VS Code Marketplace
1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X)
3. Search for "PolicyBind"
4. Click Install

### Manual Installation
1. Download the `.vsix` file from the releases page
2. In VS Code, go to Extensions
3. Click the "..." menu and select "Install from VSIX..."
4. Select the downloaded file

### From Source
```bash
cd vscode-extension
npm install
npm run compile
code --install-extension policybind-0.1.0.vsix
```

## Usage

### File Patterns
The extension automatically activates for files matching:
- `*.policy.yaml`
- `*.policy.yml`
- `policies/*.yaml`
- `policies/*.yml`

### Using Snippets
Type any of these prefixes and press Tab:
- `policyset` - Create a new policy set
- `pbrule` - Create a new rule
- `pbdeny` - Create a deny rule
- `pballow` - Create an allow rule
- `pbratelimit` - Create a rate limiting rule
- `pbapproval` - Create an approval-required rule
- `pbmodify` - Create a modify rule (e.g., PII redaction)
- `pbaudit` - Create an audit rule

### Quick Patterns
- `pb-deny-pii-external` - Deny PII data to external providers
- `pb-gpt4-engineering` - Restrict GPT-4 to engineering department
- `pb-business-hours` - Restrict usage to business hours
- `pb-cost-limit` - Apply daily cost limits

## Configuration

Access settings via File > Preferences > Settings, then search for "PolicyBind".

| Setting | Default | Description |
|---------|---------|-------------|
| `policybind.validation.enabled` | `true` | Enable/disable validation |
| `policybind.validation.onSave` | `true` | Validate on file save |
| `policybind.validation.onType` | `true` | Validate while typing |
| `policybind.hover.enabled` | `true` | Show hover documentation |
| `policybind.completion.enabled` | `true` | Enable IntelliSense |
| `policybind.filePatterns` | See below | File patterns to recognize |

Default file patterns:
```json
[
  "**/*.policy.yaml",
  "**/*.policy.yml",
  "**/policies/*.yaml",
  "**/policies/*.yml"
]
```

## Example Policy File

```yaml
name: production-policies
version: 1.0.0
description: Production AI governance policies

metadata:
  author: security-team
  environment: production
  compliance:
    - SOC2
    - GDPR

rules:
  # Deny PII data to external AI providers
  - name: deny-pii-external
    description: Block PII data from going to external providers
    priority: 100
    enabled: true
    match_conditions:
      data_classification:
        contains: pii
    action: DENY
    action_params:
      reason: PII data cannot be sent to external AI providers

  # Rate limit expensive models
  - name: rate-limit-gpt4
    description: Apply rate limits to GPT-4 usage
    priority: 80
    enabled: true
    match_conditions:
      model:
        contains: gpt-4
    action: RATE_LIMIT
    action_params:
      rate_limit:
        requests_per_hour: 100
        cost_per_day: 50.00

  # Allow all other requests
  - name: allow-default
    description: Default allow rule
    priority: 0
    enabled: true
    match_conditions: {}
    action: ALLOW
```

## Development

### Building
```bash
npm install
npm run compile
```

### Testing
```bash
npm run test
```

### Packaging
```bash
npm run package
```

This creates `policybind-X.X.X.vsix` in the extension directory.

### Publishing
```bash
npm run publish
```

Requires a Visual Studio Marketplace publisher account and token.

## Troubleshooting

### Validation not working
1. Check that validation is enabled in settings
2. Ensure the file matches one of the configured patterns
3. Try running "PolicyBind: Validate File" command manually

### IntelliSense not appearing
1. Ensure the file is recognized as a policy file
2. Check that completions are enabled in settings
3. Make sure you're in a valid YAML context

### Extension not activating
1. Check the file extension matches the patterns
2. Look for activation events in the Output panel
3. Try reloading the window (Ctrl+Shift+P > "Reload Window")

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please see the main PolicyBind repository for contribution guidelines.

## Support

- [Documentation](https://policybind.io/docs)
- [GitHub Issues](https://github.com/clay-good/policybind/issues)
- [Discussions](https://github.com/clay-good/policybind/discussions)
