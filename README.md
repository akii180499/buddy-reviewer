# 🤖 AI-Assisted Mulesoft Code Review Plugin

A comprehensive code review tool for Mulesoft applications that combines programmatic checks with AI-assisted analysis to ensure code quality, security, and architectural best practices.

## ✨ Features

- 🔍 **Programmatic Code Analysis** - Automated checks for Mulesoft-specific issues
- 🤖 **AI-Powered Review** - GPT-4 based intelligent code analysis
- 🏗️ **Architectural Analysis** - Solution architect-level design review
- 📊 **Quality Scoring** - Weighted severity-based quality metrics
- 🎯 **Risk Assessment** - Dynamic risk level determination
- 📦 **Dependency Analysis** - Vulnerability scanning and version checking
- 💬 **GitHub Integration** - Automatic PR commenting with detailed feedback
- 🎨 **Beautiful Reporting** - Circular gauge visualization with color-coded risk levels

## 📋 Requirements

- Python 3.8+
- GitHub Personal Access Token
- OpenAI API Key

### Required Python Packages

```bash
pip install --break-system-packages pygithub requests openai python-dotenv
```

## 🚀 Usage

### Method 1: Command-Line Arguments (Recommended)

```bash
python mulesoft_code_review_complete.py \
    --repo "username/repository-name" \
    --github-token "your_github_token" \
    --openai-key "your_openai_key"
```

### Method 2: Environment Variables

Create a `.env` file:

```env
GITHUB_TOKEN=your_github_token_here
OPENAI_API_KEY=your_openai_api_key_here
REPO_NAME=username/repository-name
```

Then run:

```bash
python mulesoft_code_review_complete.py
```

### Method 3: GitHub Actions (CI/CD)

The tool automatically detects `GITHUB_REPOSITORY` environment variable in GitHub Actions:

```yaml
name: Mulesoft Code Review

on:
  pull_request:
    types: [opened, synchronize]

jobs:
  code-review:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install dependencies
        run: |
          pip install pygithub requests openai python-dotenv
      
      - name: Run Mulesoft Code Review
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          python mulesoft_code_review_complete.py
```

### Method 4: Mixed Approach

You can mix environment variables and command-line arguments. Command-line arguments take precedence:

```bash
# Set tokens in .env file
export GITHUB_TOKEN=your_token
export OPENAI_API_KEY=your_key

# Specify repo via command line
python mulesoft_code_review_complete.py --repo "username/my-repo"
```

## 🎯 Command-Line Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `--repo` | Repository name in `owner/repo` format | `--repo "john/my-mulesoft-app"` |
| `--github-token` | GitHub Personal Access Token | `--github-token "ghp_xxxxx"` |
| `--openai-key` | OpenAI API Key | `--openai-key "sk-xxxxx"` |

## 🔐 Environment Variables

The tool supports multiple environment variable names for flexibility:

| Variable | Alternative | Description |
|----------|-------------|-------------|
| `GITHUB_TOKEN` | - | GitHub Personal Access Token |
| `OPENAI_API_KEY` | - | OpenAI API Key |
| `REPO_NAME` | `GITHUB_REPOSITORY` | Repository name (owner/repo) |

## 📊 What Gets Analyzed

### Code Quality Checks

#### XML Files
- ✅ AutoDiscovery configuration
- ✅ HTTP request configurations (hardcoded URLs, IP addresses)
- ✅ Error handler presence
- ✅ Flow complexity (component count)
- ✅ Flows per file limit
- ✅ HTTP listener configurations
- ✅ Logger best practices
- ✅ Database query optimization
- ✅ Global element placement
- ✅ Interface file structure

#### Properties Files
- ✅ Empty file detection
- ✅ Naming convention compliance
- ✅ Key format validation

#### YAML Files
- ✅ Empty file detection
- ✅ API specification validation

#### DataWeave Files
- ✅ Naming convention (msg/var prefix)
- ✅ File organization

#### POM.xml
- ✅ Dependency version analysis
- ✅ Security vulnerability detection (CVEs)
- ✅ Outdated dependency identification
- ✅ MUnit configuration check
- ✅ Deployment configuration

### Architectural Analysis

- 🏗️ API Layer Pattern (SAPI/PAPI/EAPI)
- 🎨 Design Pattern Identification
- 📈 Scalability Considerations
- 🔄 Integration Pattern Analysis
- 🧹 Code Maintainability
- 💡 Architecture Recommendations

## 📈 Quality Scoring

### Severity Weights

| Severity | Weight | Impact |
|----------|--------|--------|
| 🔴 Critical | 30 points | Security vulnerabilities, deployment blockers |
| 🟠 High | 20 points | Best practice violations, performance issues |
| 🟡 Medium | 10 points | Code quality issues, maintainability concerns |
| 🟢 Low | 5 points | Minor improvements, style issues |
| ℹ️ Info | 2 points | Informational notices, suggestions |

### Risk Levels

| Score Range | Risk Level | Description |
|-------------|------------|-------------|
| 90-100 | 🟢 MINIMAL | Excellent code quality |
| 75-89 | 🟡 LOW | Good with minor issues |
| 50-74 | 🟠 MEDIUM | Moderate improvements needed |
| 25-49 | 🔴 HIGH | Significant issues present |
| 0-24 | 🔴 CRITICAL | Critical issues must be addressed |

**Note:** Any critical issue automatically results in CRITICAL risk level.

## 🎨 Output Example

The tool generates a comprehensive GitHub PR comment with:

1. **Quality Score Gauge** - Circular visualization with color-coded risk level
2. **Summary** - Total issues breakdown by severity
3. **Build Status** - Pass/Warning/Fail determination
4. **Detailed Issues** - File-by-file analysis with:
   - Issue severity and title
   - Problematic code snippet
   - Why it's an issue (reasons)
   - How to fix it (with code examples)
5. **Architectural Analysis** - Design review for solution architects
6. **Dependency Analysis** - Table of all dependencies with update recommendations
7. **Security Requirements** - Full compliance checklist

## 🛠️ Example Scenarios

### Scenario 1: Local Development Review

```bash
# Review your current branch before pushing
python mulesoft_code_review_complete.py \
    --repo "mycompany/payments-api" \
    --github-token "$GITHUB_TOKEN" \
    --openai-key "$OPENAI_KEY"
```

### Scenario 2: CI/CD Pipeline

```bash
# In your Jenkins/GitLab CI script
export REPO_NAME="${CI_PROJECT_PATH}"
python mulesoft_code_review_complete.py
```

### Scenario 3: Multiple Repositories

```bash
#!/bin/bash
# Review multiple repos
REPOS=("team/api-layer" "team/process-layer" "team/system-layer")

for repo in "${REPOS[@]}"; do
    echo "Reviewing $repo..."
    python mulesoft_code_review_complete.py --repo "$repo"
done
```

## 🔧 Customization

### Modify Security Requirements

Edit the `SECURITY_REQUIREMENTS` variable in the `main()` function to add/remove checks:

```python
SECURITY_REQUIREMENTS = """
Your custom requirements here...
"""
```

### Adjust Severity Weights

Modify the `SEVERITY_WEIGHTS` in `QualityScoreCalculator` class:

```python
SEVERITY_WEIGHTS = {
    'critical': 30,  # Adjust these values
    'high': 20,
    'medium': 10,
    'low': 5,
    'info': 2
}
```

## 📝 GitHub Token Setup

1. Go to GitHub Settings → Developer settings → Personal access tokens
2. Generate new token (classic)
3. Select scopes:
   - `repo` (Full control of private repositories)
   - `write:discussion` (Read/write access to discussions)
4. Copy the token and use it

## 🔑 OpenAI API Key Setup

1. Go to https://platform.openai.com/api-keys
2. Create new secret key
3. Copy the key and use it

## 🐛 Troubleshooting

### "No open pull requests found"
- Ensure there's at least one open PR in the repository
- Check that your GitHub token has access to the repo

### "Error analyzing file with LLM"
- Verify your OpenAI API key is valid
- Check your OpenAI account has available credits

### "Invalid repository name format"
- Repository name must be in `owner/repo` format
- Example: `mycompany/my-api-project` ✅
- Example: `my-api-project` ❌

### Rate Limiting
- GitHub API: 5000 requests/hour for authenticated requests
- OpenAI API: Depends on your plan tier

## 📄 License

This tool is provided as-is for code review purposes.

## 🤝 Contributing

To extend the tool:

1. Add new checker classes inheriting from `BaseCodeChecker`
2. Implement the `check()` method
3. Add your checker to `CodeAnalyzer.__init__()`

Example:

```python
class CustomFileChecker(BaseCodeChecker):
    def check(self, file_name: str, file_content: str, all_files: Dict[str, str]) -> List[CodeIssue]:
        issues = []
        # Your custom logic here
        return issues
```

## 📞 Support

For issues or questions:
- Check the troubleshooting section
- Review the example scenarios
- Ensure all requirements are met

## 🎓 Best Practices

1. **Run early and often** - Review code before merging
2. **Address critical issues first** - Focus on security and deployment blockers
3. **Use architectural feedback** - Leverage solution architect insights
4. **Keep dependencies updated** - Regularly review the dependency table
5. **Customize for your team** - Adjust requirements and weights as needed

---

**Happy Coding! 🚀**

