"""
Mulesoft Code Review Plugin

A comprehensive code review tool for Mulesoft applications that performs
both programmatic checks and AI-assisted analysis.
"""

import os
import re
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

import requests
from github import Github
from github.Repository import Repository
from github.PullRequest import PullRequest
from github.PaginatedList import PaginatedList
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()


@dataclass
class CodeIssue:
    """Represents a code quality issue."""
    severity: str
    title: str
    code: str
    reasons: List[str]
    fix: str


class GithubClient:
    """Manages GitHub API client connection."""

    def __init__(self, token: str):
        self._token = token
        self._client: Optional[Github] = None

    def get_client(self) -> Github:
        """Returns a GitHub client object (lazy initialization)."""
        if self._client is None:
            self._client = Github(self._token)
        return self._client


class GithubRepository:
    """Manages operations on a specific GitHub repository."""

    def __init__(self, github_client: GithubClient, repo_name: str):
        self._github_client = github_client
        self._repo_name = repo_name
        self._repo: Optional[Repository] = None

    def get_repository(self) -> Repository:
        """Returns a repository object (lazy initialization)."""
        if self._repo is None:
            client = self._github_client.get_client()
            self._repo = client.get_repo(self._repo_name)
        return self._repo


class PullRequestManager:
    """Manages pull request operations for a repository."""

    def __init__(self, repository: GithubRepository):
        self._repository = repository

    def get_latest_open_pr(self) -> PullRequest:
        """
        Fetches the most recently created open pull request.

        Returns:
            PullRequest: The latest open pull request.

        Raises:
            ValueError: If no open pull requests are found.
        """
        repo = self._repository.get_repository()
        open_prs = repo.get_pulls(state="open", sort="created", direction="desc")

        try:
            return open_prs[0]
        except (IndexError, StopIteration):
            raise ValueError(
                f"No open pull requests found in repository '{repo.full_name}'"
            )

    def get_pr_files(self, pr: PullRequest) -> Dict[str, str]:
        """
        Fetches all relevant files from a pull request.

        Args:
            pr: The pull request object.

        Returns:
            Dict mapping filenames to their content.
        """
        file_contents = {}
        files = pr.get_files()
        relevant_extensions = ('.xml', '.dw', '.yaml', '.yml', '.dwl', '.properties')

        for file in files:
            if file.filename.endswith(relevant_extensions) or file.filename == 'pom.xml':
                try:
                    file_contents[file.filename] = requests.get(file.raw_url).text
                except Exception as e:
                    print(f"Error fetching {file.filename}: {str(e)}")

        return file_contents


class BaseCodeChecker(ABC):
    """Abstract base class for code checkers."""

    @abstractmethod
    def check(self, file_name: str, file_content: str, all_files: Dict[str, str]) -> List[CodeIssue]:
        """
        Check code for issues.

        Args:
            file_name: Name of the file being checked.
            file_content: Content of the file.
            all_files: All files in the PR for cross-file checks.

        Returns:
            List of CodeIssue objects found.
        """
        pass


class XMLCodeChecker(BaseCodeChecker):
    """Checks XML files for Mulesoft-specific issues."""

    NAMESPACES = {
        'mule': 'http://www.mulesoft.org/schema/mule/core',
        'http': 'http://www.mulesoft.org/schema/mule/http',
        'db': 'http://www.mulesoft.org/schema/mule/db',
        'apikit': 'http://www.mulesoft.org/schema/mule/mule-apikit',
        'api-gateway': 'http://www.mulesoft.org/schema/mule/api-gateway',
        'doc': 'http://www.mulesoft.org/schema/mule/documentation'
    }

    def check(self, file_name: str, file_content: str, all_files: Dict[str, str]) -> List[CodeIssue]:
        """Check XML files for Mulesoft issues."""
        if not file_name.endswith('.xml'):
            return []

        issues = []
        try:
            root = ET.fromstring(file_content)

            issues.extend(self._check_autodiscovery(root, file_name))
            issues.extend(self._check_http_requests(root))
            issues.extend(self._check_error_handlers(root))
            issues.extend(self._check_flow_complexity(root))
            issues.extend(self._check_flows_per_file(root, file_name))
            issues.extend(self._check_http_listeners(root))
            issues.extend(self._check_loggers(root))
            issues.extend(self._check_database_queries(root))
            issues.extend(self._check_database_config(root))
            issues.extend(self._check_global_elements(root, file_name))
            issues.extend(self._check_interface_listeners(root, file_name))

        except ET.ParseError as e:
            issues.append(CodeIssue(
                severity='Critical',
                title='XML parsing error',
                code=str(e),
                reasons=[
                    'XML file is malformed and cannot be parsed',
                    'File will fail deployment',
                    'Syntax errors must be fixed immediately'
                ],
                fix='Fix XML syntax errors. Use an XML validator or IDE to identify the issue.'
            ))

        return issues

    def _check_autodiscovery(self, root: ET.Element, file_name: str) -> List[CodeIssue]:
        """Check for AutoDiscovery configuration."""
        issues = []
        autodiscovery_elements = root.findall(
            './/{http://www.mulesoft.org/schema/mule/api-gateway}autodiscovery'
        )

        if (not autodiscovery_elements and
                'interface' not in file_name.lower() and
                'api' in file_name.lower()):
            issues.append(CodeIssue(
                severity='High',
                title='Missing AutoDiscovery configuration',
                code='<!-- No api-gateway:autodiscovery element found -->',
                reasons=[
                    'API will not be registered in API Manager',
                    'Violates: "Use AutoDiscovery to register API in API Manager (High)"',
                    'Without AutoDiscovery, policies cannot be applied and API cannot be managed'
                ],
                fix='''Add AutoDiscovery configuration in your main/interface XML:
```xml
<api-gateway:autodiscovery 
    apiId="${api.id}" 
    flowRef="api-main" 
    doc:name="API Autodiscovery"/>
```
And add the api.id property in your properties files.'''
            ))

        return issues

    def _check_http_requests(self, root: ET.Element) -> List[CodeIssue]:
        """Check HTTP request configurations."""
        issues = []
        http_requests = root.findall('.//{http://www.mulesoft.org/schema/mule/http}request')

        for req in http_requests:
            url = req.get('url', '')
            host = req.get('host', '')

            # Check for hardcoded URLs
            if url and ('http://' in url or 'https://' in url) and '${' not in url:
                issues.append(CodeIssue(
                    severity='High',
                    title='Hardcoded URL in HTTP request',
                    code=f'<http:request url="{url}" ... />',
                    reasons=[
                        'Hardcoded URLs are not environment-specific and cause deployment issues',
                        'Violates: "Sensitive global config values must come from properties files (Critical)"',
                        'Cannot be changed without code modification'
                    ],
                    fix=f'''Move URL to properties file and reference it:
```xml
<http:request url="${{target.url}}" ... />
```
In properties file:
```
target.url={url}
```'''
                ))

            # Check for IP addresses
            if host and re.match(r'\d+\.\d+\.\d+\.\d+', host):
                issues.append(CodeIssue(
                    severity='High',
                    title='IP address used instead of domain name',
                    code=f'<http:request host="{host}" ... />',
                    reasons=[
                        'IP addresses are not portable across environments',
                        'Violates: "Host must be a domain name, not an IP address (High)"',
                        'Makes configuration management difficult'
                    ],
                    fix='''Use a domain name and parameterize it:
```xml
<http:request host="${target.host}" ... />
```'''
                ))

        return issues

    def _check_error_handlers(self, root: ET.Element) -> List[CodeIssue]:
        """Check for error handlers in flows."""
        issues = []
        flows = root.findall('.//{http://www.mulesoft.org/schema/mule/core}flow')

        for flow in flows:
            error_handler = flow.find('{http://www.mulesoft.org/schema/mule/core}error-handler')
            if error_handler is None:
                flow_name = flow.get('name', 'Unknown')
                issues.append(CodeIssue(
                    severity='High',
                    title=f'Missing error handler in flow "{flow_name}"',
                    code=f'<flow name="{flow_name}">...</flow> <!-- No error-handler -->',
                    reasons=[
                        'Without error handling, exceptions will propagate uncaught',
                        'Violates: "Configure global error handler using configuration element (High)"',
                        'Cannot provide meaningful error responses to clients'
                    ],
                    fix=f'''Add error handler to the flow:
```xml
<flow name="{flow_name}">
    <!-- flow content -->
    <error-handler>
        <on-error-propagate type="ANY">
            <logger level="ERROR" message="#[error.description]" />
            <!-- Handle error appropriately -->
        </on-error-propagate>
    </error-handler>
</flow>
```'''
                ))

        return issues

    def _check_flow_complexity(self, root: ET.Element) -> List[CodeIssue]:
        """Check flow complexity based on number of components."""
        issues = []
        flows = root.findall('.//{http://www.mulesoft.org/schema/mule/core}flow')

        for flow in flows:
            component_count = len(list(flow))
            if component_count > 10:
                flow_name = flow.get('name', 'Unknown')
                issues.append(CodeIssue(
                    severity='High',
                    title=f'Flow "{flow_name}" has too many components ({component_count})',
                    code=f'<flow name="{flow_name}"> <!-- {component_count} components -->',
                    reasons=[
                        f'Flow has {component_count} components, exceeding the recommended limit of 10',
                        'Violates: "Create flows with fewer than 10 components (High)"',
                        'Complex flows are harder to maintain and test'
                    ],
                    fix='''Break down the flow into smaller sub-flows:
```xml
<flow name="main-flow">
    <flow-ref name="validation-subflow"/>
    <flow-ref name="processing-subflow"/>
    <flow-ref name="response-subflow"/>
</flow>

<sub-flow name="validation-subflow">
    <!-- validation logic -->
</sub-flow>
```'''
                ))

        return issues

    def _check_flows_per_file(self, root: ET.Element, file_name: str) -> List[CodeIssue]:
        """Check number of flows per file."""
        issues = []
        flows = root.findall('.//{http://www.mulesoft.org/schema/mule/core}flow')

        if len(flows) > 10:
            issues.append(CodeIssue(
                severity='High',
                title=f'Too many flows in single file ({len(flows)} flows)',
                code=f'<!-- {len(flows)} flows found in {file_name} -->',
                reasons=[
                    f'File contains {len(flows)} flows, exceeding the recommended limit of 10',
                    'Violates: "Less than 10 flows per configuration XML is recommended (High)"',
                    'Large files are difficult to navigate and maintain'
                ],
                fix='''Split flows into multiple files by domain or functionality:
- interface.xml (HTTP listeners)
- implementation.xml (business logic)
- error-handlers.xml (error handling)'''
            ))

        return issues

    def _check_http_listeners(self, root: ET.Element) -> List[CodeIssue]:
        """Check HTTP listener configurations."""
        issues = []
        http_listeners = root.findall('.//{http://www.mulesoft.org/schema/mule/http}listener')

        for listener in http_listeners:
            config_ref = listener.get('config-ref', '')
            if not config_ref:
                issues.append(CodeIssue(
                    severity='High',
                    title='HTTP Listener without config-ref',
                    code=ET.tostring(listener, encoding='unicode')[:200],
                    reasons=[
                        'HTTP Listener must reference a valid configuration',
                        'Flow will fail to deploy without proper HTTP configuration',
                        'Cannot configure host, port, and other HTTP settings'
                    ],
                    fix='''Add config-ref to HTTP Listener:
```xml
<http:listener config-ref="HTTP_Listener_config" path="/api/*" />
```'''
                ))

            # Check for allowed methods
            allowed_methods = listener.get('allowedMethods', '')
            if not allowed_methods:
                issues.append(CodeIssue(
                    severity='Medium',
                    title='HTTP Listener without specified allowed methods',
                    code=ET.tostring(listener, encoding='unicode')[:200],
                    reasons=[
                        'All HTTP methods will be allowed by default (security risk)',
                        'Violates: "Specify permitted HTTP Listener methods (Medium)"',
                        'May allow unintended HTTP methods like DELETE, PUT on read-only endpoints'
                    ],
                    fix='''Specify allowed methods explicitly:
```xml
<http:listener config-ref="HTTP_Listener_config" 
    path="/api/*" 
    allowedMethods="GET,POST" />
```'''
                ))

        return issues

    def _check_loggers(self, root: ET.Element) -> List[CodeIssue]:
        """Check logger configurations."""
        issues = []
        loggers = root.findall('.//{http://www.mulesoft.org/schema/mule/core}logger')

        for logger in loggers:
            message = logger.get('message', '')

            # Check for DataWeave in loggers
            if '#[' in message and ('payload' in message or 'dw::' in message):
                issues.append(CodeIssue(
                    severity='Medium',
                    title='DataWeave expression used in Logger',
                    code=f'<logger message="{message}" />',
                    reasons=[
                        'DataWeave in loggers impacts performance',
                        'Violates: "Avoid using DataWeave in Logger components (Medium)"',
                        'Payload evaluation happens even when log level is disabled'
                    ],
                    fix='''Use simple references or move complex logic outside:
```xml
<set-variable variableName="logMessage" value="#[payload.id]"/>
<logger message="Processing ID: #[vars.logMessage]" />
```'''
                ))

            # Check for sensitive data
            message_lower = message.lower()
            sensitive_keywords = ['password', 'secret', 'token', 'key', 'credential', 'ssn', 'credit']
            if any(keyword in message_lower for keyword in sensitive_keywords):
                issues.append(CodeIssue(
                    severity='Critical',
                    title='Potential sensitive data in logger',
                    code=f'<logger message="{message}" />',
                    reasons=[
                        'Logging sensitive data is a severe security violation',
                        'Violates: "Sensitive client data must not be logged or traced (Critical)"',
                        'May expose passwords, tokens, or PII in log files'
                    ],
                    fix='''Remove sensitive data from logs or mask it:
```xml
<logger message="User authenticated: #[vars.userId]" />
<!-- Do NOT log: password, token, ssn, etc -->
```'''
                ))

        return issues

    def _check_database_queries(self, root: ET.Element) -> List[CodeIssue]:
        """Check database query configurations."""
        issues = []
        db_selects = root.findall('.//{http://www.mulesoft.org/schema/mule/db}select')

        for select in db_selects:
            query_text = ''.join(select.itertext()).strip()
            if 'SELECT *' in query_text.upper():
                issues.append(CodeIssue(
                    severity='High',
                    title='Database query using SELECT *',
                    code=query_text[:200],
                    reasons=[
                        'SELECT * retrieves unnecessary columns and impacts performance',
                        'Violates: "Parameterize DB queries and avoid SELECT * (High)"',
                        'Schema changes can break the application unexpectedly'
                    ],
                    fix='''Specify explicit columns:
```xml
<db:select>
    <db:sql>SELECT id, name, email FROM users WHERE id = :userId</db:sql>
    <db:input-parameters>#[{userId: vars.userId}]</db:input-parameters>
</db:select>
```'''
                ))

        return issues

    def _check_database_config(self, root: ET.Element) -> List[CodeIssue]:
        """Check database configuration for hardcoded values."""
        issues = []
        db_configs = root.findall('.//{http://www.mulesoft.org/schema/mule/db}config')

        for db_config in db_configs:
            # Check generic-connection for hardcoded values
            generic_conn = db_config.find('.//{http://www.mulesoft.org/schema/mule/db}generic-connection')
            
            if generic_conn is not None:
                url = generic_conn.get('url', '')
                user = generic_conn.get('user', '')
                password = generic_conn.get('password', '')
                
                # Check if URL is hardcoded (not using property placeholder)
                if url and '${' not in url and ('jdbc:' in url or 'mysql://' in url or 'postgresql://' in url or 'oracle:' in url):
                    issues.append(CodeIssue(
                        severity='High',
                        title='Hardcoded database URL in configuration',
                        code=f'url="{url}"',
                        reasons=[
                            'Database URL is hardcoded instead of using property placeholders',
                            'Violates: "Sensitive global config values must come from properties files (Critical)"',
                            'Makes it impossible to change database connection per environment'
                        ],
                        fix=f'''Move database URL to properties file:
```xml
<db:generic-connection url="${{db.url}}" ... />
```
In properties file:
```
db.url={url}
```'''
                    ))
                
                # Check if user is hardcoded
                if user and '${' not in user and user != '':
                    issues.append(CodeIssue(
                        severity='High',
                        title='Hardcoded database user in configuration',
                        code=f'user="{user}"',
                        reasons=[
                            'Database username is hardcoded instead of using property placeholders',
                            'Violates: "Sensitive global config values must come from properties files (Critical)"',
                            'Security risk and makes environment-specific configuration difficult'
                        ],
                        fix=f'''Move database user to properties file:
```xml
<db:generic-connection user="${{db.user}}" ... />
```
In properties file:
```
db.user={user}
```'''
                    ))
                
                # Check if password is hardcoded
                if password and '${' not in password and password != '':
                    issues.append(CodeIssue(
                        severity='Critical',
                        title='Hardcoded database password in configuration',
                        code='password="****"',
                        reasons=[
                            'Database password is hardcoded - SEVERE SECURITY VIOLATION',
                            'Violates: "Sensitive global config values must come from properties files (Critical)"',
                            'Exposes credentials in source code, major security risk'
                        ],
                        fix='''Move database password to secure properties:
```xml
<db:generic-connection password="${secure::db.password}" ... />
```
Use Mule Secure Configuration Properties for sensitive data.'''
                    ))

        return issues

    def _check_global_elements(self, root: ET.Element, file_name: str) -> List[CodeIssue]:
        """Check for global configuration elements placement."""
        issues = []

        if 'global' not in file_name.lower():
            global_elements = root.findall('.//{http://www.mulesoft.org/schema/mule/http}listener-config')
            global_elements += root.findall('.//{http://www.mulesoft.org/schema/mule/db}config')

            if global_elements:
                issues.append(CodeIssue(
                    severity='High',
                    title='Global configuration elements in non-global file',
                    code=f'<!-- Found {len(global_elements)} global config elements -->',
                    reasons=[
                        'Global configurations should be centralized in global-config.xml',
                        'Violates: "All global elements must exist in global config file (High)"',
                        'Scattered configurations are harder to manage'
                    ],
                    fix='''Move all config elements to global-config.xml:
```xml
<!-- global-config.xml -->
<http:listener-config name="HTTP_Listener_config" .../>
<db:config name="Database_Config" .../>
```'''
                ))

        return issues

    def _check_interface_listeners(self, root: ET.Element, file_name: str) -> List[CodeIssue]:
        """Check interface file for multiple HTTP listeners."""
        issues = []
        http_listeners = root.findall('.//{http://www.mulesoft.org/schema/mule/http}listener')

        if 'interface' in file_name.lower() and len(http_listeners) > 1:
            issues.append(CodeIssue(
                severity='High',
                title=f'Multiple HTTP Listeners in interface file ({len(http_listeners)} found)',
                code=f'<!-- {len(http_listeners)} HTTP Listeners found -->',
                reasons=[
                    'Interface file should have only one HTTP Listener',
                    'Violates: "Only one HTTP Listener allowed in interface file (High)"',
                    'Multiple listeners complicate API management'
                ],
                fix='Keep only one HTTP Listener in interface.xml and use flow-ref for routing'
            ))

        return issues


class PropertiesFileChecker(BaseCodeChecker):
    """Checks .properties files for issues."""

    def check(self, file_name: str, file_content: str, all_files: Dict[str, str]) -> List[CodeIssue]:
        """Check properties files for issues."""
        if not file_name.endswith('.properties'):
            return []

        issues = []

        # Check for empty files
        if not file_content or file_content.strip() == '':
            issues.append(CodeIssue(
                severity='Medium',
                title='Empty properties file',
                code=f'{file_name} is empty',
                reasons=[
                    'Empty properties files serve no purpose',
                    'Violates: ".properties files must not be empty (Medium)"',
                    'May indicate missing configuration'
                ],
                fix='Add required properties or remove the empty file.'
            ))
        else:
            # Check property key naming conventions
            lines = file_content.split('\n')
            for line in lines:
                if '=' in line and not line.strip().startswith('#'):
                    key = line.split('=')[0].strip()
                    if not re.match(r'^[a-z][a-z0-9.]*$', key):
                        issues.append(CodeIssue(
                            severity='Info',
                            title=f'Property key does not follow naming convention: {key}',
                            code=line,
                            reasons=[
                                'Property keys should be lowercase and dot-separated',
                                'Violates: ".properties keys must be lowercase and dot-separated (Info)"',
                                'Inconsistent naming makes properties harder to find'
                            ],
                            fix=f'Rename to lowercase with dots: {key.lower()}'
                        ))

        return issues


class YAMLFileChecker(BaseCodeChecker):
    """Checks .yaml/.yml files for issues."""

    def check(self, file_name: str, file_content: str, all_files: Dict[str, str]) -> List[CodeIssue]:
        """Check YAML files for issues."""
        if not file_name.endswith(('.yaml', '.yml')):
            return []

        issues = []

        # Check for empty files
        if not file_content or file_content.strip() == '':
            issues.append(CodeIssue(
                severity='High',
                title='Empty YAML file',
                code=f'{file_name} is empty',
                reasons=[
                    'Empty YAML files will cause parsing errors',
                    'Violates: ".yaml files must not be empty (High)"',
                    'API specification or configuration is missing'
                ],
                fix='Add valid YAML content or remove the file.'
            ))

        return issues


class DWLFileChecker(BaseCodeChecker):
    """Checks .dwl (DataWeave) files for issues."""

    def check(self, file_name: str, file_content: str, all_files: Dict[str, str]) -> List[CodeIssue]:
        """Check DWL files for issues."""
        if not file_name.endswith('.dwl'):
            return []

        issues = []
        base_name = os.path.basename(file_name)

        # Check naming convention
        if not (base_name.startswith('msg') or base_name.startswith('var')):
            issues.append(CodeIssue(
                severity='Medium',
                title='DWL filename does not follow convention',
                code=f'File: {file_name}',
                reasons=[
                    'DWL files should start with "msg" or "var"',
                    'Violates: "DWL filenames must start with msg or var and follow conventions (Medium)"',
                    'Naming convention helps identify the purpose of the transformation'
                ],
                fix='Rename file to start with msg (for message transformations) or var (for variable transformations)'
            ))

        return issues


class POMFileChecker(BaseCodeChecker):
    """Checks pom.xml files for dependency issues."""

    def check(self, file_name: str, file_content: str, all_files: Dict[str, str]) -> List[CodeIssue]:
        """Check POM files for issues."""
        if file_name != 'pom.xml':
            return []

        # POM checks are primarily handled by LLM
        # This is a placeholder for any programmatic POM checks
        return []


class CodeAnalyzer:
    """Coordinates all code checkers."""

    def __init__(self):
        self.checkers: List[BaseCodeChecker] = [
            XMLCodeChecker(),
            PropertiesFileChecker(),
            YAMLFileChecker(),
            DWLFileChecker(),
            POMFileChecker()
        ]

    def analyze(self, file_name: str, file_content: str, all_files: Dict[str, str]) -> List[CodeIssue]:
        """
        Run all applicable checkers on a file.

        Args:
            file_name: Name of the file.
            file_content: Content of the file.
            all_files: All files in the PR.

        Returns:
            List of all issues found.
        """
        all_issues = []
        for checker in self.checkers:
            issues = checker.check(file_name, file_content, all_files)
            all_issues.extend(issues)
        return all_issues


class DesignAnalyzer:
    """Analyzes architectural and design patterns in Mulesoft applications."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.client = OpenAI(api_key=api_key)

    def analyze_architecture(self, all_files: Dict[str, str]) -> str:
        """
        Perform architectural analysis for solution architects.

        Args:
            all_files: All files in the PR.

        Returns:
            Architecture analysis report.
        """
        # Categorize files
        xml_files = [f for f in all_files.keys() if f.endswith('.xml')]
        properties_files = [f for f in all_files.keys() if f.endswith('.properties')]
        dwl_files = [f for f in all_files.keys() if f.endswith('.dwl')]
        yaml_files = [f for f in all_files.keys() if f.endswith(('.yaml', '.yml'))]
        pom_file = 'pom.xml' in all_files

        # Build file structure summary
        file_structure = f"""
**File Structure:**
- XML Configuration Files: {len(xml_files)}
- Properties Files: {len(properties_files)}
- DataWeave Files: {len(dwl_files)}
- YAML/API Specs: {len(yaml_files)}
- POM File: {'Yes' if pom_file else 'No'}
"""

        # Sample key files for analysis (limit to prevent token overflow)
        key_files_content = ""
        for file_name in xml_files[:3]:  # Analyze first 3 XML files
            key_files_content += f"\n\n--- {file_name} ---\n{all_files[file_name][:2000]}"  # Limit content

        prompt = f"""
You are a Senior Solution Architect specializing in MuleSoft integration architecture. 
Analyze the following MuleSoft application from an architectural perspective.

{file_structure}

Key Files Content (sample):
{key_files_content}

Provide a comprehensive architectural analysis covering:

1. **API Layer Pattern**: Identify if this follows SAPI/PAPI/EAPI pattern. What layer does this represent?

2. **Design Patterns**: Identify design patterns used (or missing):
   - Separation of concerns (interface vs implementation)
   - Error handling strategy
   - Configuration management
   - Reusability patterns (sub-flows, flow-refs)

3. **Scalability Considerations**:
   - Potential bottlenecks
   - Performance considerations
   - Resource management

4. **Integration Patterns**:
   - Synchronous vs Asynchronous
   - API-led connectivity compliance
   - Message transformation approach

5. **Maintainability**:
   - Code organization
   - Modularity
   - Documentation

6. **Recommendations**:
   - Architectural improvements
   - Best practices alignment
   - Refactoring suggestions

Format your response in clear sections with markdown headers.
Be specific and reference actual patterns found in the code.
"""

        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a Senior MuleSoft Solution Architect with expertise in API-led connectivity and enterprise integration patterns."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=2000,
                temperature=0.3
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error performing architectural analysis: {str(e)}"


class LLMAnalyzer:
    """Handles AI-assisted code analysis using OpenAI."""

    def __init__(self, api_key: str, security_requirements: str):
        self.api_key = api_key
        self.security_requirements = security_requirements
        self.client = OpenAI(api_key=api_key)

    def analyze_file(self, file_name: str, file_content: str, programmatic_issues: List[CodeIssue]) -> str:
        """
        Analyze code using LLM.

        Args:
            file_name: Name of the file.
            file_content: Content of the file.
            programmatic_issues: Issues already found programmatically.

        Returns:
            LLM feedback as a string.
        """
        programmatic_issues_text = self._format_programmatic_issues(programmatic_issues)
        is_pom_file = file_name.endswith('pom.xml')

        prompt = self._build_prompt(file_name, file_content, programmatic_issues_text, is_pom_file)

        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a helpful Mulesoft code review assistant. You provide detailed, actionable feedback with code examples."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=3000 if is_pom_file else 2000,
                temperature=0.2
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error analyzing file {file_name} with LLM: {str(e)}"

    def _format_programmatic_issues(self, issues: List[CodeIssue]) -> str:
        """Format programmatic issues for LLM prompt."""
        if not issues:
            return ""

        text = "\n\nPROGRAMMATIC CHECKS ALREADY FOUND THESE ISSUES:\n"
        for issue in issues:
            text += f"- [{issue.severity}] {issue.title}\n"
        text += "\nDo NOT repeat these issues. Focus on OTHER violations and best practices.\n"
        return text

    def _build_prompt(self, file_name: str, file_content: str, 
                     programmatic_issues_text: str, is_pom_file: bool) -> str:
        """Build the appropriate prompt based on file type."""
        if is_pom_file:
            return f"""
You are an expert Mulesoft developer and security specialist. Review the following pom.xml file for dependency issues, updates, and vulnerabilities:

File: {file_name}
Code:
{file_content}

Security Requirements:
{self.security_requirements}
{programmatic_issues_text}

CRITICAL TASKS FOR POM.XML:
1. Analyze ALL dependencies in the file
2. Identify outdated dependencies and suggest latest stable versions
3. Flag known security vulnerabilities (CVEs) in current versions
4. Check for deprecated Mulesoft runtime versions
5. Verify MUnit test coverage configuration exists
6. Check deployment configuration for CloudHub/On-Premise

For EACH issue found, format your response EXACTLY as follows:

[SEVERITY: Critical|High|Medium|Low|Info] <Brief title of the issue>

**Code:**
```xml
<Show the problematic dependency/configuration>
```

**Why it's <severity>:**
- <Reason 1 - explain the impact>
- <Reason 2 - explain what requirement it violates or vulnerability it exposes>
- <Reason 3 - explain the risk if not fixed>

**Fix:**
- <Step-by-step instructions on how to fix>
```xml
<corrected code here>
```

---

MANDATORY: AFTER all issues, you MUST provide a DEPENDENCY UPDATE TABLE. 
Even if there are no issues, you MUST analyze ALL dependencies and provide the table.

## 📦 Dependency Analysis

| Dependency | Current Version | Latest Version | Risk Level | Vulnerabilities | Recommendation |
|------------|----------------|----------------|------------|-----------------|----------------|
| groupId:artifactId | x.x.x | y.y.y | 🔴/🟠/🟡/🟢 | CVE-XXXX-XXXX or None | Update/Keep/Review |

Example rows:
| org.mule.connectors:mule-http-connector | 1.5.0 | 1.7.3 | 🟠 HIGH | CVE-2023-1234 | Update to 1.7.3 |
| com.mulesoft.munit:munit-runner | 2.3.0 | 2.3.15 | 🟢 LOW | None | Consider update |

IMPORTANT: 
- ALWAYS include the dependency table - this is MANDATORY
- Analyze EVERY dependency in the pom.xml
- Research actual latest versions for each dependency
- Be specific about security risks and CVEs
- Mark risk level with emojis: 🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, 🟢 LOW
- If a dependency is up-to-date, still include it in the table with 🟢 LOW
"""
        else:
            return f"""
You are an expert Mulesoft developer. Review the following code for best practices, potential issues, and improvements:

File: {file_name}
Code:
{file_content}

Security Requirements:
{self.security_requirements}
{programmatic_issues_text}

Focus on:
- Proper use of error handling (<error-handler>)
- Avoiding hardcoded values (use properties files)
- Proper use of DataWeave transformations
- Adding <logger> for debugging and monitoring
- Logical flaws in flow design, such as unnecessary components or inefficient logic
- Missing or incorrect configurations
- Violations of Mulesoft best practices

CRITICAL RULES FOR HARDCODED VALUES:
1. Property placeholders like ${{property.name}} are CORRECT and should NOT be flagged as hardcoded
2. Examples of CORRECT usage:
   - url="${{database.url}}" ✓ CORRECT
   - user="${{db.user}}" ✓ CORRECT
   - host="${{api.host}}" ✓ CORRECT
3. Examples of INCORRECT (hardcoded) usage:
   - url="jdbc:mysql://localhost:3306/db" ✗ HARDCODED
   - user="admin" ✗ HARDCODED
   - password="secret123" ✗ HARDCODED
4. DO NOT flag configurations that already use property placeholders (${{...}})
5. ONLY flag values that are actual hardcoded strings without property placeholders

For EACH issue found, format your response EXACTLY as follows:

[SEVERITY: Critical|High|Medium|Low|Info] <Brief title of the issue>

**Code:**
```
<Show the problematic code snippet here>
```

**Why it's <severity>:**
- <Reason 1 - explain the impact>
- <Reason 2 - explain what requirement it violates>
- <Reason 3 - explain the risk if not fixed>

**Fix:**
- <Step-by-step instructions on how to fix>
- <Show the corrected code snippet if applicable>
```
<corrected code here>
```

---

IMPORTANT: 
- Provide the actual code snippets from the file
- Be very specific about what's wrong and why
- Always include the fix with example code
- If no issues are found, respond with "No issues found."
- DO NOT flag property placeholders (${{...}}) as hardcoded values
"""

    @staticmethod
    def parse_feedback(feedback: str) -> Dict[str, List[str]]:
        """
        Parse LLM feedback to extract issues by severity.

        Args:
            feedback: Raw LLM feedback string.

        Returns:
            Dictionary mapping severity levels to lists of issues.
        """
        issues_by_severity = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }

        pattern = r'\[SEVERITY:\s*(Critical|High|Medium|Low|Info)\]\s*(.+?)(?=\[SEVERITY:|$)'
        matches = re.findall(pattern, feedback, re.IGNORECASE | re.DOTALL)

        for severity, description in matches:
            severity_key = severity.lower()
            if severity_key in issues_by_severity:
                cleaned_description = description.strip()
                issues_by_severity[severity_key].append(cleaned_description)

        return issues_by_severity


class QualityScoreCalculator:
    """Calculates code quality scores based on issues."""

    # Updated weights for more significant impact
    SEVERITY_WEIGHTS = {
        'critical': 30,
        'high': 20,
        'medium': 10,
        'low': 4,
        'info': 1
    }

    @staticmethod
    def calculate_score(all_issues: List[Dict]) -> Tuple[float, Dict[str, int]]:
        """
        Calculate quality score and issue counts.

        Args:
            all_issues: List of issue dictionaries per file.

        Returns:
            Tuple of (score, issue_counts).
        """
        total_deduction = 0
        issue_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        for file_issues in all_issues:
            for severity, issues in file_issues['issues_by_severity'].items():
                count = len(issues)
                issue_counts[severity] += count
                total_deduction += count * QualityScoreCalculator.SEVERITY_WEIGHTS[severity]

        base_score = 100
        score = max(0, base_score - total_deduction)

        return round(score, 1), issue_counts

    @staticmethod
    def get_risk_level(score: float, issue_counts: Dict[str, int]) -> str:
        """
        Determine risk level based on score and issues.

        Args:
            score: Quality score.
            issue_counts: Count of issues by severity.

        Returns:
            Risk level string.
        """
        # Priority-based risk determination
        if issue_counts['critical'] > 0:
            return 'CRITICAL'
        elif issue_counts['high'] >= 5:
            return 'CRITICAL'
        elif issue_counts['high'] >= 3 or score < 30:
            return 'HIGH'
        elif issue_counts['high'] > 0 or issue_counts['medium'] >= 5 or score < 60:
            return 'MEDIUM'
        elif issue_counts['medium'] > 0 or score < 80:
            return 'LOW'
        else:
            return 'MINIMAL'


class ReviewCommentFormatter:
    """Formats review comments for GitHub."""

    @staticmethod
    def generate_score_table(risk_level: str, score: float, issue_counts: Dict[str, int]) -> str:
        """Generate tabular structure for quality metrics."""
        # Color/emoji mapping based on risk level
        risk_emoji_map = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'MINIMAL': '✅'
        }
        
        risk_emoji = risk_emoji_map.get(risk_level, '⚪')
        
        # Generate progress bar
        filled = int(score / 5)  # 20 blocks total (100/5)
        empty = 20 - filled
        progress_bar = '█' * filled + '░' * empty
        
        # Calculate total issues
        total_issues = sum(issue_counts.values())
        
        table = f'''
## 📊 Code Quality Metrics

| Metric | Value | Details |
|--------|-------|---------|
| **Quality Score** | **{score}/100** | {progress_bar} |
| **Risk Level** | **{risk_emoji} {risk_level}** | Overall code quality assessment |
| **🔴 Critical Issues** | {issue_counts['critical']} | Security vulnerabilities, deployment blockers |
| **🟠 High Issues** | {issue_counts['high']} | Best practice violations, performance issues |
| **🟡 Medium Issues** | {issue_counts['medium']} | Code quality issues, maintainability concerns |
| **🟢 Low Issues** | {issue_counts['low']} | Minor improvements, style issues |
| **ℹ️ Info Issues** | {issue_counts['info']} | Informational notices, suggestions |
| **📋 Total Issues** | **{total_issues}** | All issues found in this review |
'''
        return table.strip()

    @staticmethod
    def format_comment(all_issues: List[Dict], score: float, 
                      risk_level: str, issue_counts: Dict[str, int],
                      security_requirements: str, design_analysis: str = None) -> str:
        """
        Format the complete review comment.

        Args:
            all_issues: All issues found.
            score: Quality score.
            risk_level: Risk level.
            issue_counts: Issue counts by severity.
            security_requirements: Security requirements text.
            design_analysis: Architectural analysis for solution architects.

        Returns:
            Formatted comment string.
        """
        # Use new tabular format instead of gauge
        score_table = ReviewCommentFormatter.generate_score_table(risk_level, score, issue_counts)

        feedback_details = ""
        issue_number = 1

        for issue_data in all_issues:
            file_name = issue_data['file']
            feedback_details += f"\n## 📄 `{file_name}`\n\n"

            has_issues = False
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                issues = issue_data['issues_by_severity'][severity]
                if issues:
                    has_issues = True
                    severity_emoji = {
                        'critical': '🔴',
                        'high': '🟠',
                        'medium': '🟡',
                        'low': '🟢',
                        'info': 'ℹ️'
                    }[severity]

                    for issue in issues:
                        feedback_details += f"### {issue_number}) {severity_emoji} **{severity.upper()}** Severity\n\n"
                        feedback_details += f"{issue}\n\n"
                        feedback_details += "---\n\n"
                        issue_number += 1

            if not has_issues:
                feedback_details += "✅ **No issues found.**\n\n"

        if issue_counts['critical'] > 0:
            policy_message = "❌ **Build FAILED**: Critical severity issues detected."
        elif issue_counts['high'] >= 3:
            policy_message = "⚠️ **Build WARNING**: Multiple high severity issues detected."
        else:
            policy_message = "✅ **Build PASSED**: No critical issues found."

        # Add design analysis section if available
        design_section = ""
        if design_analysis:
            design_section = f"""
---

## 🏗️ Architectural & Design Analysis
<details>
<summary>📐 Click to view Solution Architect Review</summary>

{design_analysis}

</details>

"""

        comment_body = f"""
# 🤖 AI-Assisted Mulesoft Code Review

{score_table}

### {policy_message}

---

{feedback_details}

{design_section}

<details>
<summary>📋 View Security Requirements Checked</summary>

```
{security_requirements}
```

</details>

---
*Review generated automatically by Mulesoft Code Review Plugin*
*Includes programmatic validation + AI analysis + architectural review*
"""
        return comment_body


class MulesoftCodeReviewPlugin:
    """Main plugin orchestrating the code review process."""

    def __init__(self, repo_name: str, github_token: str, 
                 openai_api_key: str, security_requirements: str):
        self.repo_name = repo_name
        self.security_requirements = security_requirements

        # Initialize components
        self.github_client = GithubClient(github_token)
        self.repository = GithubRepository(self.github_client, repo_name)
        self.pr_manager = PullRequestManager(self.repository)
        self.code_analyzer = CodeAnalyzer()
        self.llm_analyzer = LLMAnalyzer(openai_api_key, security_requirements)
        self.design_analyzer = DesignAnalyzer(openai_api_key)

    def analyze_code(self, file_contents: Dict[str, str]) -> Tuple[List[Dict], float, str, Dict[str, int], str]:
        """
        Analyze all files in the PR.

        Args:
            file_contents: Dictionary of file names to contents.

        Returns:
            Tuple of (all_issues, score, risk_level, issue_counts, design_analysis).
        """
        all_issues = []

        for filename, content in file_contents.items():
            print(f"Analyzing {filename}...")

            # Programmatic checks
            programmatic_issues = self.code_analyzer.analyze(filename, content, file_contents)
            programmatic_issues_dict = self._convert_issues_to_severity_dict(programmatic_issues)

            # LLM analysis
            llm_feedback = self.llm_analyzer.analyze_file(filename, content, programmatic_issues)
            llm_issues_dict = LLMAnalyzer.parse_feedback(llm_feedback)

            # Merge issues
            merged_issues = {
                'critical': programmatic_issues_dict['critical'] + llm_issues_dict['critical'],
                'high': programmatic_issues_dict['high'] + llm_issues_dict['high'],
                'medium': programmatic_issues_dict['medium'] + llm_issues_dict['medium'],
                'low': programmatic_issues_dict['low'] + llm_issues_dict['low'],
                'info': programmatic_issues_dict['info'] + llm_issues_dict['info']
            }

            all_issues.append({
                "file": filename,
                "raw_feedback": llm_feedback,
                "issues_by_severity": merged_issues
            })

        # Perform architectural/design analysis
        print("Performing architectural analysis...")
        design_analysis = self.design_analyzer.analyze_architecture(file_contents)

        score, issue_counts = QualityScoreCalculator.calculate_score(all_issues)
        risk_level = QualityScoreCalculator.get_risk_level(score, issue_counts)

        return all_issues, score, risk_level, issue_counts, design_analysis

    def _convert_issues_to_severity_dict(self, issues: List[CodeIssue]) -> Dict[str, List[str]]:
        """Convert CodeIssue objects to severity dictionary format."""
        issues_by_severity = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }

        for issue in issues:
            severity_key = issue.severity.lower()

            formatted_issue = f"{issue.title}\n\n"
            formatted_issue += f"**Code:**\n```\n{issue.code}\n```\n\n"
            formatted_issue += f"**Why it's {issue.severity.lower()}:**\n"
            for reason in issue.reasons:
                formatted_issue += f"- {reason}\n"
            formatted_issue += f"\n**Fix:**\n{issue.fix}"

            if severity_key in issues_by_severity:
                issues_by_severity[severity_key].append(formatted_issue)

        return issues_by_severity

    def post_review_comment(self, pr: PullRequest, all_issues: List[Dict], 
                           score: float, risk_level: str, issue_counts: Dict[str, int],
                           design_analysis: str):
        """Post review comment to PR."""
        comment_body = ReviewCommentFormatter.format_comment(
            all_issues, score, risk_level, issue_counts, 
            self.security_requirements, design_analysis
        )
        pr.create_issue_comment(comment_body)

    def review(self):
        """Perform the full review process."""
        try:
            pr = self.pr_manager.get_latest_open_pr()
            print(f"Reviewing PR #{pr.number}: {pr.title}")

            file_contents = self.pr_manager.get_pr_files(pr)

            if not file_contents:
                print("No relevant files found in PR.")
                return

            all_issues, score, risk_level, issue_counts, design_analysis = self.analyze_code(file_contents)
            
            # Print detailed summary to console
            print(f"\n{'='*60}")
            print(f"QUALITY SCORE CALCULATION:")
            print(f"{'='*60}")
            print(f"Critical issues: {issue_counts['critical']} × 30 = {issue_counts['critical'] * 30} points")
            print(f"High issues:     {issue_counts['high']} × 20 = {issue_counts['high'] * 20} points")
            print(f"Medium issues:   {issue_counts['medium']} × 10 = {issue_counts['medium'] * 10} points")
            print(f"Low issues:      {issue_counts['low']} × 5 = {issue_counts['low'] * 5} points")
            print(f"Info issues:     {issue_counts['info']} × 2 = {issue_counts['info'] * 2} points")
            total_deduction = (issue_counts['critical'] * 30 + issue_counts['high'] * 20 + 
                             issue_counts['medium'] * 10 + issue_counts['low'] * 5 + issue_counts['info'] * 2)
            print(f"{'='*60}")
            print(f"Total deduction: {total_deduction} points")
            print(f"Final Score: 100 - {total_deduction} = {score}")
            print(f"Risk Level: {risk_level}")
            print(f"{'='*60}\n")

            self.post_review_comment(pr, all_issues, score, risk_level, issue_counts, design_analysis)

            if issue_counts['critical'] > 0:
                raise Exception(f"Build failed due to {issue_counts['critical']} CRITICAL severity issue(s).")

            if issue_counts['high'] >= 3:
                print(f"WARNING: {issue_counts['high']} HIGH severity issues found.")

            print(f"Review completed for PR #{pr.number}.")
            print(f"Quality Score: {score}/100 | Risk Level: {risk_level}")

        except Exception as e:
            print(f"Error during review: {str(e)}")
            raise


def main():
    """Main entry point."""
    import argparse
    
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description='Mulesoft Code Review Plugin - AI-assisted code review for Mulesoft applications'
    )
    parser.add_argument(
        '--repo',
        type=str,
        help='Repository name in format: owner/repo-name (e.g., "username/my-repo")',
        default=None
    )
    parser.add_argument(
        '--github-token',
        type=str,
        help='GitHub personal access token (or set GITHUB_TOKEN env variable)',
        default=None
    )
    parser.add_argument(
        '--openai-key',
        type=str,
        help='OpenAI API key (or set OPENAI_API_KEY env variable)',
        default=None
    )
    
    args = parser.parse_args()
    
    # Get GitHub token from args or environment
    GITHUB_TOKEN = args.github_token or os.getenv("GITHUB_TOKEN")
    
    # Get OpenAI API key from args or environment
    OPENAI_API_KEY = args.openai_key or os.getenv("OPENAI_API_KEY")
    
    # Get repository name from args or environment (fallback to default)
    REPO_NAME = args.repo or os.getenv("REPO_NAME") or os.getenv("GITHUB_REPOSITORY")
    
    # Validate required parameters
    if not GITHUB_TOKEN:
        print("Error: GitHub token is required.")
        print("Provide it via --github-token argument or GITHUB_TOKEN environment variable.")
        exit(1)
    
    if not OPENAI_API_KEY:
        print("Error: OpenAI API key is required.")
        print("Provide it via --openai-key argument or OPENAI_API_KEY environment variable.")
        exit(1)
    
    if not REPO_NAME:
        print("Error: Repository name is required.")
        print("Provide it via --repo argument, REPO_NAME environment variable, or GITHUB_REPOSITORY environment variable.")
        print("Format: owner/repo-name (e.g., 'username/my-repo')")
        exit(1)
    
    # Validate repository name format
    if '/' not in REPO_NAME:
        print(f"Error: Invalid repository name format: '{REPO_NAME}'")
        print("Repository name must be in format: owner/repo-name (e.g., 'username/my-repo')")
        exit(1)
    
    print(f"Starting code review for repository: {REPO_NAME}")
    print(f"GitHub Token: {'*' * (len(GITHUB_TOKEN) - 4) + GITHUB_TOKEN[-4:]}")
    print(f"OpenAI API Key: {'*' * (len(OPENAI_API_KEY) - 4) + OPENAI_API_KEY[-4:]}")
    print("=" * 60)

    SECURITY_REQUIREMENTS = """
    Project name should suggest an API or API-type (papi/sapi/eapi/exp/prc/sys or -api). (Medium)
    Test data file must be present and not empty in src/test/resources/example/. (Info)
    Create flows with fewer than 10 components. (High)
    Less than 10 flows per configuration XML is recommended. (High)
    Avoid using sizeOf()==0; prefer isEmpty(). (Medium)
    Use indent = false in DWL files for large payloads. (Medium)
    Use standard ports (8081, 8082, 8091, 8092). (Medium)
    global.xml / global-config.xml must exist in src/main/mule. (High)
    All files must exist in their respective folders. (Medium)
    api folder must exist inside resources. (Medium)
    Environment property files must exist under src/main/resources. (High)
    properties folder must exist inside resources. (High)
    Default HTTP success response codes should be 2XX/3XX. (Info)
    Default HTTP error response codes should be 4XX/5XX. (Info)
    Specify permitted HTTP Listener methods. (Medium)
    Sensitive client data must not be logged or traced. (Critical)
    .properties files must not be empty. (Medium)
    Use connection pooling for database connectors. (High)
    Mule config, YAML, and properties filenames must follow conventions. (Medium)
    .properties keys must be lowercase and dot-separated. (Info)
    .yaml keys must follow naming conventions. (Info)
    .yaml files must not be empty. (High)
    Payload DWL mappings must be externalized to .dwl files. (High)
    Keep all error flows in a single file. (High)
    Enable sendCorrelationId and set it to ALWAYS. (Medium)
    Avoid using DataWeave in Logger components. (Medium)
    Component names must be descriptive. (Medium)
    Flow names must follow naming conventions. (Medium)
    DataType names must use TitleCase (Async API). (Medium)
    Parameterize DB queries and avoid SELECT *. (High)
    Sensitive global config values must come from properties files. (Critical)
    Variable names must follow defined regex patterns. (Medium)
    DWL filenames must start with msg or var and follow conventions. (Medium)
    CI/CD deployment config must exist in pom.xml. (Medium)
    Avoid commented code in Mule config files. (Medium)
    Avoid using Choice routers for mapping logic. (Medium)
    Avoid combining Set Variable and Transform Message. (Medium)
    Avoid consecutive Set Variable components. (Medium)
    Use APIKIT features in interface or main XML. (High)
    Only one HTTP Listener allowed in interface file. (High)
    All global elements must exist in global config file. (High)
    Logger level must be INFO in flows, DEBUG in subflows. (Info)
    Define MUnit code coverage in pom.xml. (High)
    Use Mule Secure Properties feature. (Critical)
    Configure global error handler using configuration element. (High)
    Flow/sub-flow must not exist in global config file. (High)
    Use AutoDiscovery to register API in API Manager. (High)
    Host must be a domain name, not an IP address. (High)
    """

    plugin = MulesoftCodeReviewPlugin(
        REPO_NAME,
        GITHUB_TOKEN,
        OPENAI_API_KEY,
        SECURITY_REQUIREMENTS
    )
    plugin.review()


if __name__ == "__main__":
    main()