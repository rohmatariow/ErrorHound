# -*- coding: utf-8 -*-
"""
Regex patterns for verbose error detection
Organized by error type and language/framework
"""

import re

class DetectionPatterns:
    """All regex patterns for error detection"""
    
    # Stack trace patterns by language
    STACK_TRACES = {
        'java': [
            r'at\s+[\w\.]+\([^)]+\.java:\d+\)',           # at com.example.Class(File.java:123)
            r'at\s+[\w\.$]+\.[\w]+\([^)]*\)',             # at com.example.Class.method()
            r'java\.[\w\.]+Exception',                     # java.lang.NullPointerException
            r'javax\.[\w\.]+Exception',                    # javax.servlet.ServletException
            r'org\.[\w\.]+Exception',                      # org.springframework.web.Exception
            r'com\.[\w\.]+Exception',                      # com.company.custom.Exception
            r'Caused by:',                                 # Stack trace chain
            r'Exception in thread',
            r'at sun\.reflect',
            r'at org\.apache',
            r'at org\.springframework',
            r'at com\.fasterxml\.jackson',                 # JSON parsing
        ],
        'python': [
            r'Traceback \(most recent call last\):',
            r'File ".*?", line \d+',                       # File "/path/file.py", line 123
            r'[\w\.]+Error:',                              # ValueError:, TypeError:, etc
            r'raise \w+Error',
            r'django\.[\w\.]+',
            r'flask\.[\w\.]+',
            r'sqlalchemy\.[\w\.]+',
        ],
        'php': [
            r'Fatal error:',
            r'Warning:.*in\s+/.+\.php\s+on line\s+\d+',   # Warning: ... in /path/file.php on line 123
            r'Parse error:',
            r'Notice:.*in\s+/.+\.php',
            r'Call to undefined',
            r'mysql_.*\(\):',
            r'mysqli::',
            r'PDOException',
            r'Stack trace:',
            r'#\d+\s+/.+\.php\(\d+\):',                    # #0 /path/file.php(123):
        ],
        'dotnet': [
            r'at\s+[\w\.]+\.[\w]+\([^)]*\)\s+in\s+[^:]+:\w+\s+\d+',  # at Namespace.Class.Method() in File.cs:line 123
            r'System\.[\w\.]+Exception',
            r'Microsoft\.[\w\.]+Exception',
            r'Exception Details:',
            r'Server Error in .* Application',
            r'\[[\w]+Exception:',
            r'at System\.',
            r'at Microsoft\.',
        ],
        'nodejs': [
            r'Error:\s+.*\n\s+at\s+',
            r'at\s+\w+\s+\([^)]+:\d+:\d+\)',               # at function (file.js:123:45)
            r'at\s+[^(]+\([^)]*\.js:\d+:\d+\)',
            r'TypeError:',
            r'ReferenceError:',
            r'SyntaxError:',
            r'at Module\._compile',
            r'at Function\.Module',
        ],
        'ruby': [
            r'[\w:]+Error:.*',
            r'from\s+/.+\.rb:\d+:in\s+',                   # from /path/file.rb:123:in `method'
            r'gems/[\w\-]+',
            r'app/[\w/]+\.rb:\d+',
        ],
        'go': [
            r'panic:',
            r'goroutine \d+ \[',
            r'[\w/]+\.go:\d+',
            r'runtime\.goexit',
            r'created by',
        ],
    }
    
    # Database error patterns
    DATABASE_ERRORS = {
        'mysql': [
            r'You have an error in your SQL syntax',
            r'mysql_fetch',
            r'MySQL server version',
            r'MySQLSyntaxErrorException',
            r'com\.mysql\.jdbc',
            r'Duplicate entry .* for key',
            r"Table .* doesn't exist",
            r"Unknown column '.*' in",
        ],
        'postgresql': [
            r'PostgreSQL.*ERROR',
            r'PSQLException',
            r'org\.postgresql',
            r'ERROR:\s+syntax error at or near',
            r'relation ".*" does not exist',
            r'column ".*" does not exist',
        ],
        'mssql': [
            r'Microsoft SQL Server',
            r'ODBC SQL Server Driver',
            r'SQLServer JDBC Driver',
            r'com\.microsoft\.sqlserver',
            r'Incorrect syntax near',
            r'Unclosed quotation mark',
        ],
        'oracle': [
            r'ORA-\d{5}',                                  # ORA-00001, ORA-12345, etc
            r'oracle\.jdbc',
            r'OracleException',
        ],
        'mongodb': [
            r'MongoError',
            r'mongodb\.MongoException',
            r'Failed to parse:',
        ],
        'sqlite': [
            r'SQLite.*error',
            r'sqlite3\.OperationalError',
            r'near ".*": syntax error',
        ],
    }
    
    # Framework-specific patterns
    FRAMEWORK_ERRORS = {
        'spring': [
            r'org\.springframework',
            r'HandlerExceptionResolver',
            r'DispatcherServlet',
            r'RequestMappingHandlerMapping',
            r'NoHandlerFoundException',
            r'HttpRequestMethodNotSupportedException',
            r'MethodArgumentNotValidException',
            r'TypeMismatchException',
        ],
        'laravel': [
            r'Illuminate\\',
            r'Laravel\\',
            r'vendor/laravel',
            r'Whoops\\',
            r'ErrorException',
            r'at vendor/laravel',
        ],
        'django': [
            r'django\.core\.exceptions',
            r'django\.db\.utils',
            r'django\.http\.response',
            r'DoesNotExist',
            r'OperationalError',
            r'ImproperlyConfigured',
        ],
        'flask': [
            r'flask\.app',
            r'werkzeug\.exceptions',
            r'werkzeug\.routing',
        ],
        'express': [
            r'at Layer\.handle',
            r'at Route\.dispatch',
            r'at Function\.app\.use',
        ],
        'aspnet': [
            r'ASP\.NET',
            r'System\.Web\.HttpException',
            r'Server Error in .* Application',
            r'Version Information:.*\.NET',
        ],
        'rails': [
            r'ActiveRecord::',
            r'ActionController::',
            r'ActionView::',
            r'app/controllers/',
            r'app/models/',
        ],
    }
    
    # Validation & parse error patterns
    VALIDATION_ERRORS = {
        'json_parse': [
            r'JSON[Pp]arse[^:]*[Ee]xception',
            r'Unexpected token',
            r'Unterminated string',
            r'Expected .* but found',
            r'Invalid JSON',
            r'Unexpected end of JSON input',
            r'com\.fasterxml\.jackson\.core',
            r'com\.google\.gson',
            r'JSON\.parse',
            r'SyntaxError: JSON',
        ],
        'xml_parse': [
            r'XML[Pp]ars[^:]*[Ee]xception',
            r'SAXParseException',
            r'org\.xml\.sax',
            r'Unclosed tag',
            r'Invalid XML',
            r'The element type',
            r'must be terminated',
        ],
        'validation': [
            r'Validation failed',
            r'Field .* is required',
            r'Expected .* type but got',
            r'must be of type',
            r'Invalid value for',
            r'ConstraintViolationException',
            r'ValidationException',
            r'Schema validation failed',
        ],
        'type_error': [
            r'Type mismatch',
            r'Cannot convert',
            r'ClassCastException',
            r'TypeError',
            r'Invalid type',
            r'Expected .* but received',
        ],
    }
    
    # Path disclosure patterns
    PATH_DISCLOSURE = [
        # Unix/Linux paths
        r'/home/[\w\-]+',
        r'/var/www',
        r'/usr/[\w/]+',
        r'/opt/[\w/]+',
        r'/etc/[\w/]+',
        r'/tmp/[\w/]+',
        
        # Windows paths
        r'[A-Z]:\\[\w\\\-\.]+',
        r'C:\\inetpub',
        r'C:\\Program Files',
        
        # Web application paths
        r'/app/[\w/]+',
        r'/src/[\w/]+',
        r'/lib/[\w/]+',
        r'/vendor/[\w/]+',
        r'/node_modules/',
        
        # Java paths
        r'\.jar!/',
        r'/WEB-INF/',
        r'/META-INF/',
        
        # Generic patterns
        r'[/\\][\w\-]+[/\\][\w\-]+[/\\][\w\-]+\.(java|php|py|rb|js|cs|go)',
    ]
    
    # Sensitive information patterns
    SENSITIVE_INFO = [
        # Database credentials
        r'password["\']?\s*[:=]\s*["\'][\w\-@!#$%]+["\']',
        r'username["\']?\s*[:=]\s*["\'][\w]+["\']',
        r'jdbc:[^"\s]+',
        r'mongodb://[^"\s]+',
        
        # API Keys / Tokens
        r'api[_\-]?key["\']?\s*[:=]\s*["\'][^"\']+["\']',
        r'token["\']?\s*[:=]\s*["\'][^"\']+["\']',
        r'secret["\']?\s*[:=]\s*["\'][^"\']+["\']',
        
        # Internal IPs
        r'(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}',
        
        # Email addresses
        r'[\w\.\-]+@[\w\.\-]+\.\w+',
        
        # Version information
        r'Version:\s*[\d\.]+',
        r'v\d+\.\d+\.\d+',
    ]
    
    @staticmethod
    def compile_patterns(pattern_dict):
        """
        Compile all patterns in a dictionary
        
        Args:
            pattern_dict: Dictionary of pattern lists
            
        Returns:
            Dictionary with compiled regex patterns
        """
        compiled = {}
        for key, patterns in pattern_dict.items():
            if isinstance(patterns, dict):
                compiled[key] = DetectionPatterns.compile_patterns(patterns)
            else:
                compiled[key] = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns]
        return compiled
    
    @staticmethod
    def get_all_patterns():
        """Get all patterns compiled"""
        return {
            'stack_traces': DetectionPatterns.compile_patterns(DetectionPatterns.STACK_TRACES),
            'database_errors': DetectionPatterns.compile_patterns(DetectionPatterns.DATABASE_ERRORS),
            'framework_errors': DetectionPatterns.compile_patterns(DetectionPatterns.FRAMEWORK_ERRORS),
            'validation_errors': DetectionPatterns.compile_patterns(DetectionPatterns.VALIDATION_ERRORS),
            'path_disclosure': [re.compile(p) for p in DetectionPatterns.PATH_DISCLOSURE],
            'sensitive_info': [re.compile(p, re.IGNORECASE) for p in DetectionPatterns.SENSITIVE_INFO],
        }
