**Title: [sql-injection] in [Online-Student-Clearance-System] <= [v1.0]**
---
## BUG Author: [Anuj Sharma]
---
### Product Information:
---
- Vendor Homepage: (https://www.sourcecodester.com/)
- Software Link: (https://www.sourcecodester.com/php/17892/online-clearance-system.html)
- Affected Version: [<= v1.0]
- BUG Author: Anuj Sharma

### Vulnerability Details
---
- Type: Time Based SQL Injection
- Affected URL: http://localhost/student_clearance_system/Admin/login.php
- Vulnerable Parameter: username

#### Vulnerable Files:
- File Name: Login.php
- Path: student_clearance_system/Admin/login.php

#### Vulnerability Type
SQL Injection Vulnerability (CWE-89: SQL Injection)

#### Root Cause
The code directly concatenates user input into SQL query strings without any parameterization or input validation, allowing attackers to inject malicious SQL code.
***Line 18 is causing the vulnerability***
<img width="644" alt="cve_01" src="https://github.com/user-attachments/assets/2e29c22a-be41-47fd-9d0e-606cc3f24f17" />

### Impact:
- Unauthorized access to database information  
- Potential exposure of sensitive information (such as user passwords)  
- Possible database corruption or data manipulation

### Description:
---
#### 1. Vulnerability Details:
- In this php code, username parameter is directly concatenated into SQL Statement
- No input validation or escaping mechanisms implemented

#### 2. Attack Vectors:
- Attackers can manipulate SQL query structure using special characters
- Additional information can be extracted using Time Based Payloads
- Database information can be obtained through Time Based injection
- Time based injection might reveal more information

#### 3. Attack Payload Examples: 
```
sql: txtusername=test ' AND (SELECT 1824 FROM (SELECT(SLEEP(5)))nyKW) AND 'amlx'='amLx&txtpassword=test
```
<img width="734" alt="cve_1" src="https://github.com/user-attachments/assets/eda43d16-b6af-4cdb-8e6b-6c773dd2d13f" />

### Code Scan:

This vulnerability found by (https://github.com/cybersharmaji)

code scan found that there is no input validation or escaping in login.php file.

![image](https://github.com/user-attachments/assets/b9fafaac-fe77-4c76-a638-61727dd2dff3)

### Proof of Concept:
---
#### Information extraction
```
txtusername=test ' AND (SELECT 1824 FROM (SELECT(SLEEP(5)))nyKW) AND 'amlx'='amLx&txtpassword=test
```
##### txtusername is injectable!
<img width="769" alt="cve_0" src="https://github.com/user-attachments/assets/5a0d464d-0ade-4a99-ae26-82de3e3785c0" />

##### Databases information extracted
<img width="897" alt="cve_2" src="https://github.com/user-attachments/assets/25bbfe4f-2898-49cc-8e62-adb120edf3f2" />

##### Tables information extracted
<img width="890" alt="cve_3" src="https://github.com/user-attachments/assets/5e2b27e9-c193-4d82-aac3-a6b81684bcfb" />

##### Table=admin data dumped!
<img width="862" alt="cve_5" src="https://github.com/user-attachments/assets/58614a56-a0ef-4755-942d-025a408c7648" />

### Suggested Remediation:
---
- Implement Prepared Statements
- Input Validation
- Security Recommendations
  - Implement principle of least privilege
  - Encrypt sensitive data storage
  - Implement WAF protection
  - Conduct regular security audits
  - Use ORM frameworks for database operations

### Additional Information:
---
- Refer to OWASP SQL Injection Prevention Guide
- Consider using modern frameworks like MyBatis or Hibernate
- Implement logging and monitoring mechanisms
- References:
 - OWASP SQL Injection Prevention Cheat Sheet
 - CWE-89: SQL Injection
 - CERT Oracle Secure Coding Standard for Java

The severity of this vulnerability is ***HIGH***, and immediate remediation is recommended as it poses a serious threat to the system's data security.

Mitigation Timeline:

- Immediate: Implement prepared statements
- Short-term: Add input validation
- Long-term: Consider migrating to an ORM framework

This vulnerability requires immediate attention due to its potential for significant data breach and system compromise.





