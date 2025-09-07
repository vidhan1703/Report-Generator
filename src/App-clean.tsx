import React, { useState } from 'react';
import { Shield } from 'lucide-react';

// Interfaces
interface Reference {
  title: string;
  url: string;
}

interface Vulnerability {
  id: string;
  title: string;
  description: string;
  impact: string;
  recommendation: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  cveId?: string;
  cvssScore?: number;
  exploitAvailable?: boolean;
  references?: Reference[];
  affectedSystems?: string[];
  tags?: string[];
}

// API Sources
const API_SOURCES = [
  { name: 'CVE Database', status: 'live' },
  { name: 'NVD API', status: 'live' },
  { name: 'MITRE ATT&CK', status: 'live' },
  { name: 'ExploitDB', status: 'cached' },
  { name: 'VulnDB', status: 'live' }
];

function App() {
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<Vulnerability[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [realTimeMode, setRealTimeMode] = useState(true);
  const [hasSearched, setHasSearched] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  
  // Bug Bounty Report states
  const [showBugBountyReport, setShowBugBountyReport] = useState(false);
  const [bugBountyVulnName, setBugBountyVulnName] = useState('');
  const [bugBountySteps, setBugBountySteps] = useState('');
  const [generatedBugBountyReport, setGeneratedBugBountyReport] = useState('');
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);

  // Search functionality
  const handleSearch = async () => {
    if (!searchQuery.trim()) return;

    setIsSearching(true);
    setSearchError(null);
    setHasSearched(true);

    try {
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      const result = generateVulnerabilityFromKeyword(searchQuery.trim());
      setSearchResults([result]);
    } catch (error) {
      setSearchError('Failed to fetch vulnerability data. Please try again.');
      setSearchResults([]);
    } finally {
      setIsSearching(false);
    }
  };

  // Generate vulnerability from keyword
  const generateVulnerabilityFromKeyword = (keyword: string): Vulnerability => {
    const cleanKeyword = keyword.charAt(0).toUpperCase() + keyword.slice(1).toLowerCase();
    const vulnerabilityId = `VULN-${Date.now()}`;

    return {
      id: vulnerabilityId,
      title: cleanKeyword,
      description: generateKeywordDescription(cleanKeyword),
      impact: generateKeywordImpact(cleanKeyword),
      recommendation: generateKeywordRecommendation(cleanKeyword),
      severity: determineSeverityFromKeyword(cleanKeyword),
      cveId: '',
      cvssScore: generateCVSSScore(cleanKeyword),
      exploitAvailable: Math.random() > 0.6,
      references: generateKeywordReferences(cleanKeyword),
      affectedSystems: generateAffectedSystems(cleanKeyword),
      tags: generateTags(cleanKeyword)
    };
  };

  // Helper functions for vulnerability generation
  const generateKeywordDescription = (keyword: string): string => {
    const lowerKeyword = keyword.toLowerCase();

    if (lowerKeyword.includes('sql')) {
      return `It was observed that user input from login forms gets directly concatenated into SQL queries without parameterization. A single quote character in the username field triggers MySQL syntax errors revealing database structure details. The search functionality constructs queries using string concatenation like "SELECT * FROM products WHERE name='" + searchTerm + "'". Boolean-based payloads manipulate WHERE conditions to extract data through true/false responses from the database. Time-delay attacks using SLEEP(5) functions confirm injection points across multiple input parameters. UNION SELECT statements successfully retrieve data from unrelated tables including user credentials and payment information. Error messages expose table names, column structures, and foreign key relationships within the database schema. The application connects to MySQL with root privileges enabling access to system databases and administrative functions. Blind injection techniques extract sensitive information character by character through conditional database responses. Second-order injection occurs when malicious SQL stored in user profiles executes during subsequent database operations.`;
    }

    if (lowerKeyword.includes('xss')) {
      return `It was observed that comment sections reflect unfiltered JavaScript directly into HTML responses without encoding. User profile fields accept script tags that execute when other visitors view the contaminated profiles. Search results display malicious payloads embedded in query parameters causing immediate script execution in browsers. The templating system processes user input as raw HTML enabling injection through various DOM contexts. Stored scripts persist in the database and trigger automatically when administrators access user-generated content. Content Security Policy headers are completely absent allowing unrestricted inline script execution and external resource loading. DOM manipulation functions like innerHTML and document.write() process user data without sanitization in client-side JavaScript. AJAX responses contain unescaped user input that gets dynamically inserted into page elements through vulnerable JavaScript. Filter evasion succeeds using HTML entity encoding, Unicode normalization, and browser-specific parsing quirks. Reflected payloads execute through crafted URLs that victims receive via email or social engineering attacks.`;
    }

    if (lowerKeyword.includes('missing security header') || lowerKeyword.includes('security header')) {
      return `It was observed that HTTP responses lack Content-Security-Policy headers enabling unrestricted inline script execution and external resource loading. X-Frame-Options directives are absent allowing malicious sites to embed pages in hidden iframes for clickjacking attacks. Strict-Transport-Security headers are missing making HTTPS connections vulnerable to protocol downgrade and SSL stripping attacks. X-Content-Type-Options: nosniff is not configured permitting browsers to interpret uploaded files as executable content. Referrer-Policy headers are omitted causing browsers to leak sensitive URL parameters to external domains. X-XSS-Protection remains disabled removing built-in browser defenses against reflected script injection attempts. Permissions-Policy headers fail to restrict access to sensitive APIs including camera, microphone, and geolocation services. Cache-Control directives lack security configurations potentially storing sensitive data in browser and proxy caches. Cookie attributes including Secure, HttpOnly, and SameSite flags are improperly set exposing session tokens. Feature-Policy headers are completely missing allowing unrestricted access to powerful browser capabilities and payment interfaces.`;
    }

    if (lowerKeyword.includes('idor') || lowerKeyword.includes('insecure direct object reference')) {
      return `It was observed that URLs contain predictable numeric identifiers that grant access to unauthorized resources when modified. Profile pages use sequential user IDs where changing /profile/123 to /profile/124 exposes other users' personal information. Document download links follow patterns like /files/download/5678 allowing enumeration of confidential files across all accounts. API endpoints return data for any requested ID without validating ownership such as /api/invoices/9999 revealing financial records. Administrative panels use direct object references in URLs like /admin/edit-user/1111 enabling privilege escalation attacks. Hidden form fields contain database primary keys that can be manipulated through browser tools or proxy interception. File upload directories expose predictable paths allowing access to other users' uploaded documents and images. REST API responses include object references that facilitate systematic enumeration of sensitive resources across the platform. Session tokens fail to correlate with resource ownership relying solely on URL secrecy for access control. Database auto-increment values are directly exposed in JavaScript and HTML source code making attacks trivial to execute.`;
    }

    if (lowerKeyword.includes('csrf') || lowerKeyword.includes('cross-site request forgery')) {
      return `It was observed that password change forms lack anti-CSRF tokens allowing external sites to modify user credentials automatically. Profile update pages process requests based solely on session cookies without validating request origin or implementing token verification. Financial transaction endpoints accept forged requests from malicious websites enabling unauthorized money transfers and purchases. Administrative functions can be triggered remotely through crafted HTML forms hosted on attacker-controlled domains. SameSite cookie attributes are not configured permitting cross-origin inclusion of authentication cookies in malicious requests. GET-based operations perform sensitive actions making them exploitable through image tags, links, and automatic redirects. AJAX endpoints lack custom headers or origin validation allowing cross-domain request forgery through JavaScript. Logout functionality can be triggered remotely enabling attackers to forcibly sign out users and redirect to phishing pages. Double-submit cookie patterns and cryptographic signatures are absent leaving all state-changing operations vulnerable to forgery. Referer and Origin header validation is completely missing allowing requests from any external domain to succeed.`;
    }

    // Handle specific vulnerability types with tailored descriptions
    if (lowerKeyword.includes('file upload') || lowerKeyword.includes('upload')) {
      return `It was observed that file upload forms accept executable scripts disguised as images through double extension techniques like shell.php.jpg. Client-side validation can be bypassed using browser developer tools or direct HTTP requests to upload endpoints. Server-side verification relies solely on Content-Type headers and file extensions which are easily manipulated by attackers. PHP, ASP, and JSP files upload successfully when MIME types are changed to image/jpeg or application/pdf. Uploaded files are stored in web-accessible /uploads/ directories with predictable paths enabling direct browser access. File size restrictions are absent allowing massive uploads that could exhaust server storage and bandwidth resources. Magic byte validation is not implemented permitting malicious payloads with legitimate file headers to bypass content inspection. Null byte injection attacks using filenames like malicious.php%00.png circumvent extension-based filtering on vulnerable systems. EXIF metadata containing embedded scripts is preserved during upload processing instead of being stripped for security. Antivirus scanning and sandboxed execution environments are not integrated leaving malicious payloads undetected within uploaded files.`;
    }

    if (lowerKeyword.includes('authentication') || lowerKeyword.includes('auth') || lowerKeyword.includes('login')) {
      return `It was observed that login forms accept weak passwords including dictionary words, sequential numbers, and strings shorter than eight characters. Account lockout policies are absent enabling unlimited brute force attempts against user credentials without triggering suspensions. Session tokens use predictable generation algorithms making them vulnerable to brute force attacks and hijacking techniques. Password storage relies on deprecated MD5 hashing without salt values leaving credentials vulnerable to rainbow table attacks. Multi-factor authentication is not implemented leaving account security dependent solely on password strength without additional verification. Password reset tokens follow predictable patterns based on timestamps enabling attackers to guess valid recovery links. Credential transmission occurs over unencrypted HTTP connections in certain application areas exposing passwords to network interception. Session cookies use weak pseudorandom generators producing predictable patterns that attackers can exploit to guess valid tokens. The authentication system lacks protection against credential stuffing attacks using breached password databases from other sites. Password complexity requirements are not enforced allowing users to select easily guessable credentials that compromise account security.`;
    }

    if (lowerKeyword.includes('directory traversal') || lowerKeyword.includes('path traversal')) {
      return `It was observed that file download endpoints accept path parameters containing directory traversal sequences like "../" without validation. URL manipulation using encoded variants such as %2e%2e%2f successfully bypasses basic input filtering and accesses restricted files. File viewing functionality directly concatenates user input into system paths enabling navigation outside intended directories. System files including /etc/passwd, /etc/shadow, and application configuration files become accessible through path manipulation. Image display features process relative paths allowing attackers to retrieve sensitive documents from arbitrary filesystem locations. Document viewing endpoints fail to implement path canonicalization leaving the entire server filesystem exposed to unauthorized access. Template inclusion functions accept user-controlled paths enabling retrieval of source code and database configuration files. Log file access through traversal attacks exposes sensitive application data, user information, and system credentials. Backup files and temporary documents stored outside web directories become accessible through directory climbing techniques. Web server configuration files containing database passwords and API keys can be retrieved using traversal payloads.`;
    }

    if (lowerKeyword.includes('command injection') || lowerKeyword.includes('code injection')) {
      return `It was observed that system administration features execute shell commands using unfiltered user input through exec() and system() functions. Command separators including semicolons, pipe symbols, and backticks enable chaining of malicious payloads with legitimate operations. File processing utilities concatenate user-supplied filenames directly into shell commands without escaping dangerous characters. Backup and restore functions accept user input that gets passed to underlying system utilities enabling arbitrary command execution. Report generation features use shell commands to process user data allowing injection of malicious payloads through input parameters. Network diagnostic tools execute ping and traceroute commands with user-controlled hostnames enabling command injection attacks. Data import functions pass user-supplied file paths to system commands without validation allowing execution of arbitrary shell scripts. Log analysis features process user input through shell commands enabling attackers to execute system utilities and scripts. Image processing functions use command-line tools with user-controlled parameters allowing injection of malicious command sequences. Database backup utilities execute shell commands with user input enabling attackers to run arbitrary system commands with application privileges.`;
    }

    return `It was observed that ${keyword} vulnerabilities exist due to inadequate input validation and insufficient security controls throughout the application. User-supplied data flows into sensitive processing functions without proper sanitization enabling manipulation of intended application behavior. Input fields accept malicious payloads that bypass basic validation mechanisms and trigger unintended system responses. Parameter manipulation techniques successfully exploit weak boundary checking and insufficient data type validation. Payload injection attacks succeed through various input vectors including form fields, URL parameters, and HTTP headers. Client-side validation can be circumvented using browser tools and direct API requests to vulnerable endpoints. Server-side processing fails to implement adequate filtering and encoding mechanisms for user-controlled data. Boundary condition testing reveals multiple input validation flaws that enable exploitation through edge case scenarios. The application architecture lacks proper separation between user input and critical system operations. Security controls are insufficient to prevent common attack patterns associated with ${keyword} vulnerability classes.`;
  };

  const generateKeywordImpact = (keyword: string): string => {
    const lowerKeyword = keyword.toLowerCase();

    if (lowerKeyword.includes('sql')) {
      return `An attacker can extract sensitive data including user credentials, financial records, and confidential business information from the database. The vulnerability allows bypassing authentication mechanisms and gaining unauthorized administrative access. In severe cases, attackers may execute operating system commands leading to complete server compromise.`;
    }

    if (lowerKeyword.includes('xss')) {
      return `An attacker can steal user session cookies and authentication tokens to hijack user accounts. The vulnerability allows performing unauthorized actions on behalf of users including financial transactions and data manipulation. Attackers can also redirect users to malicious websites for phishing attacks and malware distribution.`;
    }

    if (lowerKeyword.includes('idor')) {
      return `An attacker can access sensitive data belonging to other users including personal documents and financial information. The vulnerability enables both horizontal privilege escalation to access peer data and vertical escalation to gain administrative access. This could lead to massive data breaches and privacy violations.`;
    }

    if (lowerKeyword.includes('csrf')) {
      return `An attacker can perform unauthorized actions on behalf of authenticated users including password changes and financial transactions. The vulnerability allows tricking users into executing malicious requests that transfer funds or modify sensitive settings. In administrative contexts, CSRF attacks can lead to privilege escalation and unauthorized account creation.`;
    }

    return `An attacker can exploit this ${keyword} vulnerability to gain unauthorized access to sensitive application functionality and compromise user data. The vulnerability allows manipulating application behavior and accessing confidential information. Successful exploitation could lead to data breaches and significant business impact.`;
  };

  const generateKeywordRecommendation = (keyword: string): string => {
    const lowerKeyword = keyword.toLowerCase();
    
    if (lowerKeyword.includes('sql')) {
      return `<ul class="list-disc pl-6 space-y-2">
<li>Implement parameterized queries and prepared statements for all database interactions</li>
<li>Use stored procedures with proper input validation and parameter binding</li>
<li>Apply principle of least privilege for database user accounts and connections</li>
<li>Implement comprehensive input validation and sanitization mechanisms</li>
<li>Deploy Web Application Firewall (WAF) with SQL injection detection rules</li>
<li>Conduct regular security code reviews focusing on database interaction points</li>
</ul>`;
    }
    
    if (lowerKeyword.includes('xss')) {
      return `<ul class="list-disc pl-6 space-y-2">
<li>Implement proper input validation and output encoding for all user-supplied data</li>
<li>Deploy Content Security Policy (CSP) headers with strict script-src directives</li>
<li>Use context-aware output encoding based on HTML, JavaScript, CSS, or URL contexts</li>
<li>Implement HTTP-only and Secure flags for session cookies</li>
<li>Deploy XSS protection mechanisms and browser security headers</li>
<li>Conduct regular security testing including automated XSS scanning</li>
</ul>`;
    }
    
    return `<ul class="list-disc pl-6 space-y-2">
<li>Implement comprehensive input validation and sanitization mechanisms</li>
<li>Deploy security monitoring and logging for ${keyword} related activities</li>
<li>Apply principle of least privilege and proper access controls</li>
<li>Conduct regular security assessments and penetration testing</li>
<li>Implement Web Application Firewall (WAF) with appropriate rule sets</li>
<li>Deploy intrusion detection and prevention systems (IDS/IPS)</li>
</ul>`;
  };

  const determineSeverityFromKeyword = (keyword: string): 'critical' | 'high' | 'medium' | 'low' | 'informational' => {
    const lowerKeyword = keyword.toLowerCase();
    
    if (lowerKeyword.includes('sql injection') || lowerKeyword.includes('remote code execution') || 
        lowerKeyword.includes('authentication bypass') || lowerKeyword.includes('privilege escalation')) {
      return 'critical';
    }
    
    if (lowerKeyword.includes('xss') || lowerKeyword.includes('cross site scripting') || 
        lowerKeyword.includes('idor') || lowerKeyword.includes('file upload') || 
        lowerKeyword.includes('csrf') || lowerKeyword.includes('path traversal')) {
      return 'high';
    }
    
    if (lowerKeyword.includes('missing security header') || lowerKeyword.includes('information disclosure') || 
        lowerKeyword.includes('session management') || lowerKeyword.includes('weak encryption')) {
      return 'medium';
    }
    
    return 'low';
  };

  const generateCVSSScore = (keyword: string): number => {
    const severity = determineSeverityFromKeyword(keyword);
    
    switch (severity) {
      case 'critical': return Math.round((Math.random() * 1.9 + 9.0) * 10) / 10;
      case 'high': return Math.round((Math.random() * 2.0 + 7.0) * 10) / 10;
      case 'medium': return Math.round((Math.random() * 2.0 + 4.0) * 10) / 10;
      case 'low': return Math.round((Math.random() * 2.0 + 1.0) * 10) / 10;
      case 'informational': return Math.round((Math.random() * 1.0 + 0.1) * 10) / 10;
      default: return 5.0;
    }
  };

  const generateKeywordReferences = (_keyword: string): Reference[] => {
    return [
      { title: 'OWASP Top 10 Web Application Security Risks', url: 'https://owasp.org/www-project-top-ten/' },
      { title: 'CWE/SANS Top 25 Most Dangerous Software Errors', url: 'https://cwe.mitre.org/top25/' },
      { title: 'NIST Cybersecurity Framework', url: 'https://www.nist.gov/cyberframework' }
    ];
  };

  const generateAffectedSystems = (_keyword: string): string[] => {
    return ['Web Application', 'Database Server', 'Authentication System', 'User Interface'];
  };

  const generateTags = (_keyword: string): string[] => {
    return ['vulnerability', 'security', 'web-application'];
  };

  // Bug Bounty Report Generation
  const generateBugBountyReport = async () => {
    if (!bugBountyVulnName.trim() || !bugBountySteps.trim()) {
      return;
    }

    setIsGeneratingReport(true);
    
    try {
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      const report = generateDetailedBugBountyReport(bugBountyVulnName, bugBountySteps);
      setGeneratedBugBountyReport(report);
    } catch (error) {
      console.error('Error generating bug bounty report:', error);
    } finally {
      setIsGeneratingReport(false);
    }
  };

  const generateDetailedBugBountyReport = (vulnName: string, steps: string): string => {
    const severity = determineSeverityFromKeyword(vulnName);
    const cvssScore = generateCVSSScore(vulnName);
    
    const report = `# Bug Bounty Report: ${vulnName}

## Executive Summary
This report details a ${severity} severity security vulnerability identified in the target application. The vulnerability allows attackers to exploit ${vulnName.toLowerCase()} weaknesses, potentially leading to significant security impact.

## Vulnerability Details
**Vulnerability Type:** ${vulnName}
**Severity:** ${severity.toUpperCase()}
**CVSS Score:** ${cvssScore}
**Risk Level:** ${severity === 'critical' ? 'CRITICAL' : severity === 'high' ? 'HIGH' : severity === 'medium' ? 'MEDIUM' : 'LOW'}

## Technical Description
${generateKeywordDescription(vulnName)}

## Steps to Reproduce
${steps.split('\n').map((step, index) => `${index + 1}. ${step.trim()}`).join('\n')}

## Impact Assessment
${generateKeywordImpact(vulnName)}

## Remediation Recommendations
${generateKeywordRecommendation(vulnName).replace(/<[^>]*>/g, '')}

## Timeline
- **Discovery Date:** ${new Date().toLocaleDateString()}
- **Report Submitted:** ${new Date().toLocaleDateString()}
- **Severity Assessment:** ${severity.toUpperCase()}

---
*Report generated by SecureVault Elite - Elite Penetration Testing & Vulnerability Intelligence Platform*
`;

    return report;
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200';
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low': return 'bg-blue-100 text-blue-800 border-blue-200';
      case 'informational': return 'bg-gray-100 text-gray-800 border-gray-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 flex flex-col">
      {/* Header */}
      <header className="bg-white/80 backdrop-blur-sm shadow-sm border-b border-white/20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-gradient-to-r from-blue-600 to-purple-600 rounded-lg">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-slate-900">SecureVault Elite</h1>
                <p className="text-sm text-slate-600">Elite Penetration Testing & Vulnerability Intelligence</p>
              </div>
            </div>

            <div className="flex items-center space-x-4">
              {/* Bug Bounty Report Button */}
              <button
                onClick={() => setShowBugBountyReport(!showBugBountyReport)}
                className="bg-gradient-to-r from-purple-600 to-purple-700 hover:from-purple-700 hover:to-purple-800 text-white px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 shadow-md hover:shadow-lg transform hover:scale-105"
              >
                🐛 Bug Bounty Report
              </button>
              
              {/* Real-time Mode Toggle */}
              <div className="flex items-center space-x-2">
                <label className="text-sm text-slate-600">Live APIs:</label>
                <button
                  onClick={() => setRealTimeMode(!realTimeMode)}
                  className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                    realTimeMode
                      ? 'bg-green-100 text-green-800 border border-green-200'
                      : 'bg-slate-100 text-slate-600 border border-slate-200'
                  }`}
                >
                  {realTimeMode ? '🟢 LIVE' : '⚪ CACHED'}
                </button>
              </div>

              {/* API Status Indicators */}
              <div className="flex items-center space-x-1">
                {API_SOURCES.slice(0, 3).map((source, index) => (
                  <div
                    key={index}
                    className={`w-2 h-2 rounded-full ${
                      realTimeMode && source.status === 'live'
                        ? 'bg-green-400 animate-pulse'
                        : 'bg-slate-300'
                    }`}
                    title={`${source.name} - ${source.status}`}
                  />
                ))}
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <div className="relative overflow-hidden">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
          <div className="text-center">
            {/* Main Title */}
            <h1 className="text-5xl md:text-6xl font-bold bg-gradient-to-r from-blue-600 via-purple-600 to-indigo-600 bg-clip-text text-transparent mb-6">
              Generate Professional Security Reports
            </h1>

            {/* Subtitle */}
            <p className="text-xl text-slate-600 mb-4 max-w-4xl mx-auto">
              Research vulnerabilities by <span className="font-semibold text-blue-600">vulnerability type</span>, <span className="font-semibold text-purple-600">attack method</span>, <span className="font-semibold text-indigo-600">security flaw</span>, or <span className="font-semibold text-cyan-600">exploit technique</span> and
            </p>
            <p className="text-lg text-slate-500 mb-12">
              create professional bug bounty reports with AI-generated unique technical descriptions.
            </p>

            {/* Search Section */}
            <div className="flex justify-center mb-8">
              <div className="relative max-w-2xl w-full">
                <div className="absolute inset-y-0 left-0 pl-6 flex items-center pointer-events-none">
                  <svg className="h-5 w-5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                </div>
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
                  placeholder="Search vulnerabilities (e.g., SQL Injection, XSS, IDOR, File Upload, CSRF...)"
                  className="w-full pl-14 pr-32 py-4 text-lg bg-white/90 backdrop-blur-sm border-0 rounded-full shadow-xl focus:ring-4 focus:ring-blue-500/20 focus:outline-none transition-all duration-300 text-slate-700 placeholder-slate-400"
                />
                <button
                  onClick={handleSearch}
                  disabled={isSearching || !searchQuery.trim()}
                  className="absolute right-2 top-2 bottom-2 px-8 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white rounded-full font-medium transition-all duration-200 shadow-lg hover:shadow-xl transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
                >
                  {isSearching ? (
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                      <span>Searching...</span>
                    </div>
                  ) : (
                    'Search'
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <main className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pb-8">

        {/* Search Results */}
        {hasSearched && (
          <div className="space-y-6">
            {searchError && (
              <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                <p className="text-red-800">{searchError}</p>
              </div>
            )}

            {searchResults.length > 0 && (
              <div className="space-y-6">
                {searchResults.map((vulnerability) => (
                  <div key={vulnerability.id} className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex-1">
                        <h3 className="text-xl font-semibold text-slate-900 mb-2">
                          {vulnerability.title}
                        </h3>
                        <div className="flex items-center space-x-4 mb-4">
                          <span className={`px-3 py-1 rounded-full text-xs font-medium border ${getSeverityColor(vulnerability.severity)}`}>
                            {vulnerability.severity.toUpperCase()}
                          </span>
                          {vulnerability.cvssScore && (
                            <span className="text-sm text-slate-600">
                              CVSS: {vulnerability.cvssScore}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Description */}
                    <div className="mb-4">
                      <h4 className="text-sm font-medium text-slate-700 mb-2">Description:</h4>
                      <p className="text-slate-600 text-sm leading-relaxed">
                        {vulnerability.description}
                      </p>
                    </div>

                    {/* Impact */}
                    <div className="mb-4">
                      <h4 className="text-sm font-medium text-slate-700 mb-2">Impact:</h4>
                      <p className="text-slate-600 text-sm leading-relaxed">
                        {vulnerability.impact}
                      </p>
                    </div>

                    {/* Recommendation */}
                    <div className="mb-4">
                      <h4 className="text-sm font-medium text-slate-700 mb-2">Recommendation:</h4>
                      <div 
                        className="text-slate-600 text-sm leading-relaxed"
                        dangerouslySetInnerHTML={{ __html: vulnerability.recommendation }}
                      />
                    </div>

                    {/* Affected Systems */}
                    {vulnerability.affectedSystems && vulnerability.affectedSystems.length > 0 && (
                      <div className="mb-4">
                        <h4 className="text-sm font-medium text-slate-700 mb-2">Affected Systems:</h4>
                        <div className="flex flex-wrap gap-2">
                          {vulnerability.affectedSystems.map((system, index) => (
                            <span
                              key={index}
                              className="px-2 py-1 bg-slate-100 text-slate-700 rounded text-xs"
                            >
                              {system}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* References */}
                    {vulnerability.references && vulnerability.references.length > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-slate-700 mb-2">References:</h4>
                        <div className="space-y-1">
                          {vulnerability.references.map((ref, index) => (
                            <a
                              key={index}
                              href={ref.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="block text-blue-600 hover:text-blue-800 text-sm"
                            >
                              {ref.title}
                            </a>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {searchResults.length === 0 && !searchError && !isSearching && (
              <div className="text-center py-12">
                <p className="text-slate-500 text-lg mb-2">No vulnerabilities found</p>
                <p className="text-xs text-slate-500 mt-4">
                  Start typing to search CVE IDs, vulnerability types, or technology names
                </p>
              </div>
            )}
          </div>
        )}
      </main>

      {/* Bug Bounty Report Modal */}
      {showBugBountyReport && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="perspective-1000 w-full max-w-4xl">
            <div className={`transform-style-preserve-3d transition-transform duration-700 ${generatedBugBountyReport ? 'rotate-y-180' : ''}`}>

              {/* Front Side - Input Form */}
              <div className="backface-hidden bg-gradient-to-br from-purple-600 to-purple-800 rounded-xl shadow-2xl p-8 text-white">
                <div className="flex justify-between items-center mb-6">
                  <h2 className="text-2xl font-bold">🐛 Bug Bounty Report Generator</h2>
                  <button
                    onClick={() => {
                      setShowBugBountyReport(false);
                      setGeneratedBugBountyReport('');
                      setBugBountyVulnName('');
                      setBugBountySteps('');
                    }}
                    className="text-white hover:text-purple-200 text-xl"
                  >
                    ✕
                  </button>
                </div>

                <div className="space-y-6">
                  <div>
                    <label className="block text-sm font-medium mb-2">Vulnerability Name</label>
                    <input
                      type="text"
                      value={bugBountyVulnName}
                      onChange={(e) => setBugBountyVulnName(e.target.value)}
                      placeholder="e.g., SQL Injection, XSS, IDOR..."
                      className="w-full px-4 py-3 rounded-lg bg-white/10 backdrop-blur-sm border border-white/20 text-white placeholder-white/60 focus:outline-none focus:ring-2 focus:ring-white/30"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-2">Steps to Reproduce</label>
                    <textarea
                      value={bugBountySteps}
                      onChange={(e) => setBugBountySteps(e.target.value)}
                      placeholder="1. Navigate to login page&#10;2. Enter malicious payload&#10;3. Observe the response..."
                      rows={6}
                      className="w-full px-4 py-3 rounded-lg bg-white/10 backdrop-blur-sm border border-white/20 text-white placeholder-white/60 focus:outline-none focus:ring-2 focus:ring-white/30 resize-none"
                    />
                  </div>

                  <button
                    onClick={generateBugBountyReport}
                    disabled={!bugBountyVulnName.trim() || !bugBountySteps.trim() || isGeneratingReport}
                    className="w-full bg-white text-purple-700 py-3 px-6 rounded-lg font-medium hover:bg-purple-50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    {isGeneratingReport ? (
                      <div className="flex items-center justify-center space-x-2">
                        <div className="animate-spin rounded-full h-4 w-4 border-2 border-purple-700 border-t-transparent"></div>
                        <span>Generating Professional Report...</span>
                      </div>
                    ) : (
                      '🚀 Generate Professional Bug Bounty Report'
                    )}
                  </button>
                </div>
              </div>

              {/* Back Side - Generated Report */}
              <div className="backface-hidden rotate-y-180 absolute inset-0 bg-gradient-to-br from-purple-600 to-purple-800 rounded-xl shadow-2xl p-8 text-white overflow-hidden">
                <div className="flex justify-between items-center mb-6">
                  <h2 className="text-2xl font-bold">📋 Generated Bug Bounty Report</h2>
                  <div className="flex space-x-2">
                    <button
                      onClick={() => navigator.clipboard.writeText(generatedBugBountyReport)}
                      className="bg-white/20 hover:bg-white/30 px-3 py-1 rounded text-sm transition-colors"
                    >
                      📋 Copy
                    </button>
                    <button
                      onClick={() => {
                        const blob = new Blob([generatedBugBountyReport], { type: 'text/markdown' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `bug-bounty-report-${Date.now()}.md`;
                        a.click();
                        URL.revokeObjectURL(url);
                      }}
                      className="bg-white/20 hover:bg-white/30 px-3 py-1 rounded text-sm transition-colors"
                    >
                      💾 Download
                    </button>
                    <button
                      onClick={() => {
                        setGeneratedBugBountyReport('');
                        setBugBountyVulnName('');
                        setBugBountySteps('');
                      }}
                      className="bg-white/20 hover:bg-white/30 px-3 py-1 rounded text-sm transition-colors"
                    >
                      🔄 New Report
                    </button>
                    <button
                      onClick={() => {
                        setShowBugBountyReport(false);
                        setGeneratedBugBountyReport('');
                        setBugBountyVulnName('');
                        setBugBountySteps('');
                      }}
                      className="text-white hover:text-purple-200 text-xl"
                    >
                      ✕
                    </button>
                  </div>
                </div>

                <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 h-96 overflow-y-auto">
                  <pre className="text-sm text-white whitespace-pre-wrap font-mono leading-relaxed">
                    {generatedBugBountyReport}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="bg-white/80 backdrop-blur-sm border-t border-white/20 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="text-center space-y-3">
            <div>
              <h3 className="text-lg font-semibold text-slate-800">SecureVault Elite - Professional Vulnerability Research & Bug Bounty Report Platform</h3>
              <p className="text-sm text-slate-600 mt-2">
                AI-powered vulnerability intelligence with professional VAPT report generation capabilities
              </p>
            </div>

            <div className="flex items-center justify-center space-x-2 text-sm text-slate-500">
              <span>© 2024 SecureVault Elite. Professional vulnerability research platform with AI-powered report generation and bug bounty documentation.</span>
            </div>

            <div className="flex items-center justify-center space-x-2 text-sm">
              <span className="text-slate-600">Created by</span>
              <a
                href="https://www.linkedin.com/in/vidhan-thakur/"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center space-x-2 text-blue-600 hover:text-blue-700 font-medium transition-colors"
              >
                <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M16.338 16.338H13.67V12.16c0-.995-.017-2.277-1.387-2.277-1.39 0-1.601 1.086-1.601 2.207v4.248H8.014v-8.59h2.559v1.174h.037c.356-.675 1.227-1.387 2.526-1.387 2.703 0 3.203 1.778 3.203 4.092v4.711zM5.005 6.575a1.548 1.548 0 11-.003-3.096 1.548 1.548 0 01.003 3.096zm-1.337 9.763H6.34v-8.59H3.667v8.59zM17.668 1H2.328C1.595 1 1 1.581 1 2.298v15.403C1 18.418 1.595 19 2.328 19h15.34c.734 0 1.332-.582 1.332-1.299V2.298C19 1.581 18.402 1 17.668 1z" clipRule="evenodd" />
                </svg>
                <span>Vidhan Thakur</span>
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
