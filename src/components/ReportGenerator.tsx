import React, { useState } from 'react';
import { FileText, Download, Plus, X, Calendar, User, Building } from 'lucide-react';
import { Vulnerability, PenTestReport, PenTestFinding } from '../types/vulnerability';

interface ReportGeneratorProps {
  vulnerabilities: Vulnerability[];
  onClose: () => void;
}

const ReportGenerator: React.FC<ReportGeneratorProps> = ({ vulnerabilities, onClose }) => {
  const [report, setReport] = useState<Partial<PenTestReport>>({
    title: 'Penetration Testing Report',
    client: '',
    testDate: new Date().toISOString().split('T')[0],
    tester: '',
    executiveSummary: '',
    scope: [],
    methodology: 'This penetration test was conducted using industry-standard methodologies including OWASP Testing Guide, NIST SP 800-115, and PTES (Penetration Testing Execution Standard).',
    findings: [],
    recommendations: [
      'Implement regular security assessments and vulnerability scanning',
      'Establish a comprehensive patch management program',
      'Conduct security awareness training for all personnel',
      'Implement multi-factor authentication where applicable',
      'Regular backup and disaster recovery testing'
    ]
  });

  const [selectedVulns, setSelectedVulns] = useState<string[]>([]);
  const [newScope, setNewScope] = useState('');

  const addToScope = () => {
    if (newScope.trim()) {
      setReport(prev => ({
        ...prev,
        scope: [...(prev.scope || []), newScope.trim()]
      }));
      setNewScope('');
    }
  };

  const removeFromScope = (index: number) => {
    setReport(prev => ({
      ...prev,
      scope: prev.scope?.filter((_, i) => i !== index) || []
    }));
  };

  const toggleVulnerability = (vulnId: string) => {
    setSelectedVulns(prev => 
      prev.includes(vulnId) 
        ? prev.filter(id => id !== vulnId)
        : [...prev, vulnId]
    );
  };

  const generateFindings = (): PenTestFinding[] => {
    return vulnerabilities
      .filter(vuln => selectedVulns.includes(vuln.id))
      .map(vuln => ({
        id: `finding-${vuln.id}`,
        vulnerability: vuln,
        evidence: [
          'Manual testing confirmed the presence of this vulnerability',
          'Automated scanning tools detected this issue',
          'Code review revealed insecure implementation'
        ],
        exploitSteps: [
          'Identify the vulnerable endpoint or component',
          'Craft malicious payload or input',
          'Execute the attack vector',
          'Verify successful exploitation',
          'Document the impact and evidence'
        ],
        businessImpact: getBusinessImpact(vuln.severity),
        technicalImpact: vuln.impact,
        likelihood: getLikelihood(vuln.severity),
        riskRating: vuln.severity,
        affectedAssets: vuln.affectedSystems || ['Web Application']
      }));
  };

  const getBusinessImpact = (severity: string): string => {
    switch (severity) {
      case 'critical':
        return 'Critical business operations could be severely disrupted, leading to significant financial losses, regulatory penalties, and reputational damage.';
      case 'high':
        return 'High impact on business operations with potential for data breaches, service disruption, and customer trust issues.';
      case 'medium':
        return 'Moderate impact on business operations with potential for limited data exposure or service degradation.';
      case 'low':
        return 'Low impact on business operations with minimal risk to data confidentiality or service availability.';
      default:
        return 'Informational finding with no direct business impact but may aid attackers in reconnaissance.';
    }
  };

  const getLikelihood = (severity: string): 'very-low' | 'low' | 'medium' | 'high' | 'very-high' => {
    switch (severity) {
      case 'critical': return 'very-high';
      case 'high': return 'high';
      case 'medium': return 'medium';
      case 'low': return 'low';
      default: return 'very-low';
    }
  };

  const exportReport = () => {
    const findings = generateFindings();
    const fullReport: PenTestReport = {
      ...report,
      id: `report-${Date.now()}`,
      findings,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    } as PenTestReport;

    // Generate report content
    const reportContent = generateReportContent(fullReport);
    
    // Create and download file
    const blob = new Blob([reportContent], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `penetration-test-report-${report.client?.replace(/\s+/g, '-').toLowerCase() || 'client'}-${new Date().toISOString().split('T')[0]}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const generateReportContent = (fullReport: PenTestReport): string => {
    return `# ${fullReport.title}

## Executive Summary

**Client:** ${fullReport.client}  
**Test Date:** ${fullReport.testDate}  
**Tester:** ${fullReport.tester}  
**Report Date:** ${new Date().toLocaleDateString()}

${fullReport.executiveSummary}

## Scope

${fullReport.scope?.map(item => `- ${item}`).join('\n') || 'No scope defined'}

## Methodology

${fullReport.methodology}

## Findings Summary

| Severity | Count |
|----------|-------|
| Critical | ${fullReport.findings.filter(f => f.riskRating === 'critical').length} |
| High | ${fullReport.findings.filter(f => f.riskRating === 'high').length} |
| Medium | ${fullReport.findings.filter(f => f.riskRating === 'medium').length} |
| Low | ${fullReport.findings.filter(f => f.riskRating === 'low').length} |

## Detailed Findings

${fullReport.findings.map((finding, index) => `
### ${index + 1}. ${finding.vulnerability.title}

**Severity:** ${finding.riskRating.toUpperCase()}  
**CVE ID:** ${finding.vulnerability.cveId || 'N/A'}  
**CVSS Score:** ${finding.vulnerability.cvssScore || 'N/A'}

#### Description
${finding.vulnerability.description}

#### Impact
${finding.vulnerability.impact}

#### Business Impact
${finding.businessImpact}

#### Evidence
${finding.evidence.map(e => `- ${e}`).join('\n')}

#### Exploitation Steps
${finding.exploitSteps.map((step, i) => `${i + 1}. ${step}`).join('\n')}

#### Affected Assets
${finding.affectedAssets.map(asset => `- ${asset}`).join('\n')}

#### Recommendation
${finding.vulnerability.recommendation}

#### References
${finding.vulnerability.references?.map(ref => `- [${ref.title}](${ref.url})`).join('\n') || 'No references available'}

---
`).join('\n')}

## Recommendations

${fullReport.recommendations?.map(rec => `- ${rec}`).join('\n') || 'No recommendations provided'}

## Conclusion

This penetration test identified ${fullReport.findings.length} security findings across the tested scope. Immediate attention should be given to critical and high-severity findings to reduce the overall risk posture.

---

*Report generated by VulnScanner Pro on ${new Date().toLocaleString()}*
`;
  };

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl max-w-6xl w-full max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="p-6 border-b border-slate-200 dark:border-slate-700">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <FileText className="w-6 h-6 text-primary-600" />
              <h2 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
                Penetration Testing Report Generator
              </h2>
            </div>
            <button
              onClick={onClose}
              className="p-2 text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        <div className="p-6 space-y-6">
          {/* Report Details */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                <Building className="w-4 h-4 inline mr-1" />
                Client Name
              </label>
              <input
                type="text"
                value={report.client || ''}
                onChange={(e) => setReport(prev => ({ ...prev, client: e.target.value }))}
                className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                placeholder="Enter client name"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                <User className="w-4 h-4 inline mr-1" />
                Tester Name
              </label>
              <input
                type="text"
                value={report.tester || ''}
                onChange={(e) => setReport(prev => ({ ...prev, tester: e.target.value }))}
                className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                placeholder="Enter tester name"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                <Calendar className="w-4 h-4 inline mr-1" />
                Test Date
              </label>
              <input
                type="date"
                value={report.testDate || ''}
                onChange={(e) => setReport(prev => ({ ...prev, testDate: e.target.value }))}
                className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                Report Title
              </label>
              <input
                type="text"
                value={report.title || ''}
                onChange={(e) => setReport(prev => ({ ...prev, title: e.target.value }))}
                className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                placeholder="Enter report title"
              />
            </div>
          </div>

          {/* Executive Summary */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
              Executive Summary
            </label>
            <textarea
              value={report.executiveSummary || ''}
              onChange={(e) => setReport(prev => ({ ...prev, executiveSummary: e.target.value }))}
              rows={4}
              className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              placeholder="Provide a high-level summary of the penetration test results..."
            />
          </div>

          {/* Scope */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
              Test Scope
            </label>
            <div className="flex space-x-2 mb-2">
              <input
                type="text"
                value={newScope}
                onChange={(e) => setNewScope(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && addToScope()}
                className="flex-1 px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                placeholder="Add scope item (e.g., Web Application, API Endpoints)"
              />
              <button
                onClick={addToScope}
                className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
              >
                <Plus className="w-4 h-4" />
              </button>
            </div>
            <div className="flex flex-wrap gap-2">
              {report.scope?.map((item, index) => (
                <span
                  key={index}
                  className="inline-flex items-center px-3 py-1 bg-primary-100 text-primary-800 rounded-full text-sm"
                >
                  {item}
                  <button
                    onClick={() => removeFromScope(index)}
                    className="ml-2 text-primary-600 hover:text-primary-800"
                  >
                    <X className="w-3 h-3" />
                  </button>
                </span>
              ))}
            </div>
          </div>

          {/* Vulnerability Selection */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
              Select Vulnerabilities to Include ({selectedVulns.length} selected)
            </label>
            <div className="max-h-60 overflow-y-auto border border-slate-300 rounded-lg p-4 space-y-2">
              {vulnerabilities.map((vuln) => (
                <label key={vuln.id} className="flex items-center space-x-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={selectedVulns.includes(vuln.id)}
                    onChange={() => toggleVulnerability(vuln.id)}
                    className="rounded border-slate-300 text-primary-600 focus:ring-primary-500"
                  />
                  <div className="flex-1">
                    <div className="flex items-center space-x-2">
                      <span className="font-medium text-slate-900 dark:text-slate-100">
                        {vuln.title}
                      </span>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        vuln.severity === 'critical' ? 'bg-red-100 text-red-800' :
                        vuln.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                        vuln.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                        'bg-blue-100 text-blue-800'
                      }`}>
                        {vuln.severity.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                      {vuln.cveId} - {vuln.description.substring(0, 100)}...
                    </p>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Actions */}
          <div className="flex justify-end space-x-4 pt-6 border-t border-slate-200 dark:border-slate-700">
            <button
              onClick={onClose}
              className="px-6 py-2 border border-slate-300 text-slate-700 rounded-lg hover:bg-slate-50 transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={exportReport}
              disabled={selectedVulns.length === 0 || !report.client || !report.tester}
              className="flex items-center space-x-2 px-6 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <Download className="w-4 h-4" />
              <span>Generate Report</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ReportGenerator;
