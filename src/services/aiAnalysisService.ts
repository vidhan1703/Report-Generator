import { Vulnerability } from '../types/vulnerability';

interface AIAnalysisResult {
  riskScore: number;
  exploitProbability: number;
  businessImpact: string;
  technicalAnalysis: string;
  mitigationPriority: 'immediate' | 'high' | 'medium' | 'low';
  recommendedActions: string[];
  relatedThreats: string[];
  contextualInsights: string;
}

interface ThreatIntelligence {
  activeExploits: boolean;
  threatActors: string[];
  campaignReferences: string[];
  iocIndicators: string[];
  mitreTactics: string[];
}

class AIAnalysisService {
  private readonly apiKey: string | null;
  private cache = new Map<string, { data: AIAnalysisResult; timestamp: number }>();
  private readonly cacheTimeout = 30 * 60 * 1000; // 30 minutes

  constructor() {
    this.apiKey = import.meta.env.VITE_OPENAI_API_KEY || null;
  }

  async analyzeVulnerability(vulnerability: Vulnerability): Promise<AIAnalysisResult> {
    const cacheKey = `ai_analysis_${vulnerability.id}`;
    
    // Check cache first
    if (this.isValidCache(cacheKey)) {
      return this.getFromCache(cacheKey);
    }

    try {
      // If OpenAI API is available, use it for enhanced analysis
      if (this.apiKey) {
        const result = await this.performAIAnalysis(vulnerability);
        this.setCache(cacheKey, result);
        return result;
      } else {
        // Fallback to rule-based analysis
        const result = await this.performRuleBasedAnalysis(vulnerability);
        this.setCache(cacheKey, result);
        return result;
      }
    } catch (error) {
      console.error('AI Analysis error:', error);
      // Fallback to basic analysis
      return this.performBasicAnalysis(vulnerability);
    }
  }

  async generateVAPTReport(vulnerabilities: Vulnerability[], clientInfo: any): Promise<string> {
    try {
      const analyses = await Promise.all(
        vulnerabilities.map(vuln => this.analyzeVulnerability(vuln))
      );

      const reportSections = {
        executiveSummary: await this.generateExecutiveSummary(vulnerabilities, analyses),
        technicalFindings: await this.generateTechnicalFindings(vulnerabilities, analyses),
        riskAssessment: await this.generateRiskAssessment(vulnerabilities, analyses),
        recommendations: await this.generateRecommendations(vulnerabilities, analyses),
        appendices: await this.generateAppendices(vulnerabilities)
      };

      return this.compileVAPTReport(clientInfo, reportSections);
    } catch (error) {
      console.error('VAPT Report generation error:', error);
      return this.generateFallbackReport(vulnerabilities, clientInfo);
    }
  }

  async getThreatIntelligence(vulnerability: Vulnerability): Promise<ThreatIntelligence> {
    try {
      // Simulate threat intelligence gathering from multiple sources
      const intel: ThreatIntelligence = {
        activeExploits: this.checkActiveExploits(vulnerability),
        threatActors: await this.identifyThreatActors(vulnerability),
        campaignReferences: await this.findCampaignReferences(vulnerability),
        iocIndicators: await this.extractIOCs(vulnerability),
        mitreTactics: this.mapToMitreTactics(vulnerability)
      };

      return intel;
    } catch (error) {
      console.error('Threat intelligence error:', error);
      return {
        activeExploits: false,
        threatActors: [],
        campaignReferences: [],
        iocIndicators: [],
        mitreTactics: []
      };
    }
  }

  private async performAIAnalysis(vulnerability: Vulnerability): Promise<AIAnalysisResult> {
    // This would integrate with OpenAI API for advanced analysis
    // For now, we'll simulate AI-powered analysis with sophisticated rule-based logic
    
    const prompt = this.buildAnalysisPrompt(vulnerability);
    
    // Simulate AI response with realistic analysis
    return {
      riskScore: this.calculateAdvancedRiskScore(vulnerability),
      exploitProbability: this.assessExploitProbability(vulnerability),
      businessImpact: this.generateBusinessImpactAnalysis(vulnerability),
      technicalAnalysis: this.generateTechnicalAnalysis(vulnerability),
      mitigationPriority: this.determineMitigationPriority(vulnerability),
      recommendedActions: this.generateActionableRecommendations(vulnerability),
      relatedThreats: await this.findRelatedThreats(vulnerability),
      contextualInsights: this.generateContextualInsights(vulnerability)
    };
  }

  private async performRuleBasedAnalysis(vulnerability: Vulnerability): Promise<AIAnalysisResult> {
    return {
      riskScore: this.calculateRiskScore(vulnerability),
      exploitProbability: this.calculateExploitProbability(vulnerability),
      businessImpact: this.assessBusinessImpact(vulnerability),
      technicalAnalysis: this.performTechnicalAnalysis(vulnerability),
      mitigationPriority: this.assessMitigationPriority(vulnerability),
      recommendedActions: this.generateBasicRecommendations(vulnerability),
      relatedThreats: this.identifyRelatedThreats(vulnerability),
      contextualInsights: this.generateInsights(vulnerability)
    };
  }

  private performBasicAnalysis(vulnerability: Vulnerability): AIAnalysisResult {
    return {
      riskScore: vulnerability.cvssScore || 5.0,
      exploitProbability: vulnerability.exploitAvailable ? 0.8 : 0.3,
      businessImpact: `${vulnerability.severity} severity vulnerability affecting system security`,
      technicalAnalysis: vulnerability.description,
      mitigationPriority: vulnerability.severity === 'critical' ? 'immediate' : 'high',
      recommendedActions: [vulnerability.recommendation],
      relatedThreats: [],
      contextualInsights: 'Basic analysis performed due to limited data availability'
    };
  }

  private calculateAdvancedRiskScore(vulnerability: Vulnerability): number {
    let score = vulnerability.cvssScore || 5.0;
    
    // Adjust based on exploit availability
    if (vulnerability.exploitAvailable) score += 1.5;
    
    // Adjust based on affected systems
    if (vulnerability.affectedSystems?.length > 3) score += 0.5;
    
    // Adjust based on age
    if (vulnerability.publishedDate) {
      const daysSincePublished = (Date.now() - new Date(vulnerability.publishedDate).getTime()) / (1000 * 60 * 60 * 24);
      if (daysSincePublished > 365) score -= 0.5; // Older vulnerabilities might be less relevant
      if (daysSincePublished < 30) score += 0.5; // Recent vulnerabilities are more concerning
    }
    
    return Math.min(Math.max(score, 0), 10);
  }

  private assessExploitProbability(vulnerability: Vulnerability): number {
    let probability = 0.3; // Base probability
    
    if (vulnerability.exploitAvailable) probability += 0.4;
    if (vulnerability.severity === 'critical') probability += 0.2;
    if (vulnerability.severity === 'high') probability += 0.1;
    
    // Check for common vulnerability types that are frequently exploited
    const highExploitTypes = ['injection', 'xss', 'rce', 'authentication'];
    const vulnText = (vulnerability.title + ' ' + vulnerability.description).toLowerCase();
    
    if (highExploitTypes.some(type => vulnText.includes(type))) {
      probability += 0.2;
    }
    
    return Math.min(probability, 1.0);
  }

  private generateBusinessImpactAnalysis(vulnerability: Vulnerability): string {
    const impactTemplates = {
      critical: "This critical vulnerability poses an immediate and severe threat to business operations. Successful exploitation could result in complete system compromise, leading to significant financial losses, regulatory compliance violations, and severe reputational damage. The vulnerability enables attackers to gain unauthorized access to sensitive business data, potentially affecting customer trust and market position.",
      
      high: "This high-severity vulnerability represents a significant risk to business continuity and data security. Exploitation could lead to unauthorized access to sensitive information, service disruptions, and potential compliance issues. The business impact includes possible financial losses, customer data exposure, and damage to organizational reputation.",
      
      medium: "This medium-severity vulnerability poses a moderate risk to business operations. While not immediately critical, successful exploitation could result in limited data exposure, minor service disruptions, or provide attackers with a foothold for further compromise. The business should prioritize remediation to prevent escalation.",
      
      low: "This low-severity vulnerability presents a minimal immediate risk to business operations. However, it could be leveraged as part of a larger attack chain or provide reconnaissance information to potential attackers. Remediation should be included in regular maintenance cycles."
    };
    
    return impactTemplates[vulnerability.severity] || impactTemplates.medium;
  }

  private generateTechnicalAnalysis(vulnerability: Vulnerability): string {
    return `Technical analysis reveals that this vulnerability (${vulnerability.cveId || vulnerability.id}) affects ${vulnerability.affectedSystems?.join(', ') || 'multiple systems'}. The vulnerability mechanism involves ${this.extractTechnicalMechanism(vulnerability)}. Attack vectors include ${this.identifyAttackVectors(vulnerability).join(', ')}. The vulnerability can be exploited ${vulnerability.exploitAvailable ? 'with publicly available exploits' : 'through custom exploitation techniques'}. Successful exploitation requires ${this.assessExploitationRequirements(vulnerability)}.`;
  }

  private determineMitigationPriority(vulnerability: Vulnerability): 'immediate' | 'high' | 'medium' | 'low' {
    if (vulnerability.severity === 'critical' && vulnerability.exploitAvailable) return 'immediate';
    if (vulnerability.severity === 'critical' || (vulnerability.severity === 'high' && vulnerability.exploitAvailable)) return 'high';
    if (vulnerability.severity === 'high' || vulnerability.severity === 'medium') return 'medium';
    return 'low';
  }

  private generateActionableRecommendations(vulnerability: Vulnerability): string[] {
    const recommendations = [vulnerability.recommendation];
    
    // Add specific technical recommendations based on vulnerability type
    const vulnType = this.classifyVulnerabilityType(vulnerability);
    
    switch (vulnType) {
      case 'injection':
        recommendations.push(
          'Implement parameterized queries and input validation',
          'Deploy Web Application Firewall (WAF) with injection protection',
          'Conduct code review focusing on data handling practices'
        );
        break;
      case 'authentication':
        recommendations.push(
          'Implement multi-factor authentication (MFA)',
          'Review and strengthen password policies',
          'Implement account lockout mechanisms'
        );
        break;
      case 'authorization':
        recommendations.push(
          'Review and implement proper access controls',
          'Apply principle of least privilege',
          'Implement role-based access control (RBAC)'
        );
        break;
      default:
        recommendations.push(
          'Apply security patches immediately',
          'Implement monitoring and alerting',
          'Conduct regular security assessments'
        );
    }
    
    return recommendations;
  }

  private async findRelatedThreats(vulnerability: Vulnerability): Promise<string[]> {
    // Simulate finding related threats based on vulnerability characteristics
    const threats: string[] = [];
    
    if (vulnerability.tags?.includes('web')) {
      threats.push('Web Application Attacks', 'OWASP Top 10 Threats');
    }
    
    if (vulnerability.tags?.includes('network')) {
      threats.push('Network-based Attacks', 'Man-in-the-Middle Attacks');
    }
    
    if (vulnerability.exploitAvailable) {
      threats.push('Automated Exploitation', 'Botnet Activities');
    }
    
    return threats;
  }

  private generateContextualInsights(vulnerability: Vulnerability): string {
    const insights = [];
    
    if (vulnerability.publishedDate) {
      const daysSincePublished = Math.floor((Date.now() - new Date(vulnerability.publishedDate).getTime()) / (1000 * 60 * 60 * 24));
      insights.push(`This vulnerability was disclosed ${daysSincePublished} days ago`);
    }
    
    if (vulnerability.exploitAvailable) {
      insights.push('Public exploits are available, increasing the likelihood of active exploitation');
    }
    
    if (vulnerability.cvssScore && vulnerability.cvssScore > 7.0) {
      insights.push('High CVSS score indicates significant potential impact');
    }
    
    return insights.join('. ') + '.';
  }

  // Helper methods
  private isValidCache(key: string): boolean {
    const cached = this.cache.get(key);
    if (!cached) return false;
    return Date.now() - cached.timestamp < this.cacheTimeout;
  }

  private getFromCache(key: string): AIAnalysisResult {
    return this.cache.get(key)!.data;
  }

  private setCache(key: string, data: AIAnalysisResult): void {
    this.cache.set(key, { data, timestamp: Date.now() });
  }

  private buildAnalysisPrompt(vulnerability: Vulnerability): string {
    return `Analyze this security vulnerability: ${vulnerability.title}. Description: ${vulnerability.description}. Severity: ${vulnerability.severity}. CVSS Score: ${vulnerability.cvssScore}. Provide detailed risk assessment and recommendations.`;
  }

  private calculateRiskScore(vulnerability: Vulnerability): number {
    return vulnerability.cvssScore || 5.0;
  }

  private calculateExploitProbability(vulnerability: Vulnerability): number {
    return vulnerability.exploitAvailable ? 0.7 : 0.3;
  }

  private assessBusinessImpact(vulnerability: Vulnerability): string {
    return `${vulnerability.severity} severity impact on business operations`;
  }

  private performTechnicalAnalysis(vulnerability: Vulnerability): string {
    return vulnerability.description;
  }

  private assessMitigationPriority(vulnerability: Vulnerability): 'immediate' | 'high' | 'medium' | 'low' {
    if (vulnerability.severity === 'critical') return 'immediate';
    if (vulnerability.severity === 'high') return 'high';
    if (vulnerability.severity === 'medium') return 'medium';
    return 'low';
  }

  private generateBasicRecommendations(vulnerability: Vulnerability): string[] {
    return [vulnerability.recommendation];
  }

  private identifyRelatedThreats(vulnerability: Vulnerability): string[] {
    return vulnerability.tags || [];
  }

  private generateInsights(vulnerability: Vulnerability): string {
    return `Analysis of ${vulnerability.id} indicates ${vulnerability.severity} severity risk`;
  }

  private extractTechnicalMechanism(vulnerability: Vulnerability): string {
    const description = vulnerability.description.toLowerCase();
    if (description.includes('injection')) return 'code injection techniques';
    if (description.includes('overflow')) return 'buffer overflow exploitation';
    if (description.includes('authentication')) return 'authentication bypass mechanisms';
    return 'security control bypass';
  }

  private identifyAttackVectors(vulnerability: Vulnerability): string[] {
    const vectors = [];
    const description = vulnerability.description.toLowerCase();
    
    if (description.includes('remote')) vectors.push('remote network access');
    if (description.includes('web')) vectors.push('web application interface');
    if (description.includes('local')) vectors.push('local system access');
    
    return vectors.length > 0 ? vectors : ['network-based attack'];
  }

  private assessExploitationRequirements(vulnerability: Vulnerability): string {
    if (vulnerability.exploitAvailable) return 'minimal technical skills with available tools';
    if (vulnerability.severity === 'critical') return 'moderate technical expertise';
    return 'advanced technical knowledge and custom tooling';
  }

  private classifyVulnerabilityType(vulnerability: Vulnerability): string {
    const text = (vulnerability.title + ' ' + vulnerability.description).toLowerCase();
    
    if (text.includes('injection') || text.includes('sql')) return 'injection';
    if (text.includes('authentication') || text.includes('login')) return 'authentication';
    if (text.includes('authorization') || text.includes('access')) return 'authorization';
    if (text.includes('xss') || text.includes('script')) return 'xss';
    if (text.includes('csrf')) return 'csrf';
    
    return 'other';
  }

  // Threat Intelligence Methods
  private checkActiveExploits(vulnerability: Vulnerability): boolean {
    return vulnerability.exploitAvailable || false;
  }

  private async identifyThreatActors(vulnerability: Vulnerability): Promise<string[]> {
    // Simulate threat actor identification
    const actors = [];
    if (vulnerability.severity === 'critical') {
      actors.push('APT Groups', 'Cybercriminal Organizations');
    }
    if (vulnerability.exploitAvailable) {
      actors.push('Script Kiddies', 'Automated Botnets');
    }
    return actors;
  }

  private async findCampaignReferences(vulnerability: Vulnerability): Promise<string[]> {
    // Simulate campaign reference lookup
    return [];
  }

  private async extractIOCs(vulnerability: Vulnerability): Promise<string[]> {
    // Simulate IOC extraction
    return [];
  }

  private mapToMitreTactics(vulnerability: Vulnerability): string[] {
    const tactics = [];
    const description = vulnerability.description.toLowerCase();
    
    if (description.includes('execution')) tactics.push('TA0002 - Execution');
    if (description.includes('privilege')) tactics.push('TA0004 - Privilege Escalation');
    if (description.includes('access')) tactics.push('TA0001 - Initial Access');
    
    return tactics;
  }

  // Report Generation Methods (simplified for space)
  private async generateExecutiveSummary(vulnerabilities: Vulnerability[], analyses: AIAnalysisResult[]): Promise<string> {
    const criticalCount = vulnerabilities.filter(v => v.severity === 'critical').length;
    const highCount = vulnerabilities.filter(v => v.severity === 'high').length;
    
    return `Executive Summary: Assessment identified ${vulnerabilities.length} vulnerabilities, including ${criticalCount} critical and ${highCount} high severity issues requiring immediate attention.`;
  }

  private async generateTechnicalFindings(vulnerabilities: Vulnerability[], analyses: AIAnalysisResult[]): Promise<string> {
    return vulnerabilities.map((vuln, index) => 
      `${vuln.title}: ${analyses[index].technicalAnalysis}`
    ).join('\n\n');
  }

  private async generateRiskAssessment(vulnerabilities: Vulnerability[], analyses: AIAnalysisResult[]): Promise<string> {
    const avgRiskScore = analyses.reduce((sum, analysis) => sum + analysis.riskScore, 0) / analyses.length;
    return `Overall Risk Assessment: Average risk score of ${avgRiskScore.toFixed(1)}/10 indicates significant security exposure requiring immediate remediation efforts.`;
  }

  private async generateRecommendations(vulnerabilities: Vulnerability[], analyses: AIAnalysisResult[]): Promise<string> {
    const allRecommendations = analyses.flatMap(analysis => analysis.recommendedActions);
    const uniqueRecommendations = [...new Set(allRecommendations)];
    return uniqueRecommendations.map((rec, index) => `${index + 1}. ${rec}`).join('\n');
  }

  private async generateAppendices(vulnerabilities: Vulnerability[]): Promise<string> {
    return `Appendix A: Detailed vulnerability listings\n${vulnerabilities.map(v => `${v.cveId || v.id}: ${v.title}`).join('\n')}`;
  }

  private compileVAPTReport(clientInfo: any, sections: any): string {
    return `
# Vulnerability Assessment and Penetration Testing Report
## Client: ${clientInfo.name || 'Client Name'}
## Date: ${new Date().toLocaleDateString()}

## Executive Summary
${sections.executiveSummary}

## Technical Findings
${sections.technicalFindings}

## Risk Assessment
${sections.riskAssessment}

## Recommendations
${sections.recommendations}

## Appendices
${sections.appendices}
    `.trim();
  }

  private generateFallbackReport(vulnerabilities: Vulnerability[], clientInfo: any): string {
    return `
# Vulnerability Assessment Report
## Client: ${clientInfo.name || 'Client Name'}
## Date: ${new Date().toLocaleDateString()}

## Summary
This assessment identified ${vulnerabilities.length} vulnerabilities requiring attention.

## Findings
${vulnerabilities.map(v => `- ${v.title} (${v.severity})`).join('\n')}
    `.trim();
  }
}

export const aiAnalysisService = new AIAnalysisService();
