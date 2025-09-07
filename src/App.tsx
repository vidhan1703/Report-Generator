import React, { useState, useEffect } from 'react';
import { Shield, TrendingUp, AlertTriangle, Database, Github, ExternalLink, FileText, Download, Settings, Moon, Sun } from 'lucide-react';
import SearchBar from './components/SearchBar';
import VulnerabilityCard from './components/VulnerabilityCard';
import ReportGenerator from './components/ReportGenerator';
import ExportMenu from './components/ExportMenu';
import LoadingSpinner from './components/LoadingSpinner';
import { Vulnerability, SearchFilters, SearchResult } from './types/vulnerability';
import { vulnerabilityService } from './services/vulnerabilityService';
import { aiAnalysisService } from './services/aiAnalysisService';

function App() {
  const [searchResults, setSearchResults] = useState<SearchResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [selectedVulnerability, setSelectedVulnerability] = useState<Vulnerability | null>(null);
  const [stats, setStats] = useState<any>(null);
  const [showReportGenerator, setShowReportGenerator] = useState(false);
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [darkMode, setDarkMode] = useState(false);
  const [sortBy, setSortBy] = useState<'severity' | 'date' | 'cvss'>('severity');
  const [aiAnalysis, setAiAnalysis] = useState<any>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [isRealTimeSearch, setIsRealTimeSearch] = useState(true);

  useEffect(() => {
    // Load initial data and stats
    loadStats();
    handleSearch('', undefined); // Load all vulnerabilities initially
  }, []);

  const loadStats = async () => {
    try {
      const statsData = await vulnerabilityService.getVulnerabilityStats();
      setStats(statsData);
    } catch (error) {
      console.error('Failed to load stats:', error);
    }
  };

  const handleSearch = async (query: string, filters?: SearchFilters) => {
    if (!query.trim()) {
      setSearchResults(null);
      return;
    }

    setLoading(true);
    setSearchQuery(query);

    try {
      // Show immediate feedback
      console.log(`🔍 Searching for: "${query}"`);
      console.log('📡 Querying multiple vulnerability databases...');

      const results = await vulnerabilityService.searchVulnerabilities(query, filters);
      setSearchResults(results);

      // Log search results for user feedback
      console.log(`✅ Found ${results.totalCount} vulnerabilities from multiple sources`);

      // Perform AI analysis on the first few results for enhanced insights
      if (results.vulnerabilities.length > 0 && isRealTimeSearch) {
        console.log('🤖 Performing AI-powered analysis...');
        try {
          const analysis = await aiAnalysisService.analyzeVulnerability(results.vulnerabilities[0]);
          setAiAnalysis(analysis);
          console.log('✅ AI analysis complete');
        } catch (aiError) {
          console.warn('AI analysis failed, continuing with basic results:', aiError);
        }
      }

    } catch (error) {
      console.error('❌ Search error:', error);
      // Fallback to mock data if APIs fail
      console.log('🔄 Falling back to cached/mock data...');
      try {
        const fallbackResults = await vulnerabilityService.searchVulnerabilities(query, filters);
        setSearchResults(fallbackResults);
      } catch (fallbackError) {
        console.error('Fallback search also failed:', fallbackError);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleVulnerabilityClick = (vulnerability: Vulnerability) => {
    setSelectedVulnerability(vulnerability);
  };

  const closeModal = () => {
    setSelectedVulnerability(null);
  };

  const toggleDarkMode = () => {
    setDarkMode(!darkMode);
    document.documentElement.classList.toggle('dark');
  };

  const sortVulnerabilities = (vulnerabilities: Vulnerability[]) => {
    return [...vulnerabilities].sort((a, b) => {
      switch (sortBy) {
        case 'severity':
          const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
          return (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
        case 'date':
          return new Date(b.publishedDate || '').getTime() - new Date(a.publishedDate || '').getTime();
        case 'cvss':
          return (b.cvssScore || 0) - (a.cvssScore || 0);
        default:
          return 0;
      }
    });
  };

  return (
    <div className={`min-h-screen bg-gradient-to-br from-slate-50 to-blue-50 dark:from-slate-900 dark:to-slate-800 ${darkMode ? 'dark' : ''}`}>
      {/* Header */}
      <header className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-sm border-b border-slate-200 dark:border-slate-700 sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-primary-600 rounded-lg">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">
                  SecureVault Pro
                </h1>
                <p className="text-sm text-slate-600 dark:text-slate-400">
                  Advanced Vulnerability Research Platform
                </p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <label className="text-sm text-slate-600 dark:text-slate-300">Real-time APIs:</label>
                <button
                  onClick={() => setIsRealTimeSearch(!isRealTimeSearch)}
                  className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                    isRealTimeSearch
                      ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
                      : 'bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-400'
                  }`}
                >
                  {isRealTimeSearch ? '🟢 LIVE' : '⚪ CACHED'}
                </button>
              </div>
              <button
                onClick={toggleDarkMode}
                className="p-2 text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100 transition-colors"
                title="Toggle Dark Mode"
              >
                {darkMode ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
              </button>
              <button
                onClick={() => setShowExportMenu(true)}
                className="p-2 text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100 transition-colors"
                title="Export Data"
              >
                <Download className="w-5 h-5" />
              </button>
              <button
                onClick={() => setShowReportGenerator(true)}
                className="p-2 text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100 transition-colors"
                title="Generate Report"
              >
                <FileText className="w-5 h-5" />
              </button>
              <a
                href="https://github.com"
                target="_blank"
                rel="noopener noreferrer"
                className="p-2 text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100 transition-colors"
              >
                <Github className="w-5 h-5" />
              </a>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Hero Section */}
        <div className="text-center mb-12">
          <h2 className="text-4xl font-bold text-slate-900 dark:text-slate-100 mb-4">
            Discover Security Vulnerabilities
          </h2>
          <p className="text-xl text-slate-600 dark:text-slate-400 mb-8 max-w-3xl mx-auto">
            Search through comprehensive vulnerability databases, generate penetration testing reports, 
            and stay ahead of security threats with our advanced research platform.
          </p>
          
          {/* Search Bar */}
          <SearchBar onSearch={handleSearch} loading={loading} />

          {/* Search Status */}
          {loading && (
            <div className="mt-4 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
              <div className="flex items-center space-x-3">
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-600"></div>
                <div>
                  <p className="text-blue-800 dark:text-blue-200 font-medium">
                    {isRealTimeSearch ? 'Searching real-time vulnerability databases...' : 'Searching cached data...'}
                  </p>
                  <p className="text-blue-600 dark:text-blue-300 text-sm">
                    {isRealTimeSearch ? 'Querying NVD, GitHub Security, OSV, and other sources' : 'Using local cache for faster results'}
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* AI Analysis Display */}
          {aiAnalysis && searchResults && (
            <div className="mt-6 p-6 bg-gradient-to-r from-purple-50 to-blue-50 dark:from-purple-900/20 dark:to-blue-900/20 rounded-xl border border-purple-200 dark:border-purple-800">
              <div className="flex items-center space-x-3 mb-4">
                <div className="p-2 bg-purple-600 rounded-lg">
                  <TrendingUp className="w-5 h-5 text-white" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
                    🤖 AI-Powered Analysis
                  </h3>
                  <p className="text-sm text-slate-600 dark:text-slate-400">
                    Enhanced insights for "{searchQuery}"
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                <div className="bg-white dark:bg-slate-800 p-4 rounded-lg border border-slate-200 dark:border-slate-700">
                  <div className="text-2xl font-bold text-red-600 dark:text-red-400">
                    {aiAnalysis.riskScore.toFixed(1)}/10
                  </div>
                  <div className="text-sm text-slate-600 dark:text-slate-400">Risk Score</div>
                </div>
                <div className="bg-white dark:bg-slate-800 p-4 rounded-lg border border-slate-200 dark:border-slate-700">
                  <div className="text-2xl font-bold text-orange-600 dark:text-orange-400">
                    {Math.round(aiAnalysis.exploitProbability * 100)}%
                  </div>
                  <div className="text-sm text-slate-600 dark:text-slate-400">Exploit Probability</div>
                </div>
                <div className="bg-white dark:bg-slate-800 p-4 rounded-lg border border-slate-200 dark:border-slate-700">
                  <div className={`text-2xl font-bold ${
                    aiAnalysis.mitigationPriority === 'immediate' ? 'text-red-600 dark:text-red-400' :
                    aiAnalysis.mitigationPriority === 'high' ? 'text-orange-600 dark:text-orange-400' :
                    'text-yellow-600 dark:text-yellow-400'
                  }`}>
                    {aiAnalysis.mitigationPriority.toUpperCase()}
                  </div>
                  <div className="text-sm text-slate-600 dark:text-slate-400">Priority</div>
                </div>
              </div>

              <div className="bg-white dark:bg-slate-800 p-4 rounded-lg border border-slate-200 dark:border-slate-700">
                <h4 className="font-medium text-slate-900 dark:text-slate-100 mb-2">Business Impact Analysis:</h4>
                <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
                  {aiAnalysis.businessImpact}
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Stats Cards */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
            <div className="bg-white dark:bg-slate-800 rounded-xl p-4 shadow-lg border border-slate-200 dark:border-slate-700">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-600 dark:text-slate-400">Total</p>
                  <p className="text-2xl font-bold text-slate-900 dark:text-slate-100">{stats.total}</p>
                </div>
                <Database className="w-8 h-8 text-primary-600" />
              </div>
            </div>
            <div className="bg-white dark:bg-slate-800 rounded-xl p-4 shadow-lg border border-slate-200 dark:border-slate-700">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-600 dark:text-slate-400">Critical</p>
                  <p className="text-2xl font-bold text-red-600">{stats.critical}</p>
                </div>
                <AlertTriangle className="w-8 h-8 text-red-600" />
              </div>
            </div>
            <div className="bg-white dark:bg-slate-800 rounded-xl p-4 shadow-lg border border-slate-200 dark:border-slate-700">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-600 dark:text-slate-400">High</p>
                  <p className="text-2xl font-bold text-orange-600">{stats.high}</p>
                </div>
                <TrendingUp className="w-8 h-8 text-orange-600" />
              </div>
            </div>
            <div className="bg-white dark:bg-slate-800 rounded-xl p-4 shadow-lg border border-slate-200 dark:border-slate-700">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-600 dark:text-slate-400">Medium</p>
                  <p className="text-2xl font-bold text-yellow-600">{stats.medium}</p>
                </div>
                <TrendingUp className="w-8 h-8 text-yellow-600" />
              </div>
            </div>
            <div className="bg-white dark:bg-slate-800 rounded-xl p-4 shadow-lg border border-slate-200 dark:border-slate-700">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-600 dark:text-slate-400">Exploits</p>
                  <p className="text-2xl font-bold text-purple-600">{stats.withExploits}</p>
                </div>
                <Shield className="w-8 h-8 text-purple-600" />
              </div>
            </div>
          </div>
        )}

        {/* Search Results */}
        {loading && (
          <div className="py-12">
            <LoadingSpinner size="lg" text="Searching vulnerabilities..." />
          </div>
        )}

        {searchResults && !loading && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <h3 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
                Search Results
              </h3>
              <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-2">
                  <label className="text-sm text-slate-600 dark:text-slate-400">Sort by:</label>
                  <select
                    value={sortBy}
                    onChange={(e) => setSortBy(e.target.value as any)}
                    className="px-3 py-1 border border-slate-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  >
                    <option value="severity">Severity</option>
                    <option value="date">Date</option>
                    <option value="cvss">CVSS Score</option>
                  </select>
                </div>
                <span className="text-slate-600 dark:text-slate-400">
                  {searchResults.totalCount} vulnerabilities found
                </span>
              </div>
            </div>
            
            {searchResults.vulnerabilities.length === 0 ? (
              <div className="text-center py-12">
                <AlertTriangle className="w-16 h-16 text-slate-400 mx-auto mb-4" />
                <h3 className="text-xl font-semibold text-slate-900 dark:text-slate-100 mb-2">
                  No vulnerabilities found
                </h3>
                <p className="text-slate-600 dark:text-slate-400">
                  Try adjusting your search terms or filters
                </p>
              </div>
            ) : (
              <div className="grid gap-6">
                {sortVulnerabilities(searchResults.vulnerabilities).map((vulnerability) => (
                  <VulnerabilityCard
                    key={vulnerability.id}
                    vulnerability={vulnerability}
                    onClick={() => handleVulnerabilityClick(vulnerability)}
                  />
                ))}
              </div>
            )}
          </div>
        )}
      </main>

      {/* Vulnerability Detail Modal */}
      {selectedVulnerability && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-slate-200 dark:border-slate-700">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
                  {selectedVulnerability.title}
                </h2>
                <button
                  onClick={closeModal}
                  className="p-2 text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100 transition-colors"
                >
                  ✕
                </button>
              </div>
              {selectedVulnerability.cveId && (
                <p className="text-lg text-slate-600 dark:text-slate-400 font-mono mt-2">
                  {selectedVulnerability.cveId}
                </p>
              )}
            </div>
            
            <div className="p-6 space-y-6">
              <div>
                <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100 mb-3">Description:</h3>
                <p className="text-slate-700 dark:text-slate-300 leading-relaxed">
                  {selectedVulnerability.description}
                </p>
              </div>
              
              <div>
                <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100 mb-3">Impact:</h3>
                <p className="text-slate-700 dark:text-slate-300 leading-relaxed">
                  {selectedVulnerability.impact}
                </p>
              </div>
              
              <div>
                <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100 mb-3">Recommendation:</h3>
                <p className="text-slate-700 dark:text-slate-300 leading-relaxed">
                  {selectedVulnerability.recommendation}
                </p>
              </div>
              
              {selectedVulnerability.references && selectedVulnerability.references.length > 0 && (
                <div>
                  <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100 mb-3">References:</h3>
                  <div className="space-y-2">
                    {selectedVulnerability.references.map((ref, index) => (
                      <a
                        key={index}
                        href={ref.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center space-x-2 text-primary-600 hover:text-primary-700 transition-colors"
                      >
                        <ExternalLink className="w-4 h-4" />
                        <span>{ref.title}</span>
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Report Generator Modal */}
      {showReportGenerator && searchResults && (
        <ReportGenerator
          vulnerabilities={searchResults.vulnerabilities}
          onClose={() => setShowReportGenerator(false)}
        />
      )}

      {/* Export Menu Modal */}
      {showExportMenu && searchResults && (
        <ExportMenu
          vulnerabilities={searchResults.vulnerabilities}
          onClose={() => setShowExportMenu(false)}
        />
      )}
    </div>
  );
}

export default App;
