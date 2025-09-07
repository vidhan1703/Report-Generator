import React, { useState, useCallback } from 'react';
import { Search, Filter, X, Shield, AlertTriangle, Info } from 'lucide-react';
import { SearchFilters, SeverityLevel } from '../types/vulnerability';

interface SearchBarProps {
  onSearch: (query: string, filters?: SearchFilters) => void;
  loading?: boolean;
  placeholder?: string;
}

const SearchBar: React.FC<SearchBarProps> = ({ 
  onSearch, 
  loading = false, 
  placeholder = "Search vulnerabilities (e.g., CVE-2024-0001, SQL injection, XSS...)" 
}) => {
  const [query, setQuery] = useState('');
  const [showFilters, setShowFilters] = useState(false);
  const [filters, setFilters] = useState<SearchFilters>({});

  const handleSearch = useCallback(() => {
    onSearch(query, filters);
  }, [query, filters, onSearch]);

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSearch();
    }
  };

  const toggleSeverity = (severity: SeverityLevel) => {
    setFilters(prev => {
      const currentSeverities = prev.severity || [];
      const newSeverities = currentSeverities.includes(severity)
        ? currentSeverities.filter(s => s !== severity)
        : [...currentSeverities, severity];
      
      return {
        ...prev,
        severity: newSeverities.length > 0 ? newSeverities : undefined
      };
    });
  };

  const clearFilters = () => {
    setFilters({});
  };

  const hasActiveFilters = Object.keys(filters).some(key => {
    const value = filters[key as keyof SearchFilters];
    return Array.isArray(value) ? value.length > 0 : value !== undefined;
  });

  const getSeverityIcon = (severity: SeverityLevel) => {
    switch (severity) {
      case 'critical':
        return <Shield className="w-4 h-4" />;
      case 'high':
      case 'medium':
        return <AlertTriangle className="w-4 h-4" />;
      default:
        return <Info className="w-4 h-4" />;
    }
  };

  const getSeverityColor = (severity: SeverityLevel, isSelected: boolean) => {
    const baseClasses = "flex items-center space-x-2 px-3 py-2 rounded-lg border transition-all duration-200 cursor-pointer";
    
    if (isSelected) {
      switch (severity) {
        case 'critical':
          return `${baseClasses} bg-red-100 border-red-300 text-red-800`;
        case 'high':
          return `${baseClasses} bg-orange-100 border-orange-300 text-orange-800`;
        case 'medium':
          return `${baseClasses} bg-yellow-100 border-yellow-300 text-yellow-800`;
        case 'low':
          return `${baseClasses} bg-blue-100 border-blue-300 text-blue-800`;
        default:
          return `${baseClasses} bg-gray-100 border-gray-300 text-gray-800`;
      }
    }
    
    return `${baseClasses} bg-white border-gray-200 text-gray-600 hover:bg-gray-50`;
  };

  return (
    <div className="w-full max-w-4xl mx-auto">
      {/* Main Search Bar */}
      <div className="relative">
        <div className="relative">
          <Search className="absolute left-4 top-1/2 transform -translate-y-1/2 text-slate-400 w-5 h-5" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder={placeholder}
            className="search-input pl-12 pr-24"
            disabled={loading}
          />
          <div className="absolute right-2 top-1/2 transform -translate-y-1/2 flex items-center space-x-2">
            <button
              onClick={() => setShowFilters(!showFilters)}
              className={`p-2 rounded-lg transition-all duration-200 ${
                showFilters || hasActiveFilters
                  ? 'bg-primary-100 text-primary-600'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
              title="Toggle Filters"
            >
              <Filter className="w-4 h-4" />
              {hasActiveFilters && (
                <span className="absolute -top-1 -right-1 w-2 h-2 bg-primary-600 rounded-full"></span>
              )}
            </button>
            <button
              onClick={handleSearch}
              disabled={loading}
              className="btn-primary px-4 py-2 text-sm"
            >
              {loading ? (
                <div className="loading-spinner w-4 h-4"></div>
              ) : (
                'Search'
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Filters Panel */}
      {showFilters && (
        <div className="mt-4 p-6 bg-white dark:bg-slate-800 rounded-xl shadow-lg border border-slate-200 dark:border-slate-700 animate-slide-up">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
              Search Filters
            </h3>
            {hasActiveFilters && (
              <button
                onClick={clearFilters}
                className="flex items-center space-x-1 text-sm text-slate-600 hover:text-slate-800 transition-colors"
              >
                <X className="w-4 h-4" />
                <span>Clear All</span>
              </button>
            )}
          </div>

          {/* Severity Filter */}
          <div className="mb-6">
            <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">
              Severity Level
            </h4>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
              {(['critical', 'high', 'medium', 'low'] as SeverityLevel[]).map((severity) => {
                const isSelected = filters.severity?.includes(severity) || false;
                return (
                  <div
                    key={severity}
                    onClick={() => toggleSeverity(severity)}
                    className={getSeverityColor(severity, isSelected)}
                  >
                    {getSeverityIcon(severity)}
                    <span className="text-sm font-medium capitalize">
                      {severity}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Exploit Available Filter */}
          <div className="mb-6">
            <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">
              Exploit Availability
            </h4>
            <div className="flex space-x-4">
              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={filters.hasExploit === true}
                  onChange={(e) => setFilters(prev => ({
                    ...prev,
                    hasExploit: e.target.checked ? true : undefined
                  }))}
                  className="rounded border-slate-300 text-primary-600 focus:ring-primary-500"
                />
                <span className="text-sm text-slate-700 dark:text-slate-300">
                  Has Public Exploit
                </span>
              </label>
            </div>
          </div>

          {/* CVSS Score Range */}
          <div className="mb-4">
            <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">
              CVSS Score Range
            </h4>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <label className="text-sm text-slate-600">Min:</label>
                <input
                  type="number"
                  min="0"
                  max="10"
                  step="0.1"
                  value={filters.cvssRange?.min || ''}
                  onChange={(e) => setFilters(prev => ({
                    ...prev,
                    cvssRange: {
                      ...prev.cvssRange,
                      min: e.target.value ? parseFloat(e.target.value) : 0,
                      max: prev.cvssRange?.max || 10
                    }
                  }))}
                  className="w-20 px-2 py-1 border border-slate-300 rounded text-sm"
                  placeholder="0.0"
                />
              </div>
              <div className="flex items-center space-x-2">
                <label className="text-sm text-slate-600">Max:</label>
                <input
                  type="number"
                  min="0"
                  max="10"
                  step="0.1"
                  value={filters.cvssRange?.max || ''}
                  onChange={(e) => setFilters(prev => ({
                    ...prev,
                    cvssRange: {
                      min: prev.cvssRange?.min || 0,
                      ...prev.cvssRange,
                      max: e.target.value ? parseFloat(e.target.value) : 10
                    }
                  }))}
                  className="w-20 px-2 py-1 border border-slate-300 rounded text-sm"
                  placeholder="10.0"
                />
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SearchBar;
