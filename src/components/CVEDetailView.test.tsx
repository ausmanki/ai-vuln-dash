import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { AppContext } from '../contexts/AppContext';
import CVEDetailView from './CVEDetailView';
import { APIService } from '../services/APIService';

// Mock the APIService and logger
jest.mock('../services/APIService');
jest.mock('../db/EnhancedVectorDatabase', () => ({
  ragDatabase: {
    initialize: jest.fn(),
    addDocument: jest.fn(),
    search: jest.fn(),
  },
}));
jest.mock('../utils/logger', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
    setVerbose: jest.fn(),
  },
}));

const mockVulnerability = {
  cve: {
    id: 'CVE-2024-12345',
    description: 'A test vulnerability description.',
    published: '2024-01-01T00:00:00.000Z',
    lastModified: '2024-01-01T00:00:00.000Z',
    vulnStatus: 'Analyzed',
    cvssV3: {
      baseScore: 7.5,
      baseSeverity: 'HIGH',
    },
  },
  epss: {
    epss: '0.95',
  }
};

const mockContext = {
  settings: { darkMode: false },
  addNotification: jest.fn(),
};

const renderWithContext = (component) => {
  return render(
    <AppContext.Provider value={mockContext}>
      {component}
    </AppContext.Provider>
  );
};

describe('CVEDetailView', () => {
  beforeEach(() => {
    // Reset mocks before each test
    jest.clearAllMocks();
  });

  it('renders the component with vulnerability data', () => {
    renderWithContext(<CVEDetailView vulnerability={mockVulnerability} />);
    expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    expect(screen.getByText(/A test vulnerability description/)).toBeInTheDocument();
  });

  it('switches between tabs', () => {
    renderWithContext(<CVEDetailView vulnerability={mockVulnerability} />);
    fireEvent.click(screen.getByText('Remediation'));
    expect(screen.getByText(/No Remediation Suggestions Available/)).toBeInTheDocument();
  });

  it('fetches and displays remediation suggestions', async () => {
    APIService.generateRemediationSuggestions.mockResolvedValue({ suggestions: 'Test remediation suggestions' });
    renderWithContext(<CVEDetailView vulnerability={mockVulnerability} />);
    fireEvent.click(screen.getByText('Remediation'));
    fireEvent.click(screen.getByText('Generate Suggestions'));

    await waitFor(() => {
      expect(screen.getByText('Test remediation suggestions')).toBeInTheDocument();
    });
  });

  it('fetches and displays threat intelligence', async () => {
    APIService.fetchAIThreatIntelligence.mockResolvedValue({ summary: 'Test threat intelligence' });
    renderWithContext(<CVEDetailView vulnerability={mockVulnerability} />);
    fireEvent.click(screen.getByText('Threat-intel'));
    fireEvent.click(screen.getByText('Generate Summary'));

    await waitFor(() => {
      expect(screen.getByText('Test threat intelligence')).toBeInTheDocument();
    });
  });

  it('fetches and displays related vulnerabilities', async () => {
    APIService.findRelatedVulnerabilities.mockResolvedValue({ related: 'CVE-2024-54321' });
    renderWithContext(<CVEDetailView vulnerability={mockVulnerability} />);
    fireEvent.click(screen.getByText('Related-cves'));
    fireEvent.click(screen.getByText('Find Related CVEs'));

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-54321')).toBeInTheDocument();
    });
  });

  it('displays an error message if fetching remediation suggestions fails', async () => {
    APIService.generateRemediationSuggestions.mockRejectedValue(new Error('Test error'));
    renderWithContext(<CVEDetailView vulnerability={mockVulnerability} />);
    fireEvent.click(screen.getByText('Remediation'));
    fireEvent.click(screen.getByText('Generate Suggestions'));

    await waitFor(() => {
      expect(mockContext.addNotification).toHaveBeenCalledWith({
        type: 'error',
        title: 'Failed to generate suggestions',
        message: 'Could not generate remediation suggestions. The AI model may be offline or the request may have timed out. \n\n Test error',
      });
    });
  });
});
