const EnhancedSearchComponent = ({ searchTerm, setSearchTerm }) => (
  <input
    type="text"
    placeholder="Search vulnerabilities..."
    value={searchTerm}
    onChange={(e) => setSearchTerm(e.target.value)}
  />
);

export default EnhancedSearchComponent;
