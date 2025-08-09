import { createContext, useState } from 'react';

const AppContext = createContext();

const AppProvider = ({ children }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [automateResponse, setAutomateResponse] = useState(false);

  return (
    <AppContext.Provider value={{
      searchTerm, setSearchTerm,
      automateResponse, setAutomateResponse
    }}>
      {children}
    </AppContext.Provider>
  );
};

export { AppContext, AppProvider };
