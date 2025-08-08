import { createContext } from 'react';

export const AppContext = createContext({
  addNotification: (_n: any) => {},
  pushChatMessage: (_m: string) => {},
  setChatMessageHandler: (_h: any) => {}
} as any);
