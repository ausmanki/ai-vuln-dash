import { searchCISAKEVForCVE, searchNVDForCVE } from './DataFetchingService';
import { AgentSettings } from '../types/cveData';

interface Notification {
  type: string;
  title: string;
  message: string;
}

/**
 * Periodically polls external feeds for CVE status changes and notifies the UI.
 */
export class UpdateNotifier {
  private interval: any;
  private statuses: Record<string, { kevListed: boolean; nvdSeverity?: string }> = {};

  constructor(
    private getCves: () => string[],
    private settings: AgentSettings,
    private notify: (n: Notification) => void,
    private pushChatMessage?: (msg: string) => void
  ) {}

  start() {
    this.stop();
    this.poll();
    const minutes = this.settings.alertFrequencyMinutes || 60;
    this.interval = setInterval(() => this.poll(), minutes * 60 * 1000);
  }

  stop() {
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
  }

  private async poll() {
    const cves = this.getCves();
    for (const cve of cves) {
      try {
        const [kev, nvd] = await Promise.all([
          searchCISAKEVForCVE(cve, this.settings),
          searchNVDForCVE(cve, this.settings)
        ]);
        const prev = this.statuses[cve];
        const current = {
          kevListed: !!kev?.listed,
          nvdSeverity: nvd?.cvssV3?.baseSeverity
        };
        this.statuses[cve] = current;
        if (!prev) continue;

        const messages: string[] = [];
        if (prev.kevListed !== current.kevListed) {
          messages.push(
            current.kevListed
              ? `${cve} is now listed in CISA KEV`
              : `${cve} removed from CISA KEV`
          );
        }
        if (prev.nvdSeverity !== current.nvdSeverity && current.nvdSeverity) {
          messages.push(`${cve} severity is now ${current.nvdSeverity}`);
        }
        if (messages.length) {
          const msg = messages.join('; ');
          this.notify({ type: 'info', title: 'CVE Update', message: msg });
          this.pushChatMessage?.(`🔔 ${msg}`);
        }
      } catch (e) {
        console.error('UpdateNotifier polling error for', cve, e);
      }
    }
  }
}
