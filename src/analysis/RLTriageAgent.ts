import { RankingWeights, VulnerabilityContext, defaultWeights, calculateVulnerabilityScore } from './VulnerabilityRanking';

export class RLTriageAgent {
  private weights: RankingWeights = { ...defaultWeights };
  private learningRate = 0.01;

  score(context: VulnerabilityContext): number {
    return calculateVulnerabilityScore(context, this.weights);
  }

  update(context: VulnerabilityContext, reward: number) {
    const prediction = this.score(context);
    const error = reward - prediction;
    this.weights.assetValue += this.learningRate * error * context.assetValue;
    this.weights.exploitability += this.learningRate * error * context.exploitability;
    this.weights.lateralMovement += this.learningRate * error * context.lateralMovement;
    if (context.activeExploitation) {
      this.weights.activeExploitation += this.learningRate * error * 10;
    }
  }

  getWeights(): RankingWeights {
    return { ...this.weights };
  }
}
