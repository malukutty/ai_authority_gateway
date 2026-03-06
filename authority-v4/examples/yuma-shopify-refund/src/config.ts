export const policy = {
  killSwitch: false,
  denyByDefault: true,
  thresholds: {
    ai_agent: { autoExecuteUpTo: 2500, requireManagerAbove: 2500, requireDirectorAbove: 20000 },
    human_agent: { autoExecuteUpTo: 10000, requireManagerAbove: 10000, requireDirectorAbove: 50000 },
    manager: { autoExecuteUpTo: 50000, requireManagerAbove: 50000, requireDirectorAbove: 200000 },
    director: { autoExecuteUpTo: 200000, requireManagerAbove: 200000, requireDirectorAbove: 500000 }
  }
};