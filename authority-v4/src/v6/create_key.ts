import { createV6ApiKey } from "./keys.js";

const { token, record } = createV6ApiKey({
  userId: "bhavia",
  visibility: "public",
  dailySpendLimitUsd: 2,
  teamDailyLimitUsd: 10,
  requestsPerMinute: 60
});

console.log("V6 API key created:");
console.log(token);
console.log(record); 