import axios from "axios";
import { policy } from "./config";

const AUTHORITY_URL = process.env.AUTHORITY_URL || "http://localhost:8787/v4/evaluate";

async function main() {
  const req = {
    commitment: {
      type: "refund",
      env: "prod",
      actorLane: "director",
      amountCents: 100,       // $1
      currency: "usd",
      orderId: "demo-order-123",
      customerId: "demo-customer-456"
    },
    policy
  };

  const { data } = await axios.post(AUTHORITY_URL, req, {
    headers: { "Content-Type": "application/json" }
  });

  console.log(JSON.stringify(data, null, 2));
}

main().catch((e) => {
  console.error(e?.response?.data || e);
  process.exit(1);
});