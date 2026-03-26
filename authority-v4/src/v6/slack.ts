export async function sendSlackAlert(params: {
  webhookUrl?: string;
  text: string;
}): Promise<void> {
  const { webhookUrl, text } = params;
  if (!webhookUrl) return;

  try {
    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text })
    });
  } catch (error) {
    console.error("V6 Slack alert failed:", error);
  }
}