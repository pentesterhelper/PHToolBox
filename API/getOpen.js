import { GoogleGenAI } from "@google/genai";

const ai = new GoogleGenAI({ apiKey: "AIzaSyD64BiPKGTqiJPwL5qg7BJjH9gaclg1_pM" });

async function main() {
  const response = await ai.models.generateContent({
    model: "gemini-2.5-flash",
    contents: "rewrite in human language: ",
  });
  console.log(response.text);
}

main();