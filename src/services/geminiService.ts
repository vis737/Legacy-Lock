import { GoogleGenAI, Type } from "@google/genai";

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || "" });

function extractJSON(text: string) {
  try {
    const jsonMatch = text.match(/\{[\s\S]*\}|\[[\s\S]*\]/);
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]);
    }
    return JSON.parse(text);
  } catch (e) {
    console.error("Failed to parse JSON from Gemini response:", text);
    return null;
  }
}

export async function generateDigitalWill(userData: any, country: string = "United States") {
  const response = await ai.models.generateContent({
    model: "gemini-3.1-pro-preview",
    contents: `Draft a professional Life Continuity & Legacy Plan based on the following assets and beneficiaries: ${JSON.stringify(userData)}. 
    The user is located in ${country}. 
    
    Requirements:
    1. Adjust the structure based on ${country} inheritance laws.
    2. Include Executor role definitions.
    3. Include Digital Asset Clauses.
    4. Include Conditional Distribution Logic.
    5. Use empowering, professional, and reassuring language.
    6. Clearly distinguish between "AI Draft" and "Legally Reviewed Copy".
    7. Frame it as a "Continuity Plan" rather than just a "Will".`,
    config: {
      systemInstruction: "You are a world-class legal expert in international digital estate planning and continuity law. Your tone is professional, empowering, and life-continuity focused.",
    }
  });

  return response.text;
}

export async function analyzeLifePatterns(activityLogs: any) {
  const response = await ai.models.generateContent({
    model: "gemini-3-flash-preview",
    contents: `Analyze these activity logs for Life Continuity Assurance: ${JSON.stringify(activityLogs)}. 
    Evaluate the user's "Continuity Confidence Score" from 0-100.
    
    Requirements:
    1. Use positive terminology (e.g., "Readiness", "Confidence").
    2. Identify if a "Wellness Confirmation Prompt" or "Trusted Circle Awareness" stage should be initiated.
    3. Return a JSON object with the score and reasoning.`,
    config: {
      responseMimeType: "application/json",
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          confidenceScore: { type: Type.NUMBER, description: "0-100 score of continuity readiness" },
          reasoning: { type: Type.STRING },
          suggestedStage: { type: Type.STRING, description: "One of: Normal, Wellness Confirmation, Trusted Circle Awareness, Legacy Readiness" }
        },
        required: ["confidenceScore", "reasoning", "suggestedStage"]
      }
    }
  });

  return extractJSON(response.text || "{}");
}

export async function scanVaultIntelligence(documents: any) {
  const response = await ai.models.generateContent({
    model: "gemini-3-flash-preview",
    contents: `Scan the following vault metadata for optimization opportunities: ${JSON.stringify(documents)}.
    
    Identify:
    1. Duplicate documents.
    2. Outdated files.
    3. Missing beneficiaries for specific assets.
    4. Incomplete asset categorization.
    
    Return a list of "Vault Enhancement Tips" and "Improvement Opportunities" in JSON format.`,
    config: {
      responseMimeType: "application/json",
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          enhancementTips: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                title: { type: Type.STRING },
                description: { type: Type.STRING },
                impact: { type: Type.STRING }
              }
            }
          },
          healthScore: { type: Type.NUMBER }
        },
        required: ["enhancementTips", "healthScore"]
      }
    }
  });

  return extractJSON(response.text || "{}");
}

export async function draftLegacyMessage(prompt: string, tone: string = "Warm") {
  const response = await ai.models.generateContent({
    model: "gemini-3-flash-preview",
    contents: `Draft a milestone legacy message based on this prompt: "${prompt}". 
    Tone: ${tone}. 
    Categories include: Celebration, Guidance, Milestone Blessing, Personal Reflection.
    Ensure the language is empowering and emotionally intelligent.`,
    config: {
      systemInstruction: "You are an AI Emotional Continuity Assistant, helping users draft meaningful messages for their loved ones.",
    }
  });

  return response.text;
}
