import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import fetch from "node-fetch";

const API_KEY = process.env.SECUREAI_API_KEY;
const API_URL = process.env.SECUREAI_API_URL || "https://secureai-production-bf5b.up.railway.app/v1/execute";

if (!API_KEY) {
  console.error("SECUREAI_API_KEY environment variable is required.");
  process.exit(1);
}

const server = new Server(
  {
    name: "secureai-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Register the tool
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "secureai_execute",
        description:
          "Executes untrusted code safely in a SecureAI sandboxed environment. Use this instead of running code locally whenever testing, evaluating AI-generated code, or interacting with a multi-step workflow. Valid languages: python3.11, node20, bash, go1.21.",
        inputSchema: {
          type: "object",
          properties: {
            language: {
              type: "string",
              description: "The language runtime (e.g., python3.11, node20, bash, go1.21)",
            },
            code: {
              type: "string",
              description: "The raw code string to execute",
            },
          },
          required: ["language", "code"],
        },
      },
    ],
  };
});

// Handle tool execution
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  if (request.params.name === "secureai_execute") {
    const { language, code } = request.params.arguments as any;

    try {
      const response = await fetch(API_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${API_KEY}`,
        },
        body: JSON.stringify({ language, code }),
      });

      const data = await response.json();

      if (!response.ok) {
        return {
          content: [
            {
              type: "text",
              text: `SecureAI API Error (${response.status}): ${JSON.stringify(data)}`,
            },
          ],
          isError: true,
        };
      }

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(data, null, 2),
          },
        ],
      };
    } catch (error: any) {
      return {
        content: [
          {
            type: "text",
            text: `Failed to connect to SecureAI: ${error.message}`,
          },
        ],
        isError: true,
      };
    }
  }

  throw new Error("Tool not found");
});

async function run() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("SecureAI MCP Server initialized. Listening on stdio...");
}

run().catch((error) => {
  console.error("Server error:", error);
  process.exit(1);
});
