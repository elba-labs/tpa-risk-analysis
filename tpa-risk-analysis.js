import {
    BedrockRuntimeClient,
    InvokeModelCommand,
} from "@aws-sdk/client-bedrock-runtime";
import pg from "pg";

// Configure PostgreSQL client
const dbConfig = {
    connectionString: "postgresql://user:password@postgres/postgres"
};

// Configure Bedrock client - SDK will auto-load credentials from standard locations
const bedrockClient = new BedrockRuntimeClient({
    region: "us-west-2",
});

// Main function to process organizations and analyze risk
async function analyzeOrganizationsRisk(specificOrgId = null) {
    const client = new pg.Client(dbConfig);

    try {
        await client.connect();
        console.log("Connected to PostgreSQL database");

        let organizations = [];

        // If a specific organization ID is provided, only analyze that one
        if (specificOrgId) {
            const orgQuery = `
        SELECT id, name
        FROM organisations
        WHERE id = $1
      `;

            const orgResult = await client.query(orgQuery, [specificOrgId]);

            if (orgResult.rows.length === 0) {
                console.error(`Organization with ID ${specificOrgId} not found`);
                return;
            }

            organizations = orgResult.rows;
            console.log(`Processing specific organization: ${organizations[0].name}`);
        } else {
            // Otherwise, get the last 10 organizations
            const orgsQuery = `
        SELECT id, name
        FROM organisations
        ORDER BY updated_at DESC
        LIMIT 20
      `;

            const orgsResult = await client.query(orgsQuery);
            organizations = orgsResult.rows;
            console.log(`Fetched ${organizations.length} organizations`);
        }

        // Create results directory if it doesn't exist
        const fs = await import('fs/promises');
        try {
            await fs.access('results');
        } catch {
            await fs.mkdir('results');
            console.log("Created results directory");
        }

        for (const org of organizations) {
            console.log(`\nProcessing organization: ${org.name} (${org.id})`);

            // Get the last 300 issues for this organization from the specific app
            const issuesQuery = `
        SELECT i.id, i.object_at_risk, i.created_at,
               o.id_source, o.url, o.scopes, o.metadata,
               tp.name as third_party_name, tp.handle as third_party_handle,
               tp.category1, tp.category2, tp.is_ai, tp.sensitive_level
        FROM saas.issues i
        LEFT JOIN third_party_apps_module.objects o ON i.id = o.issue_id
        LEFT JOIN third_party_apps_module.third_parties tp ON o.third_party_handle = tp.handle
        WHERE i.organisation_id = $1
          AND i.app_id = $2
          AND o.is_deleted = false
          AND i.remediated_at IS NULL
        ORDER BY i.created_at DESC
        LIMIT 300
      `;

            const issuesResult = await client.query(issuesQuery, [org.id, 'c9515829-aa66-4ed3-8b8e-71a7b729ad09']);
            const issues = issuesResult.rows;
            console.log(`Fetched ${issues.length} issues for organization ${org.name}`);

            if (issues.length === 0) {
                console.log(`No issues found for organization ${org.name}`);
                continue;
            }

            // Prepare data for Bedrock
            const thirdPartyApps = issues.map(issue => ({
                third_party_name: issue.third_party_name,
                third_party_handle: issue.third_party_handle,
                scopes: issue.scopes,
                category1: issue.category1,
                category2: issue.category2,
                is_ai: issue.is_ai,
                sensitive_level: issue.sensitive_level,
                object_at_risk: issue.object_at_risk
            }));

            // Send to Bedrock for analysis
            const riskAnalysis = await analyzeRiskWithBedrock(org.name, thirdPartyApps);
            console.log(`\nRisk analysis for ${org.name}:`);
            console.log(JSON.stringify(riskAnalysis, null, 2));

            // Write results to file
            const safeOrgName = org.name.replace(/[^a-z0-9]/gi, '_').toLowerCase();
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `results/${safeOrgName}_risk_analysis_${timestamp}.json`;

            await fs.writeFile(
                filename,
                JSON.stringify({
                    organization: org.name,
                    organization_id: org.id,
                    timestamp: new Date().toISOString(),
                    analysis: riskAnalysis
                }, null, 2)
            );
            console.log(`Results written to ${filename}`);
        }

    } catch (error) {
        console.error("Error:", error);
    } finally {
        await client.end();
        console.log("Disconnected from PostgreSQL database");
    }
}

// Function to analyze risks using Bedrock
async function analyzeRiskWithBedrock(orgName, thirdPartyApps) {
    try {
        // Deduplicate third-party apps
        const uniqueApps = [];
        const seenHandles = new Set();

        for (const app of thirdPartyApps) {
            if (!seenHandles.has(app.third_party_handle) && app.third_party_name) {
                seenHandles.add(app.third_party_handle);
                uniqueApps.push(app);
            }
        }

        const prompt = `
Organization: ${orgName}

Below is a list of third-party SaaS applications connected to this organization, along with their scopes:

${uniqueApps.map((app, index) => `
${index + 1}. ${app.third_party_name || 'Unknown SaaS'}
   Scopes: ${app.scopes || 'None specified'}
`).join('')}

Based on your knowledge of SaaS applications and their typical security risks, identify the TOP 3 MOST RISKY applications from this list. Consider the permissions granted and your understanding of what these applications can do.

IMPORTANT GUIDANCE:
- Focus on potentially shady, nsfw, or less-established applications over widely trusted providers like Microsoft, Google, or Adobe
- Pay special attention to applications with unusually broad permissions
- Be suspicious of applications requesting more permissions than their core functionality would require
- Consider the reputation and trustworthiness of the application provider
- Unusual or unknown application names should receive extra scrutiny

For each chosen application, provide:
1. A detailed explanation of why you consider it risky, focusing on:
   - What sensitive data it might access
   - What problematic actions it could take with its permissions
   - Any known security concerns with this type of application
2. The original permission scopes that led to this assessment

Return a JSON object with this structure:
{
  "top_risky_apps": [
    {
      "app_name": "App Name",
      "risk_level": "High/Medium/Low",
      "explanation": "Detailed explanation of why this app is risky...",
      "original_scopes": "The exact scopes string from the input",
      "risk_factors": ["Factor 1", "Factor 2", ...],
      "recommended_actions": ["Action 1", "Action 2", ...]
    },
    ...
  ]
}

Only return the JSON object, no other text.
`;

        const body = {
            max_tokens: 4000,
            anthropic_version: "bedrock-2023-05-31",
            messages: [
                {
                    role: "user",
                    content: [
                        {
                            type: "text",
                            text: prompt
                        }
                    ]
                }
            ]
        };

        // Build a lookup table for finding original scopes by app name
        const appScopesMap = {};
        for (const app of uniqueApps) {
            if (app.third_party_name) {
                appScopesMap[app.third_party_name] = app.scopes || '';
            }
        }

        const command = new InvokeModelCommand({
            modelId: "anthropic.claude-3-5-haiku-20241022-v1:0",
            contentType: "application/json",
            accept: "application/json",
            body: JSON.stringify(body)
        });

        const response = await bedrockClient.send(command);
        const responseBody = JSON.parse(new TextDecoder().decode(response.body));

        // Parse the response text as JSON
        try {
            const riskAnalysis = JSON.parse(responseBody.content[0].text);

            // Add original scopes to each risky app if not already included
            if (riskAnalysis.top_risky_apps) {
                riskAnalysis.top_risky_apps.forEach(app => {
                    if (!app.original_scopes && appScopesMap[app.app_name]) {
                        app.original_scopes = appScopesMap[app.app_name];
                    }
                });
            }

            return riskAnalysis;
        } catch (error) {
            console.error("Error parsing Bedrock response:", error);
            return { error: "Failed to parse response", raw_response: responseBody.content[0].text };
        }
    } catch (error) {
        console.error("Error processing with Bedrock:", error);
        return { error: error.message };
    }
}

// Simple package.json creator that only executes if it doesn't exist
(async () => {
    const fs = await import('fs/promises');

    try {
        await fs.access("package.json");
    } catch {
        // Only create package.json if it doesn't exist
        const packageJson = {
            "type": "module",
            "dependencies": {
                "@aws-sdk/client-bedrock-runtime": "latest",
                "pg": "latest"
            }
        };

        await fs.writeFile("package.json", JSON.stringify(packageJson, null, 2));
        console.log("Created package.json with required dependencies");
    }

    // Check if organization ID is provided as a command-line argument
    const specificOrgId = process.argv[2];

    console.log("Starting risk analysis...");
    if (specificOrgId) {
        console.log(`Analyzing specific organization with ID: ${specificOrgId}`);
    }

    await analyzeOrganizationsRisk(specificOrgId);
    console.log("Analysis complete!");
})();
