# Third-Party App Risk Analysis

This script analyzes the risk level of third-party applications connected to organizations in your database. It uses AWS Bedrock (Claude 3.5 Haiku) to evaluate the risk based on permissions, data sensitivity, security implications, and AI usage.

## Features

- Retrieves the last 10 organizations from your database
- For each organization, fetches the last 100 issues from a specific app
- Analyzes third-party app data using AWS Bedrock
- Identifies the top 3 riskiest applications with risk factors and recommended actions
- Outputs analysis results in a structured JSON format

## Prerequisites

- Node.js 16+
- AWS Account with Bedrock access
- PostgreSQL database access

## Setup

1. Clone this repository
2. Install dependencies:
   ```
   npm install
   ```
3. AWS credentials configuration:
   - The script uses the AWS SDK's default credential provider chain
   - Credentials can be set up in any standard AWS way:
     - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
     - AWS credentials file (~/.aws/credentials)
     - EC2 instance profile or container role (if running in AWS)

## Usage

Run the script:

```
node tpa-risk-analysis.js
```

The script will:
1. Connect to your PostgreSQL database
2. Fetch organizations and their third-party app data
3. Send data to AWS Bedrock for risk analysis
4. Output the results to the console

## Output

The risk analysis results are output in the following JSON format:

```json
{
  "top_risky_apps": [
    {
      "app_name": "App Name",
      "risk_level": "High/Medium/Low",
      "risk_factors": ["Factor 1", "Factor 2", ...],
      "recommended_actions": ["Action 1", "Action 2", ...]
    },
    ...
  ]
}
```

## Security Considerations

- Database credentials are hardcoded in the script for this example only
- In a production environment, move all credentials to environment variables or secure credential stores
- Ensure AWS IAM roles have appropriate permissions for Bedrock
- Consider encrypting sensitive data before storing it
