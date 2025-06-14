# IntelliMail - Advanced Email Validation Service powered by AWS Lambda

IntelliMail is a serverless application built with AWS services that provides comprehensive email validation through advanced multi-layered analysis, helping businesses prevent fake registrations, improve data quality, and detect fraudulent email addresses.

## Problem Statement

Email validation is critical for business success, but simple domain checking isn't enough. Modern threats include:
- **Disposable emails**: Temporary services that expire quickly
- **Invalid domains**: Non-existent or misconfigured email domains
- **Suspicious patterns**: Fraudulent email structures and generators
- **Poor reputation domains**: Domains associated with spam or abuse
- **Newly registered domains**: Often used for temporary fraud
- **SMTP issues**: Domains without proper mail server configuration
- **Fake providers**: Domains mimicking legitimate email services

Traditional validation methods miss these sophisticated threats, leading to:
- Fake user registrations and inflated metrics
- Reduced email deliverability rates
- Increased spam and fraudulent activities
- Poor data quality for marketing campaigns
- Customer communication failures

## Solution Overview

This application provides a comprehensive email validation API that performs 10 different validation checks in parallel, going far beyond simple disposable domain detection. It analyzes DNS records, domain reputation, SMTP configuration, suspicious patterns, and more to provide a complete email trustworthiness assessment.

## Architecture & AWS Lambda Usage

### Core AWS Lambda Functions

1. **Email Validator Function** (`emailValidator.handler`)
   - **Trigger**: API Gateway HTTP POST requests
   - **Purpose**: Comprehensive email validation using 10 different validation checks
   - **Process**: Multi-layered validation including:
     - `checkDisposableDomain()` - Checks against known temporary email providers
     - `checkDNSRecords()` - Validates MX record existence and configuration
     - `checkEmailPattern()` - Advanced regex pattern matching for local part
     - `checkDomainReputation()` - Analyzes domain reputation and trustworthiness
     - `checkDomainAge()` - Verifies domain registration age (newer domains are riskier)
     - `checkSMTPServer()` - Tests SMTP server availability and response
     - `checkDomainRegistrar()` - Identifies suspicious or known problematic registrars
     - `checkSuspiciousPatterns()` - Detects suspicious email patterns and structures
     - `checkCommonProviders()` - Validates against legitimate email providers
     - `checkDomainLength()` - Flags unusually short/long domains as suspicious

2. **Domain Updater Function** (`domainUpdater.handler`)
   - **Trigger**: EventBridge scheduled event (daily)
   - **Purpose**: Automatically updates the disposable domains database
   - **Process**: Fetches latest domain lists from multiple sources, updates DynamoDB

3. **Analytics Function** (`analytics.handler`)
   - **Trigger**: API Gateway HTTP GET requests
   - **Purpose**: Provides usage analytics and insights
   - **Process**: Aggregates validation data from DynamoDB, returns metrics

### Serverless Architecture Benefits

- **Auto-scaling**: Lambda functions scale automatically based on demand
- **Cost-effective**: Pay only for actual usage, no idle server costs
- **High availability**: Built-in fault tolerance across multiple AZs
- **Zero server management**: Focus on business logic, not infrastructure

## AWS Services Used

### Core Services
- **AWS Lambda**: Serverless compute for all business logic
- **API Gateway**: RESTful API endpoints with CORS support
- **DynamoDB**: NoSQL database for domain storage and analytics
- **EventBridge**: Scheduled triggers for automated updates

### Frontend & Distribution
- **S3**: Static website hosting for demo frontend
- **CloudFront**: Global CDN for fast content delivery
- **CloudFormation**: Infrastructure as Code deployment

### Additional Features
- **Lambda Layers**: Shared utilities across functions
- **DynamoDB TTL**: Automatic cleanup of expired data
- **IAM Roles**: Least-privilege access control

## Advanced Validation Features

## API Endpoints

### POST /validate-email
Validates if an email address uses a disposable domain.

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "email": "user@example.com",
  "isValid": true,
  "isDisposable": false,
  "domain": "example.com",
  "validationResults": {
    "disposableCheck": { "isDisposable": false, "confidence": 0.95 },
    "dnsCheck": { "hasValidMX": true, "mxRecords": ["mail.example.com"] },
    "patternCheck": { "isValidPattern": true, "localPartScore": 0.9 },
    "reputationCheck": { "score": 0.85, "status": "good" },
    "domainAge": { "ageInDays": 3650, "isSuspicious": false },
    "smtpCheck": { "isReachable": true, "responseCode": 220 },
    "registrarCheck": { "registrar": "GoDaddy", "isSuspicious": false },
    "suspiciousPatterns": { "hasPatterns": false, "patterns": [] },
    "commonProvider": { "isCommon": true, "provider": "legitimate" },
    "domainLength": { "length": 11, "isSuspicious": false }
  },
  "overallScore": 0.91,
  "riskLevel": "low",
  "timestamp": "2025-06-14T10:30:00Z"
}
```

### GET /analytics
Returns validation statistics and insights.

**Response:**
```json
{
  "totalValidations": 15420,
  "disposableDetected": 3847,
  "detectionRate": 0.249,
  "topDisposableDomains": ["10minutemail.com", "tempmail.org"]
}
```

## Getting Started

### Prerequisites
- AWS CLI configured
- SAM CLI installed
- Node.js 22.x

### Deployment
```bash
# Clone the repository
git clone <your-repo-url>
cd disposable-email-detector

# Build and deploy
sam build
sam deploy --guided

# Deploy frontend
aws s3 sync frontend/ s3://your-bucket-name/
```

### Usage
```javascript
// Example API call with detailed response
const response = await fetch('https://your-api-id.execute-api.region.amazonaws.com/prod/validate-email', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: 'test@10minutemail.com' })
});

const result = await response.json();
console.log(result.isDisposable); // true
console.log(result.overallScore); // 0.12 (high risk)
console.log(result.riskLevel); // "high"
console.log(result.validationResults.dnsCheck.hasValidMX); // false
```

## Real-World Applications

### Business Use Cases
- **User Registration**: Multi-layered fraud prevention during signup
- **Email Marketing**: Ensure deliverability with DNS and SMTP validation
- **Lead Generation**: Verify lead quality with reputation scoring
- **Survey Platforms**: Detect fake responses with pattern analysis
- **E-commerce**: Prevent fraudulent transactions with comprehensive checks
- **Financial Services**: Enhanced due diligence for account opening
- **SaaS Platforms**: Reduce trial abuse and improve conversion rates

### Integration Examples
- Form validation on websites
- CRM system integration
- Email service provider webhooks
- Mobile app user registration

## Technical Implementation

### Lambda Function Architecture
```
src/
├── lambda/
│   ├── emailValidator.js    # Main validation logic
│   ├── domainUpdater.js     # Scheduled domain updates
│   └── analytics.js         # Usage analytics
├── layers/
│   └── shared/        	     # Common utilities
frontend/
└── index.html		     # Demo interface
```

### Database Schema
**DisposableDomainsTable**
- `domain` (String, Hash Key): Domain name
- `source` (String): Data source
- `ttl` (Number): Time to live for auto-cleanup

**AnalyticsTable**
- `date` (String, Hash Key): Date in YYYY-MM-DD format
- `domain` (String, Range Key): Domain being validated
- `count` (Number): Validation count
- `isDisposable` (Boolean): Result

### Performance Optimizations
- **Parallel Processing**: All 10 validation checks run concurrently
- **Intelligent Caching**: DNS and WHOIS results cached to reduce latency
- **Early Termination**: Fast-fail for obviously invalid emails
- **DynamoDB Single-Table Design**: Optimized queries with minimal cost
- **Lambda Layer**: Shared validation utilities reduce cold start time
- **CloudFront Caching**: Frontend served from edge locations globally
- **Efficient Memory Usage**: Right-sized Lambda functions for cost optimization

## Monitoring & Analytics

### Built-in Metrics
- Real-time validation statistics
- Domain popularity tracking
- API usage patterns
- Error rate monitoring

### CloudWatch Integration
- Lambda function metrics
- API Gateway performance
- DynamoDB operation stats
- Custom business metrics

## Security Features

- **API Gateway CORS**: Secure cross-origin requests
- **IAM Roles**: Principle of least privilege
- **Input Validation**: Sanitized email inputs
- **Rate Limiting**: Prevents API abuse
- **No API Keys Required**: Public validation service

## Scalability & Performance

### Auto-scaling Capabilities
- **Concurrent Executions**: Up to 1000 concurrent Lambda invocations
- **DynamoDB On-Demand**: Automatic capacity scaling
- **Global Distribution**: CloudFront edge locations worldwide
- **Sub-second Response**: Optimized for fast validation

### Cost Optimization
- **Serverless Pricing**: Pay per request model
- **DynamoDB On-Demand**: No pre-provisioned capacity
- **S3 Standard**: Cost-effective static hosting
- **Lambda Efficiency**: Minimal compute time

## Demo

**Live Demo**: Access the demo at your CloudFront URL
**API Testing**: Use tools like Postman or curl to test endpoints

## Future Enhancements

- Machine learning-based domain classification
- Webhook notifications for real-time alerts
- Advanced analytics dashboard
- Multi-language support
- Mobile SDK for native apps

## Contributing

This project demonstrates production-ready serverless architecture patterns and can be extended for various use cases. Feel free to fork and adapt for your needs.

## License

MIT License - See LICENSE file for details

---
