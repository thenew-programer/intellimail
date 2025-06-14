const { axios, dynamoDb } = require('/opt/nodejs/utils');
const fs = require('fs');
const path = require('path');

exports.handler = async () => {
    try {
        console.log('Starting comprehensive domain update process...');
        
        let domains = new Set();
        const sources = [];
        
        await loadLocalDomains(domains, sources);
        
        await loadRemoteSources(domains, sources);
        
        await generateSuspiciousPatterns(domains, sources);
        
        console.log(`Total unique domains collected: ${domains.size}`);
        console.log(`Sources used: ${sources.length}`);
        
        if (domains.size === 0) {
            return { success: false, message: 'No domains found to update' };
        }
        
        const result = await updateDynamoDB(domains, sources);
        
        return result;
        
    } catch (error) {
        console.error('Error in domain update process:', error);
        return {
            success: false,
            error: error.message,
            timestamp: new Date().toISOString()
        };
    }
};

async function loadLocalDomains(domains, sources) {
    try {
        const localDomainsPath = path.join(__dirname, '../data/disposable-domains.json');
        
        if (fs.existsSync(localDomainsPath)) {
            const localDomainsData = fs.readFileSync(localDomainsPath, 'utf8');
            const localDomains = JSON.parse(localDomainsData);
            
            let domainList = [];
            if (Array.isArray(localDomains)) {
                domainList = localDomains;
            } else if (localDomains.domains && Array.isArray(localDomains.domains)) {
                domainList = localDomains.domains;
            } else if (typeof localDomains === 'object') {
                domainList = Object.keys(localDomains);
            }
            
            domainList.forEach(domain => {
                if (typeof domain === 'string' && domain.trim()) {
                    domains.add(domain.toLowerCase().trim());
                }
            });
            
            sources.push(`Local file: ${domainList.length} domains`);
            console.log(`Loaded ${domainList.length} domains from local file`);
        }
    } catch (error) {
        console.error('Error loading local domains:', error);
    }
}

async function loadRemoteSources(domains, sources) {
    const remoteSources = [
        {
            url: 'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf',
            type: 'text',
            name: 'Disposable Email Domains'
        },
        {
            url: 'https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json',
            type: 'json',
            name: 'Ivolo Disposable Domains'
        },
        {
            url: 'https://raw.githubusercontent.com/martenson/disposable-email-domains/master/disposable_email_blocklist.conf',
            type: 'text',
            name: 'Martenson Disposable Domains'
        },
        {
            url: 'https://raw.githubusercontent.com/wesbos/burner-email-providers/master/emails.txt',
            type: 'text',
            name: 'Wesbos Burner Emails'
        },
        {
            url: 'https://raw.githubusercontent.com/FGRibreau/mailchecker/master/list.txt',
            type: 'text',
            name: 'MailChecker List'
        }
    ];
    
    for (const source of remoteSources) {
        try {
            console.log(`Fetching from: ${source.name}`);
            const response = await axios.get(source.url, {
                timeout: 30000,
                headers: {
                    'User-Agent': 'Email-Validator-Bot/2.0',
                    'Accept': source.type === 'json' ? 'application/json' : 'text/plain'
                }
            });
            
            let newDomains = [];
            let initialCount = domains.size;
            
            if (source.type === 'json') {
                if (Array.isArray(response.data)) {
                    newDomains = response.data;
                } else if (response.data.domains) {
                    newDomains = response.data.domains;
                }
            } else {
                newDomains = response.data
                    .split('\n')
                    .map(line => line.trim())
                    .filter(line => line && 
                           !line.startsWith('#') && 
                           !line.startsWith('//') && 
                           !line.startsWith('/*'))
                    .filter(line => isValidDomain(line));
            }
            
            newDomains.forEach(domain => {
                if (typeof domain === 'string' && domain.trim()) {
                    domains.add(domain.toLowerCase().trim());
                }
            });
            
            const addedCount = domains.size - initialCount;
            sources.push(`${source.name}: ${addedCount} new domains`);
            console.log(`Added ${addedCount} new domains from ${source.name}`);
            
        } catch (error) {
            console.error(`Error fetching from ${source.name}:`, error.message);
            sources.push(`${source.name}: Error - ${error.message}`);
        }
    }
}

async function generateSuspiciousPatterns(domains, sources) {
    const suspiciousPatterns = [
        'tempmail', 'temp-mail', 'temporarymail', 'temporary-mail',
        'throwaway', 'throw-away', 'disposable', 'fake', 'spam',
        'trash', 'junk', 'dummy', 'test', 'demo', 'sample',
        
        '10minutemail', '10minute', 'tenminutemail', 'guerrillamail',
        'mailinator', 'mailtrap', 'mailhog', 'mailcatch',
        
        'email1', 'email2', 'email3', 'mail1', 'mail2', 'mail3',
        'temp1', 'temp2', 'temp3', 'test1', 'test2', 'test3'
    ];
    
    const tlds = ['com', 'net', 'org', 'info', 'biz', 'us', 'tk', 'ml', 'ga', 'cf'];
    let initialCount = domains.size;
    
    suspiciousPatterns.forEach(pattern => {
        tlds.forEach(tld => {
            const domain = `${pattern}.${tld}`;
            if (isValidDomain(domain)) {
                domains.add(domain);
            }
        });
    });
    
    for (let i = 1; i <= 20; i++) {
        ['temp', 'mail', 'email', 'test'].forEach(base => {
            tlds.forEach(tld => {
                const domain = `${base}${i}.${tld}`;
                domains.add(domain);
            });
        });
    }
    
    const addedCount = domains.size - initialCount;
    sources.push(`Generated patterns: ${addedCount} domains`);
    console.log(`Generated ${addedCount} suspicious pattern domains`);
}

function isValidDomain(domain) {
    if (!domain || typeof domain !== 'string') return false;
    if (domain.length > 253) return false;
    if (domain.startsWith('.') || domain.endsWith('.')) return false;
    if (domain.includes('..')) return false;
    
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    return domainRegex.test(domain);
}

async function updateDynamoDB(domains, sources) {
    const batchSize = 25;
    const domainArray = Array.from(domains);
    const tableName = process.env.DOMAINS_TABLE || 'disposable-domains';
    const timestamp = new Date().toISOString();
    
    let totalProcessed = 0;
    let successCount = 0;
    let errorCount = 0;
    const errors = [];
    
    console.log(`Starting DynamoDB batch update for ${domainArray.length} domains`);
    
    for (let i = 0; i < domainArray.length; i += batchSize) {
        const batch = domainArray.slice(i, i + batchSize);
        
        try {
            const putRequests = batch.map(domain => ({
                PutRequest: {
                    Item: {
                        domain: domain,
                        isDisposable: true,
                        updatedAt: timestamp,
                        ttl: Math.floor(Date.now() / 1000) + (30 * 24 * 60 * 60)
                    }
                }
            }));
            
            const params = {
                RequestItems: {
                    [tableName]: putRequests
                }
            };
            
            const result = await dynamoDb.batchWrite(params).promise();
            
            if (result.UnprocessedItems && Object.keys(result.UnprocessedItems).length > 0) {
                console.log(`Retrying ${Object.keys(result.UnprocessedItems[tableName] || {}).length} unprocessed items`);
                
                let retryCount = 0;
                let unprocessedItems = result.UnprocessedItems;
                
                while (unprocessedItems && Object.keys(unprocessedItems).length > 0 && retryCount < 3) {
                    await new Promise(resolve => setTimeout(resolve, Math.pow(2, retryCount) * 100));
                    
                    const retryResult = await dynamoDb.batchWrite({ RequestItems: unprocessedItems }).promise();
                    unprocessedItems = retryResult.UnprocessedItems;
                    retryCount++;
                }
                
                if (unprocessedItems && Object.keys(unprocessedItems).length > 0) {
                    const unprocessedCount = Object.keys(unprocessedItems[tableName] || {}).length;
                    errorCount += unprocessedCount;
                    errors.push(`Failed to process ${unprocessedCount} items after retries`);
                }
            }
            
            successCount += batch.length - (result.UnprocessedItems?.[tableName]?.length || 0);
            totalProcessed += batch.length;
            
            console.log(`Processed batch ${Math.ceil((i + batchSize) / batchSize)} of ${Math.ceil(domainArray.length / batchSize)}`);
            
        } catch (error) {
            console.error(`Error processing batch starting at index ${i}:`, error);
            errorCount += batch.length;
            errors.push(`Batch ${Math.ceil((i + batchSize) / batchSize)}: ${error.message}`);
        }
    }
    
    try {
        const metadataParams = {
            TableName: tableName,
            Item: {
                domain: '__metadata__',
                lastUpdated: timestamp,
                totalDomains: domainArray.length,
                sources: sources,
                processedCount: totalProcessed,
                successCount: successCount,
                errorCount: errorCount,
                errors: errors.length > 0 ? errors : undefined,
                ttl: Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60)
            }
        };
        
        await dynamoDb.put(metadataParams).promise();
        console.log('Metadata updated successfully');
        
    } catch (error) {
        console.error('Error updating metadata:', error);
        errors.push(`Metadata update failed: ${error.message}`);
    }
    
    const result = {
        success: errorCount === 0,
        timestamp: timestamp,
        summary: {
            totalDomains: domainArray.length,
            totalProcessed: totalProcessed,
            successCount: successCount,
            errorCount: errorCount,
            sources: sources.length
        },
        sources: sources,
        errors: errors.length > 0 ? errors : undefined
    };
    
    console.log('DynamoDB update completed:', JSON.stringify(result.summary, null, 2));
    
    return result;
}
