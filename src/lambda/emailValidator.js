const { dynamoDb, dns, net } = require('/opt/nodejs/utils');

exports.handler = async (event) => {
    if (event.httpMethod === 'OPTIONS') {
        return formatResponse(200, {});
    }

    try {
        const { email, metadata = {}, strictMode = false } = JSON.parse(event.body);
        
        // Basic validation
        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return formatResponse(400, { error: 'Invalid email format' });
        }
        
        const [localPart, domain] = email.split('@');
        
        console.log(`Validating email: ${email}`);
        
        const trustedResult = checkTrustedProvider(domain);
        if (trustedResult.isTrusted) {
            console.log(`Trusted provider detected: ${domain} - skipping validation checks`);
            
            const trustedResponse = {
                email,
                isValid: true,
                isTrustedProvider: true,
                provider: trustedResult.provider,
                checks: {
                    disposableDomain: { isDisposable: false, source: 'trusted_provider' },
                    dnsRecords: { hasMX: true, hasA: true, dnsValid: true, mxCount: 1, suspiciousFlags: [] },
                    emailPattern: { isRandom: false, hasDisposableWords: false },
                    domainReputation: { isLegitimateProvider: true, isHighRiskTld: false },
                    domainAge: { isEstablished: true, confidence: 'high' },
                    smtpServer: { smtpAvailable: true },
                    commonProviders: { isLegitimate: true, isPopular: true }
                },
                riskFactors: ['✓ Trusted email provider'],
                riskScore: 0,
                riskLevel: 'LOW',
                allowRegistration: true,
                recommendations: {
                    allowRegistration: true,
                    requireVerification: false,
                    additionalChecks: [],
                    blockReason: null
                }
            };
            
            await recordAnalytics(domain, 0, trustedResponse.checks, metadata);
            
            return formatResponse(200, trustedResponse);
        }
        
        const validationResults = {
            email,
            isValid: true,
            isTrustedProvider: false,
            checks: {},
            riskFactors: [],
            recommendations: {}
        };
        
        const checks = await Promise.allSettled([
            checkDisposableDomain(domain),
            checkDNSRecords(domain),
            checkEmailPattern(localPart, domain),
            checkDomainReputation(domain),
            checkDomainAge(domain),
            checkSMTPServer(domain),
            checkDomainRegistrar(domain),
            checkSuspiciousPatterns(email),
            checkCommonProviders(domain),
            checkDomainLength(domain)
        ]);
        
        validationResults.checks = {
            disposableDomain: checks[0].status === 'fulfilled' ? checks[0].value : { error: checks[0].reason },
            dnsRecords: checks[1].status === 'fulfilled' ? checks[1].value : { error: checks[1].reason },
            emailPattern: checks[2].status === 'fulfilled' ? checks[2].value : { error: checks[2].reason },
            domainReputation: checks[3].status === 'fulfilled' ? checks[3].value : { error: checks[3].reason },
            domainAge: checks[4].status === 'fulfilled' ? checks[4].value : { error: checks[4].reason },
            smtpServer: checks[5].status === 'fulfilled' ? checks[5].value : { error: checks[5].reason },
            domainRegistrar: checks[6].status === 'fulfilled' ? checks[6].value : { error: checks[6].reason },
            suspiciousPatterns: checks[7].status === 'fulfilled' ? checks[7].value : { error: checks[7].reason },
            commonProviders: checks[8].status === 'fulfilled' ? checks[8].value : { error: checks[8].reason },
            domainLength: checks[9].status === 'fulfilled' ? checks[9].value : { error: checks[9].reason }
        };
        
        const riskScore = calculateAdvancedRiskScore(validationResults.checks);
        validationResults.riskScore = riskScore;
        validationResults.riskLevel = getRiskLevel(riskScore);
        
        validationResults.riskFactors = generateRiskFactors(validationResults.checks);
        validationResults.recommendations = generateAdvancedRecommendations(riskScore, validationResults.checks, strictMode);
        
        validationResults.isValid = strictMode ? riskScore < 30 : riskScore < 70;
        validationResults.allowRegistration = validationResults.recommendations.allowRegistration;
        
        await recordAnalytics(domain, riskScore, validationResults.checks, metadata);
        
        return formatResponse(200, validationResults);
        
    } catch (error) {
        console.error('Error:', error);
        return formatResponse(500, { error: 'Internal server error' });
    }
};

function checkTrustedProvider(domain) {
    const trustedProviders = {
        'gmail.com': 'Google Gmail',
        'googlemail.com': 'Google Gmail',
        'yahoo.com': 'Yahoo Mail',
        'yahoo.co.uk': 'Yahoo Mail UK',
        'yahoo.ca': 'Yahoo Mail Canada',
        'yahoo.com.au': 'Yahoo Mail Australia',
        'hotmail.com': 'Microsoft Hotmail',
        'outlook.com': 'Microsoft Outlook',
        'live.com': 'Microsoft Live',
        'msn.com': 'Microsoft MSN',
        'hotmail.co.uk': 'Microsoft Hotmail UK',
        'outlook.co.uk': 'Microsoft Outlook UK',
        
        'icloud.com': 'Apple iCloud',
        'me.com': 'Apple Me',
        'mac.com': 'Apple Mac',
        
        'aol.com': 'AOL Mail',
        'protonmail.com': 'ProtonMail',
        'proton.me': 'Proton Mail',
        'tutanota.com': 'Tutanota',
        'fastmail.com': 'FastMail',
        'zoho.com': 'Zoho Mail',
        'mail.com': 'Mail.com',
        
        'yandex.com': 'Yandex Mail',
        'yandex.ru': 'Yandex Mail Russia',
        'mail.ru': 'Mail.ru',
        'gmx.com': 'GMX Mail',
        'gmx.de': 'GMX Germany',
        'web.de': 'Web.de',
        't-online.de': 'T-Online Germany',
        'laposte.net': 'La Poste France',
        'orange.fr': 'Orange France',
        'free.fr': 'Free France',
        'qq.com': 'QQ Mail China',
        '163.com': 'NetEase Mail China',
        '126.com': 'NetEase 126 China',
        'sina.com': 'Sina Mail China',
        'naver.com': 'Naver Mail Korea',
        'daum.net': 'Daum Mail Korea',
        'hanmail.net': 'Hanmail Korea'
    };
    
    const domainLower = domain.toLowerCase();
    
    if (trustedProviders[domainLower]) {
        return {
            isTrusted: true,
            provider: trustedProviders[domainLower]
        };
    }
    
    return {
        isTrusted: false,
        provider: null
    };
}

async function checkDisposableDomain(domain) {
    const params = {
        TableName: process.env.DOMAINS_TABLE,
        Key: { domain: domain.toLowerCase() }
    };
    
    try {
        const result = await dynamoDb.get(params).promise();
        return {
            isDisposable: !!result.Item,
            source: result.Item ? result.Item.source : null,
            lastUpdated: result.Item ? result.Item.lastUpdated : null
        };
    } catch (error) {
        console.error('Error checking disposable domain:', error);
        return { isDisposable: false, error: error.message };
    }
}

async function checkDNSRecords(domain) {
    try {
        const results = await Promise.allSettled([
            dns.resolveMx(domain),
            dns.resolveA(domain),
            dns.resolveTxt(domain),
        ]);
        
        const mxRecords = results[0].status === 'fulfilled' ? results[0].value : [];
        const aRecords = results[1].status === 'fulfilled' ? results[1].value : [];
        const txtRecords = results[2].status === 'fulfilled' ? results[2].value : [];
        
        const suspiciousFlags = [];
        
        if (mxRecords.length === 0) {
            suspiciousFlags.push('no_mx_records');
        }
        
        if (mxRecords.length === 1) {
            const mxDomain = mxRecords[0].exchange.toLowerCase();
            const suspiciousMx = ['mail.ru', 'yandex.ru', 'guerrillamail.com', 'tempmail.org'];
            if (suspiciousMx.some(sus => mxDomain.includes(sus))) {
                suspiciousFlags.push('suspicious_mx');
            }
        }
        
        const txtString = txtRecords.flat().join(' ').toLowerCase();
        if (txtString.includes('temporary') || txtString.includes('disposable') || txtString.includes('free')) {
            suspiciousFlags.push('suspicious_txt');
        }
        
        return {
            hasMX: mxRecords.length > 0,
            hasA: aRecords.length > 0,
            mxCount: mxRecords.length,
            mxRecords: mxRecords.map(mx => mx.exchange),
            suspiciousFlags,
            dnsValid: mxRecords.length > 0 && aRecords.length > 0
        };
        
    } catch (error) {
        return {
            hasMX: false,
            hasA: false,
            mxCount: 0,
            suspiciousFlags: ['dns_error'],
            dnsValid: false,
            error: error.message
        };
    }
}

function checkEmailPattern(localPart, domain) {
    const patterns = {
        isRandom: /^[a-z0-9]{10,}$/i.test(localPart) && !/[aeiou]{2,}/i.test(localPart),
        hasMultipleNumbers: (localPart.match(/\d/g) || []).length >= 3,
        hasRandomNumbers: /\d{4,}/.test(localPart),
        hasCommonWords: /^(test|demo|fake|temp|example|user|admin|no-reply|contact|info|support)/.test(localPart.toLowerCase()),
        hasSequentialChars: /abc|123|xyz|qwe|asd|zxc/.test(localPart.toLowerCase()),
        tooShort: localPart.length < 3,
        tooLong: localPart.length > 20,
        hasSpecialChars: /[+\-_.]/.test(localPart),
        allNumbers: /^\d+$/.test(localPart),
        allLetters: /^[a-z]+$/i.test(localPart),
        hasRepeatedChars: /(.)\1{2,}/.test(localPart)
    };
    
    const disposablePatterns = [
        'temp', 'throw', 'disposable', 'fake', 'test', 'spam', 'trash',
        'dummy', 'sample', 'trial', 'guest', 'anonymous', 'random'
    ];
    
    patterns.hasDisposableWords = disposablePatterns.some(pattern => 
        localPart.toLowerCase().includes(pattern)
    );
    
    return patterns;
}

function checkDomainReputation(domain) {
    const tld = domain.split('.').pop().toLowerCase();
    const domainParts = domain.split('.');
    
    const highRiskTlds = new Set([
        'tk', 'ml', 'ga', 'cf', 'xyz', 'online', 'site', 'tech', 'club',
        'info', 'biz', 'us', 'cc', 'tv', 'ws', 'me', 'nu', 'be'
    ]);
    
    const freeHostingPatterns = [
        'blogspot', 'wordpress', 'wix', 'weebly', 'squarespace',
        'github.io', 'herokuapp', 'netlify', 'vercel'
    ];
    
    const legitimateTlds = new Set([
        'com', 'org', 'net', 'edu', 'gov', 'mil', 'int'
    ]);
    
    return {
        tld,
        isHighRiskTld: highRiskTlds.has(tld),
        isLegitimateProvider: legitimateTlds.has(tld),
        isFreeHosting: freeHostingPatterns.some(pattern => domain.includes(pattern)),
        domainLength: domain.length,
        subdomainCount: domainParts.length - 2,
        hasNumbers: /\d/.test(domain),
        hasDashes: domain.includes('-')
    };
}

function checkDomainAge(domain) {
    const knownOldDomains = [
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
        'protonmail.com', 'icloud.com', 'me.com', 'live.com', 'msn.com'
    ];
    
    const isEstablished = knownOldDomains.includes(domain.toLowerCase());
    
    const newDomainPatterns = [
        /\d{4}/,
        /temp/, /test/, /new/, /demo/
    ];
    
    const seemsNew = newDomainPatterns.some(pattern => pattern.test(domain));
    
    return {
        isEstablished,
        seemsNew,
        confidence: isEstablished ? 'high' : (seemsNew ? 'medium' : 'low')
    };
}

async function checkSMTPServer(domain) {
    try {
        const mxRecords = await dns.resolveMx(domain);
        if (mxRecords.length === 0) {
            return { smtpAvailable: false, reason: 'no_mx_records' };
        }
        
        const primaryMX = mxRecords.sort((a, b) => a.priority - b.priority)[0];
        
        return new Promise((resolve) => {
            const socket = new net.Socket();
            const timeout = setTimeout(() => {
                socket.destroy();
                resolve({ smtpAvailable: false, reason: 'timeout' });
            }, 5000);
            
            socket.connect(25, primaryMX.exchange, () => {
                clearTimeout(timeout);
                socket.destroy();
                resolve({ smtpAvailable: true, server: primaryMX.exchange });
            });
            
            socket.on('error', () => {
                clearTimeout(timeout);
                resolve({ smtpAvailable: false, reason: 'connection_failed' });
            });
        });
        
    } catch (error) {
        return { smtpAvailable: false, reason: 'dns_error', error: error.message };
    }
}

async function checkDomainRegistrar(domain) {
    const domainParts = domain.toLowerCase().split('.');
    const rootDomain = domainParts.length > 2 
        ? domainParts.slice(-2).join('.') 
        : domainParts.join('.');
    
    // Known suspicious patterns
    const suspiciousRegistrars = [
        'freenom', 'dot.tk', 'namecheap', 'porkbun', 'namebright',
        'reg.ru', 'nic.ru', 'r01.ru', 'regtime', 'webnic'
    ];
    
    const disposableTLDs = new Set([
        'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'info', 'biz',
        'club', 'work', 'online', 'site', 'website', 'space'
    ]);
    
    const patterns = {
        freeRegistration: false,
        bulkRegistration: false,
        suspiciousRegistrar: false,
        disposableTLD: false,
        isIP: false,
        registrar: null
    };
    
    // Check for IP address
    if (net.isIP(domain)) {
        patterns.isIP = true;
        return patterns;
    }
    
    // Check TLD patterns
    const tld = domainParts.slice(-1)[0];
    patterns.disposableTLD = disposableTLDs.has(tld);
    
    // Check for free domains
    patterns.freeRegistration = [
        'tk', 'ml', 'ga', 'cf', 'gq'
    ].includes(tld);
    
    // Check for bulk registration patterns
    const domainName = domainParts[0];
    patterns.bulkRegistration = (
        /\d{4,}/.test(domainName) || 
        /([a-z])\1{3,}/.test(domainName) || 
        domainName.length > 25
    );
    
    try {
        const whoisResponse = await axios.get(`https://whois.freeaiapi.xyz/?domain=${rootDomain}`, {
            timeout: 5000
        });
        
        const whoisData = whoisResponse.data.toLowerCase();
        patterns.registrar = whoisData.match(/registrar:\s*(.*)/)?.[1] || null;
        
        if (patterns.registrar) {
            patterns.suspiciousRegistrar = suspiciousRegistrars.some(reg => 
                patterns.registrar.includes(reg.toLowerCase())
            );
        }
        
    } catch (e) {
        console.error(`WHOIS lookup failed for ${domain}:`, e.message);
    }
    
    return patterns;
}

function checkSuspiciousPatterns(email) {
    const [localPart, domain] = email.split('@');
    
    return {
        hasPlus: localPart.includes('+'),
        hasDots: localPart.includes('.'),
        hasUnderscore: localPart.includes('_'),
        hasHyphen: localPart.includes('-'),
        startsWithNumber: /^\d/.test(localPart),
        endsWithNumber: /\d$/.test(localPart),
        allCaps: localPart === localPart.toUpperCase(),
        mixedCase: localPart !== localPart.toLowerCase() && localPart !== localPart.toUpperCase(),
        commonSpamWords: /(promo|offer|deal|free|win|prize|click|buy|sale)/.test(localPart.toLowerCase())
    };
}

function checkCommonProviders(domain) {
    const legitimateProviders = new Set([
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
        'icloud.com', 'me.com', 'live.com', 'msn.com', 'protonmail.com',
        'tutanota.com', 'fastmail.com', 'zoho.com', 'yandex.com', 'mail.ru'
    ]);
    
    const businessProviders = new Set([
        'company.com', 'organization.org', 'business.net'
    ]);
    
    return {
        isLegitimate: legitimateProviders.has(domain.toLowerCase()),
        isBusiness: businessProviders.has(domain.toLowerCase()) || 
                   (!legitimateProviders.has(domain.toLowerCase()) && 
                    !domain.includes('mail') && 
                    !domain.includes('email')),
        isPopular: legitimateProviders.has(domain.toLowerCase())
    };
}

function checkDomainLength(domain) {
    const parts = domain.split('.');
    const mainDomain = parts[0];
    
    return {
        totalLength: domain.length,
        mainDomainLength: mainDomain.length,
        tooShort: mainDomain.length < 4,
        tooLong: mainDomain.length > 25,
        optimalLength: mainDomain.length >= 4 && mainDomain.length <= 15
    };
}

function calculateAdvancedRiskScore(checks) {
    let score = 0;
    
    if (checks.disposableDomain?.isDisposable) score += 50;
    
    if (!checks.dnsRecords?.dnsValid) score += 30;
    if (checks.dnsRecords?.suspiciousFlags?.length > 0) score += 15;
    
    const patterns = checks.emailPattern || {};
    if (patterns.isRandom) score += 20;
    if (patterns.hasDisposableWords) score += 25;
    if (patterns.hasMultipleNumbers) score += 10;
    if (patterns.hasCommonWords) score += 15;
    if (patterns.tooShort || patterns.tooLong) score += 5;
    if (patterns.allNumbers) score += 15;
    
    const reputation = checks.domainReputation || {};
    if (reputation.isHighRiskTld) score += 20;
    if (reputation.isFreeHosting) score += 15;
    if (reputation.hasNumbers) score += 5;
    
    const age = checks.domainAge || {};
    if (age.seemsNew) score += 10;
    if (!age.isEstablished) score += 5;
    
    if (!checks.smtpServer?.smtpAvailable) score += 15;
    
    const suspicious = checks.suspiciousPatterns || {};
    if (suspicious.commonSpamWords) score += 10;
    if (suspicious.startsWithNumber) score += 5;
    
    const providers = checks.commonProviders || {};
    if (providers.isLegitimate) score -= 20;
    if (providers.isBusiness) score -= 10;
    
    const length = checks.domainLength || {};
    if (length.tooShort || length.tooLong) score += 5;
    
    return Math.min(Math.max(score, 0), 100);
}

function getRiskLevel(score) {
    if (score < 30) return 'LOW';
    if (score < 70) return 'MEDIUM';
    return 'HIGH';
}

function generateRiskFactors(checks) {
    const factors = [];
    
    if (checks.disposableDomain?.isDisposable) {
        factors.push('Domain is in disposable email database');
    }
    
    if (!checks.dnsRecords?.dnsValid) {
        factors.push('Invalid or missing DNS records');
    }
    
    if (checks.emailPattern?.isRandom) {
        factors.push('Username appears randomly generated');
    }
    
    if (checks.emailPattern?.hasDisposableWords) {
        factors.push('Contains disposable email keywords');
    }
    
    if (checks.domainReputation?.isHighRiskTld) {
        factors.push('High-risk top-level domain');
    }
    
    if (!checks.smtpServer?.smtpAvailable) {
        factors.push('SMTP server not accessible');
    }
    
    if (checks.commonProviders?.isLegitimate) {
        factors.push('✓ Legitimate email provider');
    }
    
    return factors;
}

function generateAdvancedRecommendations(riskScore, checks, strictMode) {
    const recommendations = {
        allowRegistration: false,
        requireVerification: false,
        additionalChecks: [],
        blockReason: null
    };
    
    if (strictMode) {
        recommendations.allowRegistration = riskScore < 20;
        recommendations.requireVerification = riskScore >= 10;
    } else {
        recommendations.allowRegistration = riskScore < 60;
        recommendations.requireVerification = riskScore >= 30;
    }
    
    if (riskScore >= 80) {
        recommendations.blockReason = 'High risk - likely disposable email';
        recommendations.additionalChecks.push('manual_review', 'phone_verification');
    } else if (riskScore >= 60) {
        recommendations.additionalChecks.push('phone_verification', 'email_verification');
    } else if (riskScore >= 30) {
        recommendations.additionalChecks.push('email_verification');
    }
    
    if (checks.disposableDomain?.isDisposable) {
        recommendations.blockReason = 'Known disposable email domain';
    }
    
    if (!checks.dnsRecords?.dnsValid) {
        recommendations.blockReason = 'Invalid email domain';
    }
    
    return recommendations;
}

async function recordAnalytics(domain, riskScore, checks, metadata) {
    const today = new Date().toISOString().split('T')[0];
    const params = {
        TableName: process.env.ANALYTICS_TABLE,
        Item: {
            date: today,
            domain: domain.toLowerCase(),
            riskScore,
            timestamp: new Date().toISOString(),
            metadata,
            checks: JSON.stringify(checks),
            id: `${today}-${domain.toLowerCase()}-${Date.now()}`
        }
    };
    
    try {
        await dynamoDb.put(params).promise();
    } catch (error) {
        console.error('Error recording analytics:', error);
    }
}

function formatResponse(statusCode, body) {
    return {
        statusCode,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
            'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
        },
        body: JSON.stringify(body)
    };
}
