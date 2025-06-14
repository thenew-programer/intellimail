const { dynamoDb } = require('/opt/nodejs/utils');

exports.handler = async (event) => {
    if (event.httpMethod === 'OPTIONS') {
        return formatResponse(200, {});
    }

    try {
        console.log('Analytics request received:', JSON.stringify(event.queryStringParameters));
        
        const queryParams = event.queryStringParameters || {};
        const {
            days = '30',
            startDate: customStartDate,
            endDate: customEndDate,
            domain: filterDomain,
            minRisk,
            maxRisk,
            aggregation = 'daily'
        } = queryParams;

        const { startDate, endDate } = getDateRange(days, customStartDate, customEndDate);
        
        console.log(`Fetching analytics for date range: ${startDate} to ${endDate}`);
        
        const allItems = await fetchAnalyticsData(startDate, endDate, filterDomain, minRisk, maxRisk);
        
        if (allItems.length === 0) {
            return formatResponse(200, {
                message: 'No data found for the specified criteria',
                dateRange: { startDate, endDate },
                totalValidations: 0
            });
        }

        const analytics = await generateAnalytics(allItems, startDate, endDate, aggregation);
        
        console.log(`Analytics generated for ${allItems.length} items`);
        return formatResponse(200, analytics);
        
    } catch (error) {
        console.error('Error fetching analytics:', error);
        return formatResponse(500, { 
            error: 'Internal server error',
            message: error.message,
            timestamp: new Date().toISOString()
        });
    }
};

function getDateRange(days, customStartDate, customEndDate) {
    if (customStartDate && customEndDate) {
        return {
            startDate: customStartDate,
            endDate: customEndDate
        };
    }
    
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));
    
    return {
        startDate: startDate.toISOString().split('T')[0],
        endDate: endDate.toISOString().split('T')[0]
    };
}

async function fetchAnalyticsData(startDate, endDate, filterDomain, minRisk, maxRisk) {
    const tableName = process.env.ANALYTICS_TABLE;
    let allItems = [];
    let lastEvaluatedKey = null;
    
    let filterExpression = '#date BETWEEN :startDate AND :endDate';
    const expressionAttributeNames = { '#date': 'date' };
    const expressionAttributeValues = { 
        ':startDate': startDate,
        ':endDate': endDate
    };
    
    if (filterDomain) {
        filterExpression += ' AND #domain = :domain';
        expressionAttributeNames['#domain'] = 'domain';
        expressionAttributeValues[':domain'] = filterDomain;
    }
    
    if (minRisk !== undefined) {
        filterExpression += ' AND riskScore >= :minRisk';
        expressionAttributeValues[':minRisk'] = parseFloat(minRisk);
    }
    
    if (maxRisk !== undefined) {
        filterExpression += ' AND riskScore <= :maxRisk';
        expressionAttributeValues[':maxRisk'] = parseFloat(maxRisk);
    }
    
    do {
        const params = {
            TableName: tableName,
            FilterExpression: filterExpression,
            ExpressionAttributeNames: expressionAttributeNames,
            ExpressionAttributeValues: expressionAttributeValues,
            Limit: 1000
        };
        
        if (lastEvaluatedKey) {
            params.ExclusiveStartKey = lastEvaluatedKey;
        }
        
        const result = await dynamoDb.scan(params).promise();
        allItems = allItems.concat(result.Items);
        lastEvaluatedKey = result.LastEvaluatedKey;
        
        console.log(`Fetched ${result.Items.length} items, total so far: ${allItems.length}`);
        
    } while (lastEvaluatedKey);
    
    return allItems;
}

async function generateAnalytics(items, startDate, endDate, aggregation) {
    const analytics = {
        summary: generateSummaryStats(items, startDate, endDate),
        riskAnalysis: generateRiskAnalysis(items),
        domainAnalysis: generateDomainAnalysis(items),
        timeSeriesData: generateTimeSeriesData(items, aggregation),
        geographicData: generateGeographicData(items),
        detectionPatterns: generateDetectionPatterns(items),
        trends: generateTrends(items)
    };
    
    return analytics;
}

function generateSummaryStats(items, startDate, endDate) {
    const totalValidations = items.length;
    const uniqueDomains = new Set(items.map(item => item.domain)).size;
    const uniqueEmails = new Set(items.map(item => item.email)).size;
    
    return {
        dateRange: { startDate, endDate },
        totalValidations,
        uniqueDomains,
        uniqueEmails,
        averageRiskScore: calculateAverageRiskScore(items),
        validationRate: calculateValidationRate(items),
        dataQuality: {
            completeRecords: items.filter(item => item.email && item.domain && item.riskScore !== undefined).length,
            missingData: items.filter(item => !item.email || !item.domain || item.riskScore === undefined).length
        }
    };
}

function generateRiskAnalysis(items) {
    const riskBuckets = {
        critical: items.filter(item => item.riskScore >= 90).length,
        high: items.filter(item => item.riskScore >= 70 && item.riskScore < 90).length,
        medium: items.filter(item => item.riskScore >= 30 && item.riskScore < 70).length,
        low: items.filter(item => item.riskScore < 30).length
    };
    
    const riskFactors = analyzeRiskFactors(items);
    const riskDistribution = calculateRiskDistribution(items);
    
    return {
        distribution: riskBuckets,
        percentages: {
            critical: Math.round((riskBuckets.critical / items.length) * 10000) / 100,
            high: Math.round((riskBuckets.high / items.length) * 10000) / 100,
            medium: Math.round((riskBuckets.medium / items.length) * 10000) / 100,
            low: Math.round((riskBuckets.low / items.length) * 10000) / 100
        },
        riskFactors,
        riskDistribution
    };
}

function analyzeRiskFactors(items) {
    const factors = {
        disposableEmails: items.filter(item => item.isDisposable).length,
        suspiciousDomains: items.filter(item => item.domainAge && item.domainAge < 30).length,
        invalidSyntax: items.filter(item => !item.isValidSyntax).length,
        blacklistedDomains: items.filter(item => item.isBlacklisted).length,
        freeEmailProviders: items.filter(item => item.isFreeProvider).length
    };
    
    return factors;
}

function calculateRiskDistribution(items) {
    const buckets = {};
    for (let i = 0; i < 100; i += 10) {
        const bucketKey = `${i}-${i + 9}`;
        buckets[bucketKey] = items.filter(item => 
            item.riskScore >= i && item.riskScore < i + 10
        ).length;
    }
    return buckets;
}

function generateDomainAnalysis(items) {
    const domainStats = getEnhancedDomainStats(items);
    const topRiskyDomains = getTopRiskyDomains(items);
    const domainCategories = categorizeDomains(items);
    
    return {
        topDomains: domainStats.slice(0, 20),
        riskiestDomains: topRiskyDomains,
        categories: domainCategories,
        newDomains: getNewDomains(items)
    };
}

function getEnhancedDomainStats(items) {
    const domainMap = {};
    
    items.forEach(item => {
        const domain = item.domain || 'unknown';
        if (!domainMap[domain]) {
            domainMap[domain] = {
                count: 0,
                totalScore: 0,
                riskScores: [],
                firstSeen: item.timestamp || item.date,
                lastSeen: item.timestamp || item.date,
                emails: new Set()
            };
        }
        
        const stats = domainMap[domain];
        stats.count++;
        stats.totalScore += (item.riskScore || 0);
        stats.riskScores.push(item.riskScore || 0);
        stats.emails.add(item.email);
        
        const currentTime = item.timestamp || item.date;
        if (currentTime < stats.firstSeen) stats.firstSeen = currentTime;
        if (currentTime > stats.lastSeen) stats.lastSeen = currentTime;
    });
    
    return Object.entries(domainMap)
        .map(([domain, stats]) => ({
            domain,
            count: stats.count,
            uniqueEmails: stats.emails.size,
            averageRiskScore: Math.round((stats.totalScore / stats.count) * 100) / 100,
            minRiskScore: Math.min(...stats.riskScores),
            maxRiskScore: Math.max(...stats.riskScores),
            percentage: Math.round((stats.count / items.length) * 10000) / 100,
            firstSeen: stats.firstSeen,
            lastSeen: stats.lastSeen
        }))
        .sort((a, b) => b.count - a.count);
}

function getTopRiskyDomains(items) {
    const domainRiskMap = {};
    
    items.forEach(item => {
        const domain = item.domain || 'unknown';
        if (!domainRiskMap[domain]) {
            domainRiskMap[domain] = {
                count: 0,
                totalRisk: 0,
                highRiskCount: 0
            };
        }
        
        domainRiskMap[domain].count++;
        domainRiskMap[domain].totalRisk += (item.riskScore || 0);
        if ((item.riskScore || 0) >= 70) {
            domainRiskMap[domain].highRiskCount++;
        }
    });
    
    return Object.entries(domainRiskMap)
        .map(([domain, stats]) => ({
            domain,
            averageRiskScore: Math.round((stats.totalRisk / stats.count) * 100) / 100,
            highRiskPercentage: Math.round((stats.highRiskCount / stats.count) * 10000) / 100,
            totalValidations: stats.count
        }))
        .filter(domain => domain.averageRiskScore >= 50) // Only show risky domains
        .sort((a, b) => b.averageRiskScore - a.averageRiskScore)
        .slice(0, 10);
}

function categorizeDomains(items) {
    const categories = {
        disposable: 0,
        freeProviders: 0,
        business: 0,
        educational: 0,
        government: 0,
        unknown: 0
    };
    
    const uniqueDomains = new Set();
    
    items.forEach(item => {
        const domain = item.domain;
        if (!domain || uniqueDomains.has(domain)) return;
        
        uniqueDomains.add(domain);
        
        if (item.isDisposable) {
            categories.disposable++;
        } else if (item.isFreeProvider) {
            categories.freeProviders++;
        } else if (domain.endsWith('.edu')) {
            categories.educational++;
        } else if (domain.endsWith('.gov')) {
            categories.government++;
        } else if (item.domainAge && item.domainAge > 365) {
            categories.business++;
        } else {
            categories.unknown++;
        }
    });
    
    return categories;
}

function getNewDomains(items) {
    const now = new Date();
    const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    
    const recentDomains = new Set();
    
    items.forEach(item => {
        const itemDate = new Date(item.timestamp || item.date);
        if (itemDate >= sevenDaysAgo) {
            recentDomains.add(item.domain);
        }
    });
    
    return Array.from(recentDomains).slice(0, 10);
}

function generateTimeSeriesData(items, aggregation) {
    const timeMap = {};
    
    items.forEach(item => {
        let timeKey;
        const itemDate = new Date(item.timestamp || item.date);
        
        switch (aggregation) {
            case 'hourly':
                timeKey = itemDate.toISOString().substring(0, 13) + ':00:00.000Z';
                break;
            case 'daily':
                timeKey = itemDate.toISOString().split('T')[0];
                break;
            case 'weekly':
                const weekStart = new Date(itemDate);
                weekStart.setDate(itemDate.getDate() - itemDate.getDay());
                timeKey = weekStart.toISOString().split('T')[0];
                break;
            case 'monthly':
                timeKey = itemDate.toISOString().substring(0, 7);
                break;
            default:
                timeKey = itemDate.toISOString().split('T')[0];
        }
        
        if (!timeMap[timeKey]) {
            timeMap[timeKey] = {
                timestamp: timeKey,
                count: 0,
                totalRiskScore: 0,
                riskDistribution: { high: 0, medium: 0, low: 0 }
            };
        }
        
        const stats = timeMap[timeKey];
        stats.count++;
        stats.totalRiskScore += (item.riskScore || 0);
        
        const riskScore = item.riskScore || 0;
        if (riskScore >= 70) stats.riskDistribution.high++;
        else if (riskScore >= 30) stats.riskDistribution.medium++;
        else stats.riskDistribution.low++;
    });
    
    return Object.values(timeMap)
        .map(period => ({
            ...period,
            averageRiskScore: Math.round((period.totalRiskScore / period.count) * 100) / 100
        }))
        .sort((a, b) => a.timestamp.localeCompare(b.timestamp));
}

function generateGeographicData(items) {
    const countryMap = {};
    
    items.forEach(item => {
        const country = item.country || 'Unknown';
        if (!countryMap[country]) {
            countryMap[country] = {
                count: 0,
                totalRisk: 0,
                highRiskCount: 0
            };
        }
        
        countryMap[country].count++;
        countryMap[country].totalRisk += (item.riskScore || 0);
        if ((item.riskScore || 0) >= 70) {
            countryMap[country].highRiskCount++;
        }
    });
    
    return Object.entries(countryMap)
        .map(([country, stats]) => ({
            country,
            count: stats.count,
            averageRiskScore: Math.round((stats.totalRisk / stats.count) * 100) / 100,
            highRiskPercentage: Math.round((stats.highRiskCount / stats.count) * 10000) / 100
        }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 20);
}

function generateDetectionPatterns(items) {
    const patterns = {
        commonRiskFactors: {},
        timePatterns: {},
        behaviorPatterns: {}
    };
    
    items.forEach(item => {
        if (item.riskFactors && Array.isArray(item.riskFactors)) {
            item.riskFactors.forEach(factor => {
                patterns.commonRiskFactors[factor] = (patterns.commonRiskFactors[factor] || 0) + 1;
            });
        }
    });
    
    return patterns;
}

function generateTrends(items) {
    const sortedItems = items.sort((a, b) => 
        new Date(a.timestamp || a.date) - new Date(b.timestamp || b.date)
    );
    
    if (sortedItems.length < 2) return {};
    
    const firstHalf = sortedItems.slice(0, Math.floor(sortedItems.length / 2));
    const secondHalf = sortedItems.slice(Math.floor(sortedItems.length / 2));
    
    const firstHalfAvgRisk = calculateAverageRiskScore(firstHalf);
    const secondHalfAvgRisk = calculateAverageRiskScore(secondHalf);
    
    return {
        riskScoreTrend: {
            direction: secondHalfAvgRisk > firstHalfAvgRisk ? 'increasing' : 'decreasing',
            changePercentage: Math.round(((secondHalfAvgRisk - firstHalfAvgRisk) / firstHalfAvgRisk) * 10000) / 100,
            firstPeriodAvg: firstHalfAvgRisk,
            secondPeriodAvg: secondHalfAvgRisk
        },
        volumeTrend: {
            firstPeriodCount: firstHalf.length,
            secondPeriodCount: secondHalf.length,
            changePercentage: Math.round(((secondHalf.length - firstHalf.length) / firstHalf.length) * 10000) / 100
        }
    };
}

function calculateAverageRiskScore(items) {
    if (items.length === 0) return 0;
    const totalScore = items.reduce((sum, item) => sum + (item.riskScore || 0), 0);
    return Math.round((totalScore / items.length) * 100) / 100;
}

function calculateValidationRate(items) {
    const validItems = items.filter(item => item.isValidSyntax !== false);
    return items.length > 0 ? Math.round((validItems.length / items.length) * 10000) / 100 : 0;
}

function formatResponse(statusCode, body) {
    return {
        statusCode,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
            'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
            'Cache-Control': statusCode === 200 ? 'max-age=300' : 'no-cache'
        },
        body: JSON.stringify(body, null, 2)
    };
}
