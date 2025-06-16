const AWS = require('aws-sdk');
const axios = require('axios');
const dns = require('dns').promises;
const net = require('net');
const dynamoDb = new AWS.DynamoDB.DocumentClient();

const secretsManager = new AWS.SecretsManager();

let cachedApiKey = null;
async function getApiKey() {
  if (cachedApiKey) return cachedApiKey;
  const secret = await secretsManager.getSecretValue({ SecretId: 'WHOIS_API_KEY' }).promise();
  cachedApiKey = JSON.parse(secret.SecretString).WHOIS_API_KEY;
  return cachedApiKey;
}

module.exports = {
	dynamoDb,
	axios,
	dns,
	net,
	getApiKey
};
