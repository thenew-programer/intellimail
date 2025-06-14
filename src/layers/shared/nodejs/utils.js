const AWS = require('aws-sdk');
const axios = require('axios')
const dns = require('dns').promises;
const net = require('net');

const dynamoDb = new AWS.DynamoDB.DocumentClient();

module.exports = {
	dynamoDb,
	axios,
	dns,
	net
};
