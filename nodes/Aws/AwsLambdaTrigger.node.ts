import {
	BINARY_ENCODING,
	IWebhookFunctions,
} from 'n8n-core';

import {
	IDataObject,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	IWebhookResponseData,
	NodeOperationError,
} from 'n8n-workflow';

import * as basicAuth from 'basic-auth';

import { Response } from 'express';

import * as fs from 'fs';

import * as formidable from 'formidable';

function authorizationError(resp: Response, realm: string, responseCode: number, message?: string) {
	if (message === undefined) {
		message = 'Authorization problem!';
		if (responseCode === 401) {
			message = 'Authorization is required!';
		} else if (responseCode === 403) {
			message = 'Authorization data is wrong!';
		}
	}

	resp.writeHead(responseCode, { 'WWW-Authenticate': `Basic realm="${realm}"` });
	resp.end(message);
	return {
		noWebhookResponse: true,
	};
}

export class AwsLambdaTrigger implements INodeType {
		description: INodeTypeDescription = {
			displayName: 'AWS Lambda Trigger',
			name: 'awsLambdaTrigger',
			icon: 'file:lambda.svg',
			group: ['trigger'],
			version: 1,
			subtitle: 'Send Data to URL via AWS Lambda',
			description: 'Handle AWS Lambda events via webhooks',
			defaults: {
				name: 'AWS Lambda Trigger',
				color: '#6ad7b9',
			},
			inputs: [],
			outputs: ['main'],
			credentials: [
				{
					name: 'httpBasicAuth',
					required: true,
					displayOptions: {
						show: {
							authentication: [
								'basicAuth',
							],
						},
					},
				},
				{
					name: 'httpHeaderAuth',
					required: true,
					displayOptions: {
						show: {
							authentication: [
								'headerAuth',
							],
						},
					},
				},
			],
			webhooks: [
				{
					name: 'default',
					httpMethod: 'POST',
					responseMode: 'onReceived',
					path: 'webhook',
				},
			],
			properties: [
				{
					displayName: 'Authentication',
					name: 'authentication',
					type: 'options',
					options: [
						{
							name: 'Basic Auth',
							value: 'basicAuth',
						},
						{
							name: 'Header Auth',
							value: 'headerAuth',
						},
						{
							name: 'None',
							value: 'none',
						},
					],
					default: 'none',
					description: 'The way to authenticate.',
				},
				{
					displayName: 'Simplify Response',
					name: 'simplify',
					type: 'boolean',
					default: false,
					description: 'Return a simplified version of the response instead of the raw data.',
				},
				{
					displayName: 'Simplify Data Key',
					name: 'dataKey',
					type: 'options',
					displayOptions: {
						show: {
							simplify: [
								true,
							],
						},
					},
					options: [
						{
							name: 'Body',
							value: 'body',
						},
						{
							name: 'Params',
							value: 'params',
						},
						{
							name: 'Query',
							value: 'query',
						},
						{
							name: 'Headers',
							value: 'headers',
						},
					],
					default: 'body',
					description: 'The part of the data to display.',
				},
			],
		};


		async webhook(this: IWebhookFunctions): Promise<IWebhookResponseData> {
		const authentication = this.getNodeParameter('authentication') as string;
		const req = this.getRequestObject();
		const resp = this.getResponseObject();
		const headers = this.getHeaderData();
		const realm = 'Webhook';


		if (authentication === 'basicAuth') {
			// Basic authorization is needed to call webhook
			const httpBasicAuth = await this.getCredentials('httpBasicAuth');

			if (httpBasicAuth === undefined || !httpBasicAuth.user || !httpBasicAuth.password) {
				// Data is not defined on node so can not authenticate
				return authorizationError(resp, realm, 500, 'No authentication data defined on node!');
			}

			const basicAuthData = basicAuth(req);

			if (basicAuthData === undefined) {
				// Authorization data is missing
				return authorizationError(resp, realm, 401);
			}

			if (basicAuthData.name !== httpBasicAuth!.user || basicAuthData.pass !== httpBasicAuth!.password) {
				// Provided authentication data is wrong
				return authorizationError(resp, realm, 403);
			}
		} else if (authentication === 'headerAuth') {
			// Special header with value is needed to call webhook
			const httpHeaderAuth = await this.getCredentials('httpHeaderAuth');

			if (httpHeaderAuth === undefined || !httpHeaderAuth.name || !httpHeaderAuth.value) {
				// Data is not defined on node so can not authenticate
				return authorizationError(resp, realm, 500, 'No authentication data defined on node!');
			}
			const headerName = (httpHeaderAuth.name as string).toLowerCase();
			const headerValue = (httpHeaderAuth.value as string);

			if (!headers.hasOwnProperty(headerName) || (headers as IDataObject)[headerName] !== headerValue) {
				// Provided authentication data is wrong
				return authorizationError(resp, realm, 403);
			}
		}

		// @ts-ignore
		const mimeType = headers['content-type'] || 'application/json';
		if (mimeType.includes('multipart/form-data')) {
			// @ts-ignore
			const form = new formidable.IncomingForm({ multiples: true });

			return new Promise((resolve, reject) => {

				form.parse(req, async (err, data, files) => {
					const returnItem: INodeExecutionData = {
						binary: {},
						json: {
							headers,
							params: this.getParamsData(),
							query: this.getQueryData(),
							body: data,
						},
					};

					let count = 0;
					for (const xfile of Object.keys(files)) {
						const processFiles: formidable.File[] = [];
						let multiFile = false;
						if (Array.isArray(files[xfile])) {
							processFiles.push(...files[xfile] as formidable.File[]);
							multiFile = true;
						} else {
							processFiles.push(files[xfile] as formidable.File);
						}

						let fileCount = 0;
						for (const file of processFiles) {
							let binaryPropertyName = xfile;
							if (binaryPropertyName.endsWith('[]')) {
								binaryPropertyName = binaryPropertyName.slice(0, -2);
							}
							if (multiFile === true) {
								binaryPropertyName += fileCount++;
							}

							const fileJson = file.toJSON() as unknown as IDataObject;
							//@ts-ignore
							const fileContent = await fs.promises.readFile(file.path);

							returnItem.binary![binaryPropertyName] = await this.helpers.prepareBinaryData(Buffer.from(fileContent), fileJson.name as string, fileJson.type as string);

							count += 1;
						}
					}
					resolve({
						workflowData: [
							[
								returnItem,
							],
						],
					});
				});
			});
		}

		const response: INodeExecutionData = {
			json: {},
		};

		const simplify = this.getNodeParameter('simplify') as boolean;
		if (simplify){
			const dataKey = this.getNodeParameter('dataKey') as string;
			if (dataKey==='body') {
				response.json.body = this.getBodyData();
			} else if (dataKey==='params') {
				response.json.params = this.getParamsData();
			} else if (dataKey==='query') {
				response.json.query = this.getQueryData();
			} else if (dataKey==='headers') {
				response.json.headers = headers
			}
		} else {
			response.json.headers = headers
			response.json.params = this.getParamsData();
			response.json.query = this.getQueryData();
			response.json.body = this.getBodyData();
		}

		let webhookResponse: string | undefined;

		return {
			webhookResponse,
			workflowData: [
				[
					response,
				],
			],
		};
	}
}
