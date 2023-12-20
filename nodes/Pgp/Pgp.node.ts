/* eslint-disable n8n-nodes-base/node-filename-against-convention */
import type {
	IDataObject,
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';

import { BINARY_ENCODING, NodeOperationError } from 'n8n-workflow';

import { Readable } from 'stream';

import {
	createMessage,
	decrypt,
	decryptKey,
	encrypt,
	readKey,
	readMessage,
	readPrivateKey,
} from 'openpgp';

export class Pgp implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'PGP',
		// eslint-disable-next-line n8n-nodes-base/node-class-description-name-miscased
		name: 'PGP',
		icon: 'file:pgplogo.svg',
		group: ['input'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description: 'Use PGP to encrypt or decrypt data',
		defaults: {
			name: 'PGP',
		},
		inputs: ['main'],
		outputs: ['main'],
		credentials: [
			{
				// eslint-disable-next-line n8n-nodes-base/node-class-description-credentials-name-unsuffixed
				name: 'pgpKey',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Encrypt',
						value: 'encrypt',
					},
					{
						name: 'Decrypt',
						value: 'decrypt',
					},
				],
				default: 'encrypt',
				description: 'Which operation to use?',
			},
			{
				displayName: 'Type',
				name: 'type',
				type: 'options',
				options: [
					{
						name: 'File',
						value: 'file',
					},
					{
						name: 'String',
						value: 'string',
					},
				],
				default: 'file',
			},
			{
				displayName: 'Text',
				name: 'text',
				type: 'string',
				default: '',
				displayOptions: {
					show: {
						type: ['string'],
					},
				},
			},
			/*
			{
				displayName: 'Output as Binary Data',
				name: 'binaryData',
				type: 'boolean',
				default: false,
				displayOptions: {
					show: {
						type: ['string'],
					},
				},
			},
			{
				displayName: 'Property Name',
				name: 'propertyName',
				type: 'string',
				default: 'data',
				displayOptions: {
					show: {
						type: ['string'],
						binaryData: [true],
					},
				},
			},
			*/
			{
				displayName: 'Binary Property',
				name: 'binaryPropertyName',
				type: 'string',
				default: 'data',
				displayOptions: {
					show: {
						type: ['file'],
					},
				},
			},
			{
				displayName: 'Output Property',
				name: 'outputBinaryPropertyName',
				type: 'string',
				default: '',
				displayOptions: {
					show: {
						type: ['file'],
					},
				},
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		const operation = this.getNodeParameter('operation', 0);
		const credentials = await this.getCredentials('pgpKey');

		const privateKey = credentials.privateKey
			? await decryptKey({
					privateKey: await readPrivateKey({
						armoredKey: (credentials.privateKey as string).replace(/\\n/g, '\n'),
					}),
					passphrase: credentials.passphrase as string,
			  })
			: undefined;
		const publicKey = credentials.publicKey
			? await readKey({ armoredKey: (credentials.publicKey as string).replace(/\\n/g, '\n') })
			: undefined;

		if (operation === 'encrypt' && !publicKey)
			throw new NodeOperationError(this.getNode(), 'Missing public key for encryption');
		if (operation === 'decrypt' && !privateKey)
			throw new NodeOperationError(this.getNode(), 'Missing private key for decryption');

		let responseData;

		for (let i = 0; i < items.length; i++) {
			const dataType = this.getNodeParameter('type', i) as string;
			try {
				if (operation === 'encrypt') {
					if (dataType === 'string') {
						const data = this.getNodeParameter('text', i) as string;
						const encrypted = await encrypt({
							message: await createMessage({ text: data }),
							encryptionKeys: publicKey,
							signingKeys: privateKey,
						});
						responseData = [{ encrypted }];
					}

					if (dataType === 'file') {
						const binaryPropertyName = this.getNodeParameter('binaryPropertyName', i);
						const outputBinaryPropertyName = this.getNodeParameter(
							'outputBinaryPropertyName',
							i,
							'encrypted',
						) as string;
						const binaryData = this.helpers.assertBinaryData(i, binaryPropertyName);

						let pgpData: Buffer | Readable;
						if (binaryData.id) {
							pgpData = await this.helpers.getBinaryStream(binaryData.id);
						} else {
							pgpData = Buffer.from(binaryData.data, BINARY_ENCODING);
						}

						const encrypted = await encrypt({
							message: await createMessage({ binary: pgpData }),
							encryptionKeys: publicKey,
							signingKeys: privateKey,
							format: 'binary',
						});

						let buffer;
						if (binaryData.id) {
							buffer = await this.helpers.binaryToBuffer(encrypted as Readable);
						} else {
							buffer = Buffer.from(encrypted as Uint8Array);
						}

						items[i].binary![outputBinaryPropertyName] = await this.helpers.prepareBinaryData(
							buffer,
						);
						items[i].binary![outputBinaryPropertyName].fileName = `${binaryData.fileName}.pgp`;
						items[i].binary![outputBinaryPropertyName].fileExtension = 'pgp';
						items[i].binary![outputBinaryPropertyName].mimeType = 'application/pgp-encrypted';

						responseData = this.helpers.constructExecutionMetaData(
							this.helpers.returnJsonArray(items[i]),
							{ itemData: { item: i } },
						);
					}
				}

				// TODO Add support for verifying detached signature
				if (operation === 'decrypt') {
					if (dataType === 'string') {
						const message = await readMessage({
							armoredMessage: this.getNodeParameter('text', i) as string,
						});

						const { data: decrypted } = await decrypt({
							message,
							decryptionKeys: privateKey,
							verificationKeys: publicKey,
							expectSigned: !!publicKey,
						});
						responseData = [{ decrypted }];
					}
					if (dataType === 'file') {
						const binaryPropertyName = this.getNodeParameter('binaryPropertyName', i);
						const outputBinaryPropertyName = this.getNodeParameter(
							'outputBinaryPropertyName',
							i,
							'decrypted',
						) as string;
						const binaryData = this.helpers.assertBinaryData(i, binaryPropertyName);

						let pgpData: Buffer | Readable;
						if (binaryData.id) {
							pgpData = await this.helpers.getBinaryStream(binaryData.id);
						} else {
							pgpData = Buffer.from(binaryData.data, BINARY_ENCODING);
						}

						const encryptedMessage = await readMessage({
							binaryMessage: pgpData,
						});
						const { data: decrypted } = await decrypt({
							message: encryptedMessage,
							decryptionKeys: privateKey,
							format: 'binary',
							verificationKeys: publicKey,
							expectSigned: !!publicKey,
						});

						let buffer;
						if (binaryData.id) {
							buffer = await this.helpers.binaryToBuffer(decrypted as Readable);
						} else {
							buffer = Buffer.from(decrypted as Uint8Array);
						}

						items[i].binary![outputBinaryPropertyName] = await this.helpers.prepareBinaryData(
							buffer,
						);
						let tempFileName = binaryData.fileName || '';
						if (tempFileName.endsWith('.pgp')) {
							tempFileName = tempFileName?.slice(0, -4);
						}
						items[i].binary![outputBinaryPropertyName].fileName = `${tempFileName}`;

						responseData = this.helpers.constructExecutionMetaData(
							this.helpers.returnJsonArray(items[i]),
							{ itemData: { item: i } },
						);
					}
				}
				const executionData = this.helpers.constructExecutionMetaData(
					this.helpers.returnJsonArray(responseData as IDataObject[]),
					{ itemData: { item: i } },
				);
				returnData.push(...executionData);
			} catch (error) {
				if (this.continueOnFail()) {
					const executionErrorData = this.helpers.constructExecutionMetaData(
						this.helpers.returnJsonArray({ error: error.message }),
						{ itemData: { item: i } },
					);
					returnData.push(...executionErrorData);
					continue;
				}
				throw error;
			}
		}

		return this.prepareOutputData(returnData);
	}
}
