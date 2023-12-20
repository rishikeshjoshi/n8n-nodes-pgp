import type { ICredentialType, INodeProperties } from 'n8n-workflow';

// eslint-disable-next-line n8n-nodes-base/cred-class-name-unsuffixed
export class PgpKey implements ICredentialType {
	// eslint-disable-next-line n8n-nodes-base/cred-class-field-name-unsuffixed
	name = 'pgpKey';

	// eslint-disable-next-line n8n-nodes-base/cred-class-field-display-name-missing-api
	displayName = 'PGP Key';

	properties: INodeProperties[] = [
		{
			displayName: 'Operation',
			name: 'operation',
			type: 'options',
			options: [
				{
					name: 'Encrypt (+ Sign)',
					value: 'encrypt',
				},
				{
					name: 'Decrypt (+ Verify)',
					value: 'decrypt',
				},
				// TODO Add support for creating/verifying signature alone
			],
			default: 'encrypt',
		},
		{
			displayName: "Recipient's Public key (for encryption)",
			name: 'publicKey',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			placeholder:
				'-----BEGIN PGP PUBLIC KEY BLOCK-----\\n\\nxsFNBGWANLMBEAC4Kgo7ipR8zx4XlQxHhBnbEEdi03hS9BgSI...../ysHLJ=yV1G\\n-----END PGP PUBLIC KEY BLOCK-----',
			displayOptions: {
				show: { operation: ['encrypt'] },
			},
		},
		{
			displayName: 'Signing Key',
			name: 'privateKey',
			description: 'If empty, the message will not be signed.',
			placeholder:
				'-----BEGIN PGP PRIVATE KEY BLOCK-----\\n\\nxcaGBGWANLMBEAC4Kgo7ipR8zx4XlQxHhBnbEEdi03hS9BgSI.....wemSm3\\n-----END PGP PRIVATE KEY BLOCK-----',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			displayOptions: {
				show: { operation: ['encrypt'] },
			},
		},
		{
			displayName: "Sender's Public key (for signature verification)",
			name: 'publicKey',
			description:
				'When provided, decryption operation will fail when signature does not match. If empty, signature verification will be skipped.',
			placeholder:
				'-----BEGIN PGP PUBLIC KEY BLOCK-----\\n\\nxsFNBGWANLMBEAC4Kgo7ipR8zx4XlQxHhBnbEEdi03hS9BgSI...../ysHLJ=yV1G\\n-----END PGP PUBLIC KEY BLOCK-----',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			displayOptions: {
				show: { operation: ['decrypt'] },
			},
		},
		{
			displayName: 'Decryption key',
			name: 'privateKey',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			placeholder:
				'-----BEGIN PGP PRIVATE KEY BLOCK-----\\n\\nxcaGBGWANLMBEAC4Kgo7ipR8zx4XlQxHhBnbEEdi03hS9BgSI.....wemSm3\\n-----END PGP PRIVATE KEY BLOCK-----',
			displayOptions: {
				show: { operation: ['decrypt'] },
			},
		},
		{
			displayName: 'Passphrase',
			name: 'passphrase',
			type: 'string',
			typeOptions: { password: true },
			default: '',
		},
	];
}
