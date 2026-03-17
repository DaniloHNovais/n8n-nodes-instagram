import type {
	ICredentialDataDecryptedObject,
	IDataObject,
	IExecuteFunctions,
	IHookFunctions,
	IHttpRequestMethods,
	ILoadOptionsFunctions,
	IRequestOptions,
	IWebhookFunctions,
	JsonObject,
} from 'n8n-workflow';
import { NodeApiError } from 'n8n-workflow';
import * as crypto from 'crypto';

const INSTAGRAM_TOKEN_STORE_KEY = 'instagramOAuth2TokenStore';
const LONG_LIVED_TOKEN_LIFETIME = 60 * 24 * 60 * 60;
const LONG_LIVED_REFRESH_WINDOW = 7 * 24 * 60 * 60;
const MIN_LONG_LIVED_REFRESH_AGE = 24 * 60 * 60;

type InstagramContext =
	| IExecuteFunctions
	| IWebhookFunctions
	| IHookFunctions
	| ILoadOptionsFunctions;

type OAuthTokenData = {
	access_token?: string;
	accessToken?: string;
};

type StoredTokenState = {
	longLivedToken: string;
	tokenExpiresAt: number;
	tokenUpdatedAt: number;
};

function getCredentialStorageKey(this: InstagramContext): string {
	const credentialDetails = this.getNode().credentials?.instagramOAuth2Api;

	if (credentialDetails?.id) {
		return `id:${credentialDetails.id}`;
	}

	if (credentialDetails?.name) {
		return `name:${credentialDetails.name}`;
	}

	return 'default';
}

function getTokenStore(this: InstagramContext): Record<string, StoredTokenState> {
	const workflowState = this.getWorkflowStaticData('global') as IDataObject;
	const existingStore = workflowState[INSTAGRAM_TOKEN_STORE_KEY];

	if (existingStore && typeof existingStore === 'object' && !Array.isArray(existingStore)) {
		return existingStore as Record<string, StoredTokenState>;
	}

	const tokenStore: Record<string, StoredTokenState> = {};
	workflowState[INSTAGRAM_TOKEN_STORE_KEY] = tokenStore;

	return tokenStore;
}

function getStoredTokenState(this: InstagramContext): StoredTokenState | undefined {
	const tokenStore = getTokenStore.call(this);

	return tokenStore[getCredentialStorageKey.call(this)];
}

function setStoredTokenState(this: InstagramContext, tokenState: StoredTokenState): void {
	const tokenStore = getTokenStore.call(this);
	tokenStore[getCredentialStorageKey.call(this)] = tokenState;
}

function clearStoredTokenState(this: InstagramContext): void {
	const tokenStore = getTokenStore.call(this);
	delete tokenStore[getCredentialStorageKey.call(this)];
}

function extractShortLivedToken(credentials: ICredentialDataDecryptedObject): string | undefined {
	const oauthTokenData = credentials.oauthTokenData as OAuthTokenData | undefined;

	return oauthTokenData?.access_token ?? oauthTokenData?.accessToken;
}

function getCredentialTokenState(
	credentials: ICredentialDataDecryptedObject,
): StoredTokenState | undefined {
	const longLivedToken = credentials.longLivedToken as string;
	const tokenExpiresAt = (credentials.tokenExpiresAt as number) || 0;

	if (!longLivedToken || tokenExpiresAt <= 0) {
		return undefined;
	}

	return {
		longLivedToken,
		tokenExpiresAt,
		tokenUpdatedAt: Math.max(0, tokenExpiresAt - LONG_LIVED_TOKEN_LIFETIME),
	};
}

async function exchangeForLongLivedToken(
	this: InstagramContext,
	shortLivedToken: string,
	clientSecret: string,
): Promise<StoredTokenState> {
	const now = Math.floor(Date.now() / 1000);
	const exchanged = (await this.helpers.httpRequest({
		method: 'GET',
		url: 'https://graph.instagram.com/access_token',
		qs: {
			grant_type: 'ig_exchange_token',
			client_secret: clientSecret,
			access_token: shortLivedToken,
		},
	})) as { access_token: string; expires_in: number };

	return {
		longLivedToken: exchanged.access_token,
		tokenExpiresAt: now + exchanged.expires_in,
		tokenUpdatedAt: now,
	};
}

async function refreshLongLivedToken(
	this: InstagramContext,
	longLivedToken: string,
): Promise<StoredTokenState> {
	const now = Math.floor(Date.now() / 1000);
	const refreshed = (await this.helpers.httpRequest({
		method: 'GET',
		url: 'https://graph.instagram.com/refresh_access_token',
		qs: {
			grant_type: 'ig_refresh_token',
			access_token: longLivedToken,
		},
	})) as { access_token: string; expires_in: number };

	return {
		longLivedToken: refreshed.access_token,
		tokenExpiresAt: now + refreshed.expires_in,
		tokenUpdatedAt: now,
	};
}

/**
 * Get access token from credentials.
 *
 * Instagram's long-lived token flow is not part of n8n's built-in OAuth2 refresh handling,
 * so we manage the exchange and refresh here and persist the result in workflow static data.
 */
export async function getAccessToken(this: InstagramContext): Promise<string> {
	const credentials = (await this.getCredentials('instagramOAuth2Api')) as ICredentialDataDecryptedObject;
	const now = Math.floor(Date.now() / 1000);
	const clientSecret = credentials.clientSecret as string;

	const storedTokenState = getStoredTokenState.call(this);
	const credentialTokenState = getCredentialTokenState(credentials);
	let tokenState = storedTokenState;

	if (
		credentialTokenState &&
		(!tokenState || credentialTokenState.tokenExpiresAt > tokenState.tokenExpiresAt)
	) {
		tokenState = credentialTokenState;
		setStoredTokenState.call(this, credentialTokenState);
	}

	let hadExpiredLongLivedToken = false;

	if (tokenState?.longLivedToken) {
		if (tokenState.tokenExpiresAt > now) {
			if (tokenState.tokenExpiresAt <= now + LONG_LIVED_REFRESH_WINDOW) {
				const tokenAge = now - tokenState.tokenUpdatedAt;

				if (tokenAge >= MIN_LONG_LIVED_REFRESH_AGE) {
					try {
						const refreshedTokenState = await refreshLongLivedToken.call(
							this,
							tokenState.longLivedToken,
						);

						setStoredTokenState.call(this, refreshedTokenState);
						return refreshedTokenState.longLivedToken;
					} catch (error) {
						console.warn(
							'Instagram: Failed to refresh long-lived token, continuing with current token',
							error,
						);
					}
				}
			}

			return tokenState.longLivedToken;
		}

		hadExpiredLongLivedToken = true;
		clearStoredTokenState.call(this);
	}

	const shortLivedToken = extractShortLivedToken(credentials);

	if (!shortLivedToken) {
		throw new Error('No access token found. Please reconnect your Instagram account.');
	}

	try {
		const exchangedTokenState = await exchangeForLongLivedToken.call(
			this,
			shortLivedToken,
			clientSecret,
		);

		setStoredTokenState.call(this, exchangedTokenState);
		return exchangedTokenState.longLivedToken;
	} catch (error) {
		if (hadExpiredLongLivedToken) {
			throw new Error(
				'Instagram access token has expired. Please reconnect your account by clicking "Connect" in the credential settings.',
			);
		}

		console.warn(
			'Instagram: Failed to exchange OAuth token for a long-lived token, falling back to the short-lived token for this request',
			error,
		);
		return shortLivedToken;
	}
}

/**
 * Get Instagram Business Account ID from the authenticated user
 */
export async function getInstagramBusinessAccountId(this: InstagramContext): Promise<string> {
	try {
		const accessToken = await getAccessToken.call(this);

		const options: IRequestOptions = {
			method: 'GET',
			url: 'https://graph.instagram.com/v23.0/me',
			qs: {
				access_token: accessToken,
				fields: 'id,name,account_type,media_count,user_id,username',
			},
			json: true,
		};

		const response = await this.helpers.request(options);

		if (response && response.id) {
			return response.id;
		}

		throw new Error(
			'No Instagram Business Account found. Make sure your Facebook Page is connected to an Instagram Business Account.',
		);
	} catch (error) {
		throw new NodeApiError(this.getNode(), error as JsonObject, {
			message: 'Failed to fetch Instagram Business Account ID, Error: ' + (error as Error).message,
		});
	}
}

/**
 * Make an authenticated API request to Instagram Graph API
 */
export async function instagramApiRequest(
	this: InstagramContext,
	method: IHttpRequestMethods,
	endpoint: string,
	body: IDataObject = {},
	qs: IDataObject = {},
): Promise<any> {
	const accessToken = await getAccessToken.call(this);

	const options: IRequestOptions = {
		method,
		body,
		qs: {
			...qs,
			access_token: accessToken,
		},
		url: `https://graph.instagram.com/v23.0${endpoint}`,
		json: true,
	};

	if (Object.keys(body).length === 0) {
		delete options.body;
	}

	try {
		return await this.helpers.request(options);
	} catch (error) {
		throw new NodeApiError(this.getNode(), error as JsonObject);
	}
}

/**
 * Make an authenticated API request with pagination support
 */
export async function instagramApiRequestAllItems(
	this: IExecuteFunctions | ILoadOptionsFunctions,
	method: IHttpRequestMethods,
	endpoint: string,
	body: IDataObject = {},
	qs: IDataObject = {},
): Promise<any[]> {
	const returnData: any[] = [];
	let responseData;

	qs.limit = 100;

	do {
		responseData = await instagramApiRequest.call(this, method, endpoint, body, qs);
		if (responseData.data) {
			returnData.push(...responseData.data);
		}
		if (responseData.paging?.next) {
			const url = new URL(responseData.paging.next);
			qs.after = url.searchParams.get('after');
		} else {
			break;
		}
	} while (responseData.paging?.next);

	return returnData;
}

/**
 * Validate Instagram Webhook Signature
 */
export function validateSignature(payload: string, signature: string, appSecret: string): boolean {
	const hmac = crypto.createHmac('sha256', appSecret);
	const expectedSignature = 'sha256=' + hmac.update(payload).digest('hex');

	try {
		return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature));
	} catch (error) {
		return false;
	}
}
