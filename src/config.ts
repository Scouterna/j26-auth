import { type } from 'arktype';

const Config = type({
	'+': 'delete',
	'PORT?': type('string.integer>0').pipe((value) => Number.parseInt(value, 10)),
	PUBLIC_URL: type.string.pipe((url) => url.replace(/\/+$/, '')), // Remove trailing slashes
	'HTTPS_KEY?': type.string,
	'HTTPS_CERT?': type.string,
	OIDC_SERVER: type.string,
	OIDC_CLIENT_ID: type.string,
	OIDC_CLIENT_SECRET: type.string,
});
type Config = typeof Config.infer;

let rawConfig: Config;

export function loadConfig() {
	const parsedConfig = Config(process.env);

	if (parsedConfig instanceof type.errors) {
		throw new Error(
			`Configuration validation failed:\n${parsedConfig.summary}`,
		);
	}

	rawConfig = parsedConfig;
}

const config = new Proxy({} as Config, {
	get(_, prop: keyof Config) {
		if (rawConfig) return rawConfig[prop];

		if (
			!process.env.SUPPRESS_CONFIG_WARNINGS ||
			process.env.SUPPRESS_CONFIG_WARNINGS === 'false'
		) {
			console.warn(`Accessing property ${prop} before config is loaded`);
		}
		return undefined;
	},
});

export default config as Config;
export type { Config };
