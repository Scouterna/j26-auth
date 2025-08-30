import { mkdir, writeFile } from 'node:fs/promises';
import { getHtmlDocument } from '@scalar/core/libs/html-rendering';

const doc = getHtmlDocument({
	url: './openapi.json',
	hideClientButton: true,
});

await mkdir('docs-out', { recursive: true });
await writeFile('docs-out/index.html', doc);
