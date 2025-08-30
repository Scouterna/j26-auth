import fs, { mkdir } from 'node:fs/promises';
import { generateSpecs } from 'hono-openapi';
import app from '../src/app.ts';

const spec = await generateSpecs(app);

await mkdir('docs-out', { recursive: true });
await fs.writeFile('docs-out/openapi.json', JSON.stringify(spec, null, 2));
