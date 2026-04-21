import type { APIContext } from 'astro';
import { getCollection } from 'astro:content';

const SITE = 'https://netrecon.pages.dev';

const staticRoutes: Array<{ path: string; changefreq: string; priority: string }> = [
  { path: '/',         changefreq: 'weekly',  priority: '1.0' },
  { path: '/about/',   changefreq: 'monthly', priority: '0.7' },
  { path: '/compare/', changefreq: 'monthly', priority: '0.8' },
  { path: '/decode/',  changefreq: 'monthly', priority: '0.8' },
  { path: '/subnet/',  changefreq: 'monthly', priority: '0.8' },
  { path: '/mcp/',     changefreq: 'monthly', priority: '0.7' },
  { path: '/blog/',    changefreq: 'weekly',  priority: '0.8' },
];

function xmlEscape(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export async function GET(_ctx: APIContext) {
  const posts = await getCollection('blog');
  const entries: string[] = [];

  for (const r of staticRoutes) {
    entries.push(
      `<url><loc>${SITE}${r.path}</loc><changefreq>${r.changefreq}</changefreq><priority>${r.priority}</priority></url>`,
    );
  }
  for (const post of posts) {
    const lastmod = post.data.pubDate instanceof Date
      ? post.data.pubDate.toISOString().slice(0, 10)
      : undefined;
    const lastmodTag = lastmod ? `<lastmod>${lastmod}</lastmod>` : '';
    entries.push(
      `<url><loc>${SITE}/blog/${xmlEscape(post.slug)}/</loc>${lastmodTag}<changefreq>yearly</changefreq><priority>0.6</priority></url>`,
    );
  }

  const body = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${entries.join('\n')}\n</urlset>\n`;
  return new Response(body, {
    headers: { 'Content-Type': 'application/xml; charset=utf-8' },
  });
}
