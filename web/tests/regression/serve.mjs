// Static test server with no API proxy or lab connectivity.
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { resolve, extname, sep } from 'node:path'

const root = resolve('dist')
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.woff2': 'font/woff2' }
createServer(async (req, res) => {
  const pathname = new URL(req.url, 'http://127.0.0.1:4179').pathname
  if (pathname.startsWith('/api/')) {
    res.writeHead(501).end('API requests must be intercepted by the test')
    return
  }
  const file = resolve(root, `.${pathname}`)
  if (!file.startsWith(root + sep) && file !== root) {
    res.writeHead(403).end()
    return
  }
  try {
    const target = extname(file) ? file : resolve(root, 'index.html')
    const body = await readFile(target)
    res.writeHead(200, { 'Content-Type': mime[extname(target)] || 'application/octet-stream' }).end(body)
  } catch {
    res.writeHead(404).end()
  }
}).listen(4179, '127.0.0.1')
